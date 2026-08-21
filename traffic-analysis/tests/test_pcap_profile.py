import json, subprocess, sys
import pytest
sys.path.insert(0, "scripts")
import pcap_profile
from pcap_profile import profile

def test_profile_returns_contract_keys(test_pcap):
    result = profile(str(test_pcap))
    assert "file" in result
    assert "capture" in result
    assert "size_class" in result
    assert result["size_class"] in ("small", "medium", "large")
    assert "protocol_hierarchy" in result
    assert "endpoints_top" in result
    assert "suspicious_hypotheses" in result

def test_profile_detects_high_entropy_dns(test_pcap):
    result = profile(str(test_pcap))
    dns = result.get("dns_summary", {})
    assert dns["queries_total"] >= 1
    types = [h["type"] for h in result["suspicious_hypotheses"]]
    assert any("dns" in t or "dga" in t for t in types)

def test_profile_cli_prints_json(test_pcap):
    result = subprocess.run(
        [sys.executable, "scripts/pcap_profile.py", str(test_pcap)],
        capture_output=True
    )
    assert result.returncode == 0
    # stdout 必须为 UTF-8 字节（强制 UTF-8 约束）
    parsed = json.loads(result.stdout.decode("utf-8"))
    assert parsed["capture"]["packets_total"] > 0

def _write_tls_clienthello_pcap(path, sni: bytes = b"example.com"):
    """构造含 SNI 的 TLS ClientHello 最小 pcap（手工编码记录，避免 scapy TLS 层依赖）。"""
    from scapy.all import IP, TCP, Raw, wrpcap
    body = b"\x03\x03" + bytes(range(32)) + b"\x00"   # version, random, session id len
    body += b"\x00\x02\x13\x01"                       # 1 个密码套件 TLS_AES_128_GCM_SHA256
    body += b"\x01\x00"                               # 压缩方式: null
    # SNI 扩展: type(2) len(2) list_len(2) name_type(1) name_len(2) name
    data = (3 + len(sni)).to_bytes(2, "big") + b"\x00" + len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(data).to_bytes(2, "big") + data
    body += len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=44444, dport=443) / Raw(load=rec)
    wrpcap(str(path), [pkt])

def test_profile_tls_summary_parsed(tmp_path):
    """真实 tshark 路径：ClientHello 的 handshakes/SNI/JA3 均被解析。"""
    p = tmp_path / "tls.pcap"
    _write_tls_clienthello_pcap(p)
    tls = profile(str(p))["tls_summary"]
    assert tls["handshakes"] == 1
    assert "example.com" in tls["unique_sni"]
    assert len(tls["ja3_fingerprints"]) >= 1
    assert tls["ja3_fingerprints"][0]["count"] >= 1

def test_tls_summary_survives_ja3_failure(monkeypatch):
    """JA3 为可选增强字段：提取失败时 handshakes/SNI 必须保留（解析器拆分测试）。"""
    calls = []

    def fake_fields(pcap, fields, display_filter="", check=True):
        calls.append(list(fields))
        if "tls.handshake.ja3" in fields:
            raise RuntimeError("tshark: Some fields aren't valid: tls.handshake.ja3")
        return [["1", "example.com"]]

    monkeypatch.setattr(pcap_profile, "_tshark_fields", fake_fields)
    tls = pcap_profile._tls_summary("x.pcap")
    assert tls["handshakes"] == 1
    assert tls["unique_sni"] == ["example.com"]
    assert tls["ja3_fingerprints"] == []
    assert len(calls) == 2  # 核心字段与 JA3 分两次调用

def test_profile_raises_on_unreadable_pcap(tmp_path):
    """工具失败必须显式报错，不得输出全零画像（capinfos 对损坏文件 exit 2）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        profile(str(p))

def test_profile_empty_pcap_no_crash(tmp_path):
    """空 pcap（capinfos 输出 n/a）正常出 JSON 不崩溃。"""
    from scapy.all import wrpcap
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [])
    result = profile(str(p))
    assert result["capture"]["packets_total"] == 0
    assert result["size_class"] in ("small", "medium", "large")

def test_entropy_empty_returns_zero():
    """退化域名（子域名为空串）熵计算返回 0，不除零。"""
    assert pcap_profile._entropy("") == 0.0
