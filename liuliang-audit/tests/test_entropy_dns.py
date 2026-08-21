# tests/test_entropy_dns.py
import sys; sys.path.insert(0, "scripts")
import pytest
import entropy_dns
from entropy_dns import analyze_dns_entropy

def test_detects_dga_domain(test_pcap):
    results = analyze_dns_entropy(str(test_pcap))
    domains = [r["domain"] for r in results]
    assert any("a1b2c3d4e5f6" in d for d in domains)
    assert results[0]["verdict"] == "HIGH_ENTROPY"

def test_no_dns_returns_empty(tmp_path):
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "nodns.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)
    assert analyze_dns_entropy(str(p)) == []

def test_analyze_dns_entropy_raises_on_corrupt_pcap(tmp_path):
    """工具失败必须显式报错，不得静默返回空列表（与 pcap_profile/beacon_detect 约定一致）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        analyze_dns_entropy(str(p))

def test_analyze_dns_entropy_raises_on_missing_tshark(monkeypatch):
    """tshark 不在 PATH 时抛带提示的 RuntimeError，而不是裸 FileNotFoundError。"""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("tshark")
    monkeypatch.setattr(entropy_dns.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="tshark"):
        analyze_dns_entropy("x.pcap")

def test_entropy_empty_subdomain_returns_zero():
    """退化域名（子域名为空串）熵计算返回 0，不除零。"""
    assert entropy_dns._entropy("") == 0.0

def test_cli_forces_utf8_stdout(tmp_path):
    """全局约束：所有脚本强制 UTF-8 输出。DNS qname 含 emoji（GBK 无法编码，
    且高熵通过 DGA 过滤必然进入 JSON 输出）——未强制 UTF-8 stdout 时
    GBK 管道下必然 UnicodeEncodeError 崩溃。"""
    import os, json, subprocess
    from scapy.all import wrpcap, IP, UDP, Raw
    emoji = "🚩🚀🎯🔥💣🌐🔑⚡🎲🔒📡💊🧨🪓"
    eb = emoji.encode("utf-8")
    qname = bytes([len(eb)]) + eb + b"\x00"  # 单标签（长度按实际字节数）
    dns = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # 查询头
           + qname + b"\x00\x01\x00\x01")                       # QTYPE=A, QCLASS=IN
    p = tmp_path / "emoji_dns.pcap"
    wrpcap(str(p), [IP(src="10.0.0.5", dst="8.8.8.8") /
                    UDP(sport=5353, dport=53) / Raw(load=dns)])
    env = dict(os.environ, PYTHONIOENCODING="gbk")
    r = subprocess.run([sys.executable, "scripts/entropy_dns.py", str(p)],
                       capture_output=True, env=env)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    parsed = json.loads(r.stdout.decode("utf-8"))
    assert any(d["domain"] == emoji for d in parsed)
