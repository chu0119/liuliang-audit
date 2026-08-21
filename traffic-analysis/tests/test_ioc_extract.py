# tests/test_ioc_extract.py
import sys; sys.path.insert(0, "scripts")
import pytest
import ioc_extract
from ioc_extract import extract_iocs, to_misp_csv

def test_extracts_ips_and_domains(test_pcap):
    iocs = extract_iocs(str(test_pcap))
    assert "185.220.101.42" in iocs["ips"]
    assert any("example.com" in d for d in iocs["domains"])

def test_extracts_http_url(test_pcap):
    """真实提取验证：夹具中的 GET evil.com/secret.txt 必须还原为完整 URL。"""
    iocs = extract_iocs(str(test_pcap))
    assert "http://evil.com/secret.txt" in iocs["urls"]

def test_result_contract_keys(test_pcap):
    """接口契约：返回 dict 必须含全部六类 IOC 键，值均为列表。"""
    iocs = extract_iocs(str(test_pcap))
    assert set(iocs.keys()) == {"ips", "domains", "urls", "hashes", "ja3", "user_agents"}
    assert all(isinstance(v, list) for v in iocs.values())

def test_no_duplicate_iocs(test_pcap):
    """同一 IOC 不得重复出现（信标流对同一 IP 发 10 个 SYN 只算一个 IOC）。"""
    iocs = extract_iocs(str(test_pcap))
    for key in ("ips", "domains", "urls"):
        assert len(iocs[key]) == len(set(iocs[key]))

def test_empty_pcap_yields_empty_lists(tmp_path):
    """无 DNS/HTTP/TLS 的稀疏 pcap：派生类 IOC 必须为空列表；
    3 个同目标包去重后只算 1 个 IP IOC。"""
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)  # scapy 默认 dst=127.0.0.1
    iocs = extract_iocs(str(p))
    assert iocs["domains"] == [] and iocs["urls"] == []
    assert iocs["ja3"] == [] and iocs["user_agents"] == []
    assert iocs["ips"] == ["127.0.0.1"]

def test_misp_csv_writes(test_pcap, tmp_path):
    iocs = extract_iocs(str(test_pcap))
    csv_path = tmp_path / "iocs.csv"
    to_misp_csv(iocs, str(csv_path))
    assert csv_path.exists()
    content = csv_path.read_text(encoding="utf-8")
    assert "185.220.101.42" in content

def test_misp_csv_header_and_rows(test_pcap, tmp_path):
    """MISP CSV 结构：表头 type,value,category + 每行带类别标注。"""
    csv_path = tmp_path / "iocs.csv"
    to_misp_csv(extract_iocs(str(test_pcap)), str(csv_path))
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "type,value,category"
    assert any(l.startswith("domain,a1b2c3d4e5f6g7h8i9j0.example.com") for l in lines[1:])
    assert any(l.startswith("url,http://evil.com/secret.txt") for l in lines[1:])
    assert any(",Network activity" in l for l in lines[1:])

def test_extract_iocs_raises_on_corrupt_pcap(tmp_path):
    """工具失败必须显式报错，不得静默返回空结果（与 beacon_detect 约定一致）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        extract_iocs(str(p))

def test_extract_iocs_raises_on_missing_tshark(monkeypatch):
    """tshark 不在 PATH 时抛带提示的 RuntimeError，而不是裸 FileNotFoundError。"""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("tshark")
    monkeypatch.setattr(ioc_extract.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="tshark"):
        extract_iocs("x.pcap")

def test_ja3_failure_does_not_break_extraction(monkeypatch, test_pcap):
    """JA3 为可选增强字段（部分 tshark 构建缺失）：其失败不得拖垮整体提取。"""
    orig = ioc_extract._tshark_fields
    def flaky_fields(pcap, fields, display_filter="", check=True):
        if "tls.handshake.ja3" in fields:
            raise RuntimeError("Field 'tls.handshake.ja3' doesn't exist")
        return orig(pcap, fields, display_filter, check)
    monkeypatch.setattr(ioc_extract, "_tshark_fields", flaky_fields)
    iocs = extract_iocs(str(test_pcap))
    assert iocs["ja3"] == []
    assert "185.220.101.42" in iocs["ips"]
    assert any("example.com" in d for d in iocs["domains"])

def test_cli_forces_utf8_stdout(tmp_path):
    """全局约束：所有脚本强制 UTF-8 输出。即使管道编码为 GBK，
    含非 ASCII 的 JSON 也必须以 UTF-8 字节写出，不得 UnicodeEncodeError。
    （tshark 将 HTTP 头中的非 ASCII 字节净化为 U+FFFD——GBK 无法编码该字符，
    若未强制 UTF-8 stdout 则必然崩溃。）"""
    import os, json, subprocess
    from scapy.all import wrpcap, IP, TCP, Raw
    payload = (b"GET /x HTTP/1.1\r\nHost: evil.com\r\n"
               b"User-Agent: Bot/\xe4\xbd\xa0\xe5\xa5\xbd\r\n\r\n")
    p = tmp_path / "ua.pcap"
    wrpcap(str(p), [IP(src="10.0.0.1", dst="10.0.0.2") /
                    TCP(sport=1234, dport=80) / Raw(load=payload)])
    env = dict(os.environ, PYTHONIOENCODING="gbk")
    r = subprocess.run([sys.executable, "scripts/ioc_extract.py", str(p)],
                       capture_output=True, env=env)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    parsed = json.loads(r.stdout.decode("utf-8"))
    assert any("�" in ua for ua in parsed["user_agents"])
