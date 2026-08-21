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
