# tests/test_beacon_detect.py
import sys; sys.path.insert(0, "scripts")
import pytest
import beacon_detect
from beacon_detect import detect_beacons

def test_detects_periodic_beacon(test_pcap):
    beacons = detect_beacons(str(test_pcap))
    assert len(beacons) >= 1
    b = beacons[0]
    assert b["dst"] == "185.220.101.42:443"
    assert b["count"] >= 5
    assert 25 < b["avg_interval"] < 35
    assert b["verdict"] == "LIKELY_BEACON"

def test_no_beacon_sparse_traffic(tmp_path):
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)
    assert detect_beacons(str(p)) == []

def test_detect_beacons_raises_on_corrupt_pcap(tmp_path):
    """工具失败必须显式报错，不得静默返回空列表（与 pcap_profile 约定一致）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        detect_beacons(str(p))

def test_detect_beacons_raises_on_missing_tshark(monkeypatch):
    """tshark 不在 PATH 时抛带提示的 RuntimeError，而不是裸 FileNotFoundError。"""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("tshark")
    monkeypatch.setattr(beacon_detect.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="tshark"):
        detect_beacons("x.pcap")
