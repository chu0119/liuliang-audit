# tests/test_beacon_detect.py
import sys; sys.path.insert(0, "scripts")
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
