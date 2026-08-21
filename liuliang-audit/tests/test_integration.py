import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from pcap_profile import profile
from beacon_detect import detect_beacons
from entropy_dns import analyze_dns_entropy
from extract_files import extract_objects
from ioc_extract import extract_iocs
from timeline_builder import build_timeline
from html_report import generate_html_report

def test_full_pipeline(test_pcap, tmp_path):
    """端到端：全要素测试包跑全部脚本，验证数据流贯通。"""
    p = profile(str(test_pcap))
    assert p["capture"]["packets_total"] > 0
    assert p["size_class"] in ("small", "medium", "large")

    beacons = detect_beacons(str(test_pcap))
    assert len(beacons) >= 1

    dns = analyze_dns_entropy(str(test_pcap))
    assert len(dns) >= 1

    files = extract_objects(str(test_pcap), str(tmp_path / "extracted"))
    assert len(files) >= 1

    iocs = extract_iocs(str(test_pcap))
    assert len(iocs["ips"]) > 0

    timeline = build_timeline(str(test_pcap))
    assert len(timeline) >= 3

    html_path = tmp_path / "report.html"
    generate_html_report(str(test_pcap), str(html_path), p, timeline, iocs)
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")
    assert "185.220.101.42" in content
