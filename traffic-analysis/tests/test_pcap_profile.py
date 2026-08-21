import json, subprocess, sys
sys.path.insert(0, "scripts")
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
        capture_output=True, text=True
    )
    parsed = json.loads(result.stdout)
    assert parsed["capture"]["packets_total"] > 0
