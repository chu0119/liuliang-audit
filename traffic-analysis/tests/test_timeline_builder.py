# tests/test_timeline_builder.py
import sys; sys.path.insert(0, "scripts")
import json
import pytest
import timeline_builder
from timeline_builder import build_timeline

def test_timeline_sorted_by_time(test_pcap):
    events = build_timeline(str(test_pcap))
    assert len(events) >= 3
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)

def test_timeline_contains_dns_and_http(test_pcap):
    events = build_timeline(str(test_pcap))
    types = [e["type"] for e in events]
    assert "dns_query" in types
    assert "http_request" in types

def test_event_contract_keys(test_pcap):
    """接口契约：每个事件必须且仅含六个键，类型正确。"""
    events = build_timeline(str(test_pcap))
    assert events, "时间线不应为空"
    for e in events:
        assert set(e.keys()) == {"timestamp", "type", "src", "dst", "detail", "severity"}
        assert isinstance(e["timestamp"], str) and e["timestamp"]
        assert e["severity"] in ("info", "medium", "high")

def test_timeline_event_details(test_pcap):
    """真实内容验证：夹具中的 DGA 域名、HTTP 请求与 FTP 凭据必须进入时间线。"""
    events = build_timeline(str(test_pcap))
    dns = [e for e in events if e["type"] == "dns_query"]
    assert any("a1b2c3d4e5f6g7h8i9j0.example.com" in e["detail"] for e in dns)
    assert dns[0]["src"] == "10.0.0.5" and dns[0]["dst"] == "8.8.8.8"
    http = [e for e in events if e["type"] == "http_request"]
    assert any("GET" in e["detail"] and "/secret.txt" in e["detail"] for e in http)
    assert http[0]["src"] == "10.0.0.1" and http[0]["dst"] == "10.0.0.5"

def test_ftp_credential_severity(test_pcap):
    """FTP PASS 为 high、其余命令为 medium。"""
    events = build_timeline(str(test_pcap))
    ftp = [e for e in events if e["type"] == "ftp_credential"]
    assert len(ftp) == 2
    by_cmd = {e["detail"].split()[1]: e for e in ftp}
    assert by_cmd["PASS"]["severity"] == "high"
    assert by_cmd["USER"]["severity"] == "medium"

def test_build_timeline_raises_on_corrupt_pcap(tmp_path):
    """工具失败必须显式报错，不得静默返回空结果（与既有脚本约定一致）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        build_timeline(str(p))

def test_build_timeline_raises_on_missing_tshark(monkeypatch):
    """tshark 不在 PATH 时抛带提示的 RuntimeError，而不是裸 FileNotFoundError。"""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("tshark")
    monkeypatch.setattr(timeline_builder.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="tshark"):
        build_timeline("x.pcap")

def test_cli_outputs_sorted_json(test_pcap):
    """CLI 冒烟：退出码 0，stdout 为合法 JSON 且按时间排序。"""
    import subprocess
    r = subprocess.run([sys.executable, "scripts/timeline_builder.py", str(test_pcap)],
                       capture_output=True)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    events = json.loads(r.stdout.decode("utf-8"))
    ts = [e["timestamp"] for e in events]
    assert ts == sorted(ts)

def test_cli_forces_utf8_stdout(tmp_path):
    """全局约束：所有脚本强制 UTF-8 输出。即使管道编码为 GBK，
    含非 ASCII 的 JSON 也必须以 UTF-8 字节写出，不得 UnicodeEncodeError。
    （FTP 参数中的非法 UTF-8 字节被 tshark 净化为 U+FFFD——GBK 无法编码
    该字符，若未强制 UTF-8 stdout 则必然崩溃。）"""
    import os, subprocess
    from scapy.all import wrpcap, IP, TCP, Raw
    pkts = [IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=1234+i, dport=21) / Raw(load=c)
            for i, c in enumerate([b"USER admin\r\n", b"PASS \xff\xfe\xfd\r\n"])]
    p = tmp_path / "ftp.pcap"
    wrpcap(str(p), pkts)
    env = dict(os.environ, PYTHONIOENCODING="gbk")
    r = subprocess.run([sys.executable, "scripts/timeline_builder.py", str(p)],
                       capture_output=True, env=env)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    parsed = json.loads(r.stdout.decode("utf-8"))
    creds = [e for e in parsed if e["type"] == "ftp_credential"]
    assert any("�" in e["detail"] for e in creds)
