# tests/test_extract_files.py
import hashlib, sys; sys.path.insert(0, "scripts")
import pytest
import extract_files
from extract_files import extract_objects

def test_extracts_http_objects(test_pcap, tmp_path):
    out = tmp_path / "extracted"
    result = extract_objects(str(test_pcap), str(out))
    assert len(result) >= 1
    assert result[0]["protocol"] == "http"
    assert "sha256" in result[0]
    assert len(result[0]["sha256"]) == 64

def test_http_object_contains_flag_payload(test_pcap, tmp_path):
    """真实提取验证：导出的 HTTP 对象必须是夹具中 20 字节的 FLAG 载荷。"""
    result = extract_objects(str(test_pcap), str(tmp_path / "out"))
    flag_hash = hashlib.sha256(b"FLAG{h1dd3n_in_http}").hexdigest()
    assert any(r["sha256"] == flag_hash and r["size"] == 20 for r in result)

def test_empty_pcap_returns_empty(tmp_path):
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)
    result = extract_objects(str(p), str(tmp_path / "out"))
    assert result == []

def test_stale_files_from_previous_run_not_reported(test_pcap, tmp_path):
    """同一输出目录二次运行：前一个 pcap 的残留对象不得被误报为本次结果
    （否则 sha256 归因静默出错）。"""
    out = str(tmp_path / "out")
    first = extract_objects(str(test_pcap), out)
    assert len(first) >= 1  # 预置残留
    from scapy.all import wrpcap, IP, TCP
    empty = tmp_path / "empty.pcap"
    wrpcap(str(empty), [IP()/TCP()] * 3)
    result = extract_objects(str(empty), out)
    assert result == []

def test_extract_objects_raises_on_corrupt_pcap(tmp_path):
    """工具失败必须显式报错，不得静默返回空列表（tshark 对损坏文件 exit != 0）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        extract_objects(str(p), str(tmp_path / "out"))

def test_extract_objects_raises_on_missing_tshark(monkeypatch, tmp_path):
    """tshark 不在 PATH 时抛带提示的 RuntimeError，而不是裸 FileNotFoundError。"""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("tshark")
    monkeypatch.setattr(extract_files.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="tshark"):
        extract_objects("x.pcap", str(tmp_path / "out"))

def test_cli_forces_utf8_stdout(test_pcap, tmp_path):
    """全局约束：所有脚本强制 UTF-8 输出。即使管道编码为 GBK，
    含非 ASCII 路径的 JSON 也必须以 UTF-8 字节写出，不得 UnicodeEncodeError。"""
    import subprocess, os
    out = tmp_path / "out_🚩"  # GBK 无法编码的字符
    env = dict(os.environ, PYTHONIOENCODING="gbk")
    r = subprocess.run(
        [sys.executable, "scripts/extract_files.py", str(test_pcap), str(out)],
        capture_output=True, env=env)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    import json
    parsed = json.loads(r.stdout.decode("utf-8"))
    assert any(item["size"] == 20 for item in parsed)
