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

def test_extract_objects_raises_on_corrupt_pcap(tmp_path):
    """工具失败必须显式报错，不得静默返回空列表（tshark 对损坏文件 exit != 0）。"""
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(b"this is not a pcap file at all")
    with pytest.raises(RuntimeError):
        extract_objects(str(p), str(tmp_path / "out"))

def test_extract_objects_raises_on_missing_tshark(monkeypatch):
    """tshark 不在 PATH 时抛带提示的 RuntimeError，而不是裸 FileNotFoundError。"""
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("tshark")
    monkeypatch.setattr(extract_files.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="tshark"):
        extract_objects("x.pcap", "out")
