# tests/conftest.py
"""共享测试夹具：用 scapy 构造含多种流量特征的测试 pcap。"""
import pathlib, time
import pytest
from scapy.all import wrpcap, IP, TCP, UDP, DNS, DNSQR, Raw, ICMP

@pytest.fixture
def test_pcap(tmp_path: pathlib.Path) -> pathlib.Path:
    packets = []
    base_time = time.time()

    # 1. HTTP 文件下载（TCP 80，含 GET 请求 + 响应体）
    http_payload = b"GET /secret.txt HTTP/1.1\r\nHost: evil.com\r\n\r\n"
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nFLAG{h1dd3n_in_http}\r\n"
    for i, payload in enumerate([http_payload, http_resp]):
        pkt = IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=52000+i, dport=80) / Raw(load=payload)
        pkt.time = base_time + i * 0.1
        packets.append(pkt)

    # 2. 高熵 DNS 查询（DGA 模拟）
    dga_domain = "a1b2c3d4e5f6g7h8i9j0.example.com"
    dns_pkt = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(
        qr=0, qd=DNSQR(qname=dga_domain)
    )
    dns_pkt.time = base_time + 1
    packets.append(dns_pkt)

    # 3. C2 信标流（每 30s 一次 SYN，共 10 次）
    for i in range(10):
        beacon = IP(src="10.0.0.5", dst="185.220.101.42") / TCP(sport=50000+i, dport=443, flags="S")
        beacon.time = base_time + 60 + i * 30
        packets.append(beacon)

    # 4. ICMP 隧道（payload 含 "TUNNEL_DATA"）
    for i in range(3):
        tunnel = IP(src="10.0.0.5", dst="185.220.101.42") / ICMP() / Raw(load=b"TUNNEL_DATA_" + bytes([i]))
        tunnel.time = base_time + 100 + i * 0.5
        packets.append(tunnel)

    # 5. 明文 FTP 凭据
    ftp_cmds = [b"USER admin\r\n", b"PASS s3cr3tP@ss\r\n"]
    for i, cmd in enumerate(ftp_cmds):
        ftp = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(sport=53000+i, dport=21) / Raw(load=cmd)
        ftp.time = base_time + 200 + i * 0.1
        packets.append(ftp)

    pcap_path = tmp_path / "test_full.pcap"
    wrpcap(str(pcap_path), packets)
    return pcap_path
