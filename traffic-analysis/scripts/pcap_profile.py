"""一键 pcap 画像：封装 capinfos + tshark 统计，输出标准化 JSON。

数据契约（pcap_profile.py -> 消费者）：
{
  "file", "capture", "size_class", "protocol_hierarchy", "endpoints_top",
  "conversations_top", "ports_top", "time_distribution",
  "dns_summary", "tls_summary", "suspicious_hypotheses"
}

解析器基于真实 tshark 4.x 输出格式（-z io,phs / endpoints,ip / endpoints,tcp /
endpoints,udp / conv,tcp / conv,udp / io,stat + -T fields），已在本机
Wireshark 4.6.8 上验证。
"""
import json
import re
import subprocess
import sys
from collections import Counter
from math import log2
from pathlib import Path


def _run(cmd: list) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError(
            f"命令不存在: {cmd[0]}。请安装 Wireshark 套件 (tshark/capinfos) 并加入 PATH。"
        ) from e
    return r.stdout


def _capinfos(pcap: str) -> dict:
    out = _run(["capinfos", "-M", pcap])
    info = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
    return info


def _tshark_z(pcap: str, stat: str) -> str:
    return _run(["tshark", "-r", pcap, "-q", "-z", stat])


def _tshark_fields(pcap: str, fields: list, display_filter: str = "") -> list:
    """tshark -T fields 输出，按 | 分隔返回行列表（每行是字段值列表）。"""
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=|"] + \
          [f"-e {f}" for f in fields]
    if display_filter:
        cmd += ["-Y", display_filter]
    out = _run(cmd)
    return [line.split("|") for line in out.splitlines() if line.strip()]


def _parse_phs(out: str) -> list:
    """解析 -z io,phs。真实格式:
    frame                                    frames:18 bytes:895
      tcp                                   frames:14 bytes:694
    （按协议名去重，保留最外层；pct 相对 frame 总数）"""
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s*([A-Za-z][\w.]*)\s+frames:(\d+)\s+bytes:(\d+)", line)
        if m:
            rows.append((m.group(1), int(m.group(2))))
    if not rows:
        return []
    total = rows[0][1]
    seen = set()
    result = []
    for name, frames in rows:
        if name in seen:
            continue
        seen.add(name)
        pct = round(frames / total * 100, 2) if total else 0.0
        result.append({"protocol": name, "packets": frames, "pct": pct})
    return result


def _parse_endpoints(out: str) -> list:
    """解析 -z endpoints,ip。真实格式:
    10.0.0.5                       18   895 bytes          16 ..."""
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+bytes", line)
        if m:
            rows.append({"ip": m.group(1), "packets": int(m.group(2)),
                         "bytes": int(m.group(3))})
    return rows[:10]


def _parse_ports(out: str, proto: str) -> list:
    """解析 -z endpoints,tcp|udp。真实格式:
    185.220.101.42              443           10   400 bytes ..."""
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+bytes", line)
        if m:
            rows.append({"port": int(m.group(2)), "protocol": proto,
                         "packets": int(m.group(3))})
    return rows


def _parse_conversations(out: str) -> list:
    """解析 -z conv,tcp|udp。真实格式:
    10.0.0.5:50000  <-> 185.220.101.42:443  0 0 bytes  1 40 bytes  1 40 bytes ..."""
    rows = []
    for line in out.splitlines():
        m = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+:\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+:\d+)"
            r"\s+\d+\s+\d+\s+bytes\s+\d+\s+\d+\s+bytes\s+(\d+)\s+(\d+)\s+bytes",
            line)
        if m:
            rows.append({"src": m.group(1), "dst": m.group(2),
                         "packets": int(m.group(3)), "bytes": int(m.group(4))})
    return rows


def _parse_io_stat(out: str) -> list:
    """解析 -z io,stat,60。真实格式:
    |   0 <> 60  |      3 |   263 |
    | 300 <> Dur |      7 |   312 |"""
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\|\s*(\d+)\s*<>\s*(\d+|Dur)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", line)
        if m:
            start, end = m.group(1), m.group(2)
            label = f"{start}s+" if end == "Dur" else f"{start}-{end}s"
            rows.append({"bucket": label, "packets": int(m.group(3))})
    return rows


def _dns_summary(pcap: str) -> dict:
    """DNS 查询统计。-z dns,tree 不含域名明细，改用 -T fields 提取。"""
    rows = _tshark_fields(pcap, ["dns.qry.name"], "dns.flags.response==0")
    counts = Counter(r[0].strip() for r in rows if r and r[0].strip())
    top = [{"domain": d, "count": c} for d, c in counts.most_common(10)]
    return {"queries_total": sum(counts.values()),
            "unique_domains": len(counts), "top_domains": top}


def _tls_summary(pcap: str) -> dict:
    """TLS ClientHello 统计（handshakes / SNI / JA3）。"""
    rows = _tshark_fields(
        pcap, ["tls.handshake.type", "tls.handshake.extensions_server_name",
               "tls.handshake.ja3"], "tls.handshake.type==1")
    handshakes = 0
    snis = []
    ja3s = []
    for r in rows:
        if not r or not r[0].strip():
            continue
        handshakes += 1
        if len(r) > 1 and r[1].strip():
            snis.append(r[1].strip())
        if len(r) > 2 and r[2].strip():
            ja3s.append(r[2].strip())
    unique_sni = list(dict.fromkeys(snis))
    ja3_fps = [{"ja3": j, "count": c} for j, c in Counter(ja3s).most_common()]
    return {"handshakes": handshakes, "unique_sni": unique_sni,
            "ja3_fingerprints": ja3_fps}


def _size_class(packets: int, duration: float) -> str:
    if packets < 50_000 and duration < 600:
        return "small"
    if packets < 500_000 and duration < 3600:
        return "medium"
    return "large"


def _entropy(s: str) -> float:
    p = [n / len(s) for n in Counter(s).values()]
    return -sum(x * log2(x) for x in p if x > 0)


def _detect_hypotheses(dns_domains: list) -> list:
    """基于画像统计生成筛查假设（当前：高熵域名疑似 DGA）。"""
    hypotheses = []
    for d in dns_domains:
        sub = d["domain"].split(".")[0]
        ent = _entropy(sub)
        if ent > 3.5 and len(sub) > 10:
            hypotheses.append({
                "type": "dga_dns", "severity": "medium",
                "description": f"高熵域名疑似 DGA: {d['domain']}",
                "evidence": {"domain": d["domain"], "entropy": round(ent, 2)}})
    return hypotheses


def profile(pcap_path: str) -> dict:
    if not Path(pcap_path).is_file():
        raise FileNotFoundError(f"pcap 文件不存在: {pcap_path}")

    info = _capinfos(pcap_path)

    def _num(key: str) -> int:
        try:
            return int(info[key].split()[0].replace(",", ""))
        except (KeyError, ValueError, IndexError):
            return 0

    def _text(key: str) -> str:
        """取值并将 n/a 归一化为空串。"""
        v = info.get(key, "")
        return "" if v.lower() == "n/a" else v

    packets = _num("Number of packets")
    duration = 0.0
    if "Capture duration" in info:
        try:
            duration = float(info["Capture duration"].split()[0])
        except (ValueError, IndexError):
            duration = 0.0

    phs = _parse_phs(_tshark_z(pcap_path, "io,phs"))
    endpoints = _parse_endpoints(_tshark_z(pcap_path, "endpoints,ip"))
    ports = _parse_ports(_tshark_z(pcap_path, "endpoints,tcp"), "tcp")
    ports += _parse_ports(_tshark_z(pcap_path, "endpoints,udp"), "udp")
    ports_top = sorted(ports, key=lambda x: -x["packets"])[:10]

    convs = _parse_conversations(_tshark_z(pcap_path, "conv,tcp"))
    convs += _parse_conversations(_tshark_z(pcap_path, "conv,udp"))
    conversations_top = sorted(convs, key=lambda x: -x["packets"])[:10]

    time_distribution = _parse_io_stat(_tshark_z(pcap_path, "io,stat,60"))
    dns_summary = _dns_summary(pcap_path)
    tls_summary = _tls_summary(pcap_path)

    return {
        "file": str(Path(pcap_path).resolve()),
        "capture": {
            "packets_total": packets,
            "bytes_total": _num("File size"),
            "duration_seconds": duration,
            "start_time": _text("Earliest packet time")
                          or _text("First packet time"),
            "link_type": _text("File encapsulation")
                         or _text("Capture type"),
            "truncated": "truncated" in info.get("File comment", "").lower(),
        },
        "size_class": _size_class(packets, duration),
        "protocol_hierarchy": phs,
        "endpoints_top": endpoints,
        "conversations_top": conversations_top,
        "ports_top": ports_top,
        "time_distribution": time_distribution,
        "dns_summary": dns_summary,
        "tls_summary": tls_summary,
        "suspicious_hypotheses": _detect_hypotheses(dns_summary["top_domains"]),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_profile.py <pcap>", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(profile(sys.argv[1]), ensure_ascii=False, indent=2))
