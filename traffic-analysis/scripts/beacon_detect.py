# scripts/beacon_detect.py
"""C2 信标检测：按目标 IP:port 分组 SYN 包时间戳，计算间隔抖动。"""
import subprocess, statistics, sys
from collections import defaultdict

def detect_beacons(pcap_path: str, min_count: int = 5, max_jitter: float = 30.0) -> list[dict]:
    cmd = ["tshark", "-r", pcap_path, "-T", "fields",
           "-e", "frame.time_epoch", "-e", "ip.dst", "-e", "tcp.dstport",
           "-Y", "tcp.flags.syn==1 and tcp.flags.ack==0"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    groups = defaultdict(list)
    for line in r.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0]:
            try:
                ts = float(parts[0])
                dst = f"{parts[1]}:{parts[2]}"
                groups[dst].append(ts)
            except ValueError:
                continue
    results = []
    for dst, times in groups.items():
        times.sort()
        if len(times) < min_count:
            continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter = (stdev / avg * 100) if avg > 0 else 0
        verdict = "LIKELY_BEACON" if jitter < max_jitter and 10 < avg < 3600 else "IRREGULAR"
        results.append({"dst": dst, "count": len(times), "avg_interval": round(avg, 1),
            "stdev": round(stdev, 1), "jitter_pct": round(jitter, 1), "verdict": verdict})
    return sorted(results, key=lambda x: x["jitter_pct"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python beacon_detect.py <pcap>", file=sys.stderr); sys.exit(1)
    import json
    print(json.dumps(detect_beacons(sys.argv[1]), ensure_ascii=False, indent=2))
