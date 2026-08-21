# scripts/entropy_dns.py
"""DNS 熵分析：检测高熵子域名（DGA 特征）。"""
import math, subprocess, sys
from collections import Counter


def _run(cmd: list):
    """执行 tshark 并显式报错（与 pcap_profile.py 约定一致：工具失败必须响亮失败）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError(
            f"命令不存在: {cmd[0]}。请安装 Wireshark 套件 (tshark/capinfos) 并加入 PATH。"
        ) from e
    if r.returncode != 0:
        tail = "\n".join(r.stderr.strip().splitlines()[-5:])
        raise RuntimeError(
            f"命令失败 (exit {r.returncode}): {' '.join(cmd)}\n{tail}")
    return r


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    p = [n / len(s) for n in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)


def analyze_dns_entropy(pcap_path: str, entropy_threshold: float = 3.5,
                        min_len: int = 10) -> list[dict]:
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "dns.qry.name",
           "-Y", "dns.flags.response==0"]
    r = _run(cmd)
    seen = set()
    results = []
    for line in r.stdout.strip().splitlines():
        domain = line.strip()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        subdomain = domain.split(".")[0]
        ent = _entropy(subdomain)
        if ent > entropy_threshold and len(subdomain) > min_len:
            results.append({"domain": domain, "subdomain": subdomain,
                "entropy": round(ent, 2), "verdict": "HIGH_ENTROPY"})
    return sorted(results, key=lambda x: -x["entropy"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python entropy_dns.py <pcap>", file=sys.stderr); sys.exit(1)
    import json
    print(json.dumps(analyze_dns_entropy(sys.argv[1]), ensure_ascii=False, indent=2))
