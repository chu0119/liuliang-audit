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


_DNS_FIELD = None


def _dns_qname_field() -> str:
    """Wireshark ≥4.2 将 dns.qry.name 更名为 dns.qname，探测选择当前版本可用名。"""
    global _DNS_FIELD
    if _DNS_FIELD is None:
        out = _run(["tshark", "-G", "fields"]).stdout
        tokens = {tok for line in out.splitlines() for tok in line.split("\t")}
        _DNS_FIELD = "dns.qname" if "dns.qname" in tokens else "dns.qry.name"
    return _DNS_FIELD


def _dns_extract(call):
    """DNS 字段跨版本兼容：探测选名后运行时若仍报字段无效，自动切换另一名称重试一次。"""
    global _DNS_FIELD
    try:
        return call(_dns_qname_field())
    except RuntimeError as e:
        msg = str(e)
        if "aren't valid" not in msg and "invalid" not in msg.lower():
            raise
    _DNS_FIELD = "dns.qry.name" if _DNS_FIELD == "dns.qname" else "dns.qname"
    return _dns_extract(call)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    p = [n / len(s) for n in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)


def analyze_dns_entropy(pcap_path: str, entropy_threshold: float = 3.5,
                        min_len: int = 10) -> list[dict]:
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "{F}",
           "-Y", "dns.flags.response==0"]
    r = _dns_extract(lambda f: _run(
        [c.replace("{F}", f) for c in cmd]))
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
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    import json
    print(json.dumps(analyze_dns_entropy(sys.argv[1]), ensure_ascii=False, indent=2))
