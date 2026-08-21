# scripts/ioc_extract.py
"""IOC 提取标准化：从 pcap 提取 IP/域名/URL/哈希/UA/JA3，输出 MISP 格式。

数据契约（extract_iocs -> 消费者）：
{"ips": [...], "domains": [...], "urls": [...], "hashes": [...],
 "ja3": [...], "user_agents": [...]}

urls 为带 scheme 的完整 URL（http://host/uri），符合 MISP url 类型约定。
"""
import csv, subprocess, sys


def _run(cmd: list, check: bool = True):
    """执行 tshark 并显式报错（与 beacon_detect.py 约定一致：工具失败必须响亮失败）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError(
            f"命令不存在: {cmd[0]}。请安装 Wireshark 套件 (tshark) 并加入 PATH。"
        ) from e
    if check and r.returncode != 0:
        tail = "\n".join(r.stderr.strip().splitlines()[-5:])
        raise RuntimeError(
            f"命令失败 (exit {r.returncode}): {' '.join(cmd)}"
            + (f"\n{tail}" if tail else ""))
    return r


def _tshark_fields(pcap: str, fields: list, display_filter: str = "",
                   check: bool = True) -> list:
    """tshark -T fields 输出，按制表符切分返回每行字段值列表。

    命令参数逐个拆分为独立 token（"-e", field），避免合并成单 token
    在 POSIX exec 下被 tshark 当作一个未知参数。
    check=False 时容忍 tshark 失败（用于可选增强字段如 JA3，
    部分 tshark 构建缺失该字段），失败返回空。
    """
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    out = _run(cmd, check=check).stdout
    return [line.split("\t") for line in out.splitlines() if line.strip()]


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
    """DNS 字段跨版本兼容：探测选名后运行时若仍报字段无效，切换另一名称重试一次（有上限，不无限递归）。"""
    global _DNS_FIELD
    first = _dns_qname_field()
    other = "dns.qry.name" if first == "dns.qname" else "dns.qname"
    for cand in (first, other):
        _DNS_FIELD = cand
        try:
            return call(cand)
        except RuntimeError as e:
            msg = str(e)
            retryable = "aren't valid" in msg or "invalid" in msg.lower()
            if not retryable or cand == other:
                raise
    raise RuntimeError("DNS 字段探测失败")  # 不可达：循环内必然 return 或 raise


def _dedupe(values) -> list:
    """去重并保持首次出现顺序，剔除空值。"""
    return list(dict.fromkeys(v for v in values if v))


def extract_iocs(pcap_path: str) -> dict:
    ips = _dedupe(r[0].strip() for r in
                  _tshark_fields(pcap_path, ["ip.dst"], "ip.dst"))
    domain_rows = _dns_extract(lambda f: _tshark_fields(
        pcap_path, [f], "dns.flags.response==0"))
    domains = _dedupe(r[0].strip() for r in domain_rows)
    # host 与 uri 同一次调用按包对齐提取：比两次调用再 zip 更稳健，
    # 避免 filter 命中集合在两次调用间不一致时错位拼接。
    url_rows = _tshark_fields(pcap_path, ["http.host", "http.request.uri"],
                              "http.request")
    urls = _dedupe(f"http://{r[0].strip()}{r[1].strip()}"
                   for r in url_rows if len(r) >= 2
                   and r[0].strip() and r[1].strip())
    ja3s = []
    try:
        ja3_rows = _tshark_fields(pcap_path, ["tls.handshake.ja3"],
                                  "tls.handshake.type==1", check=False)
        ja3s = _dedupe(r[0].strip() for r in ja3_rows)
    except RuntimeError:
        ja3s = []
    uas = _dedupe(r[0].strip() for r in
                  _tshark_fields(pcap_path, ["http.user_agent"], "http.request"))
    return {"ips": ips, "domains": domains, "urls": urls,
            "hashes": [], "ja3": ja3s, "user_agents": uas}


def to_misp_csv(iocs: dict, output_path: str):
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "category"])
        for ip in iocs["ips"]:
            w.writerow(["ip-dst", ip, "Network activity"])
        for domain in iocs["domains"]:
            w.writerow(["domain", domain, "Network activity"])
        for url in iocs["urls"]:
            w.writerow(["url", url, "Network activity"])
        for ja3 in iocs["ja3"]:
            w.writerow(["ja3-fingerprint-md5", ja3, "Payload delivery"])
        for ua in iocs["user_agents"]:
            w.writerow(["user-agent", ua, "Payload delivery"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ioc_extract.py <pcap> [output.csv]", file=sys.stderr); sys.exit(1)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    import json
    iocs = extract_iocs(sys.argv[1])
    if len(sys.argv) >= 3:
        to_misp_csv(iocs, sys.argv[2])
    else:
        print(json.dumps(iocs, ensure_ascii=False, indent=2))
