# scripts/timeline_builder.py
"""事件时间线构建：从多协议字段提取事件并按时间排序。"""
import subprocess, sys


def _run(cmd: list):
    """执行 tshark 并显式报错（与 beacon_detect.py 约定一致：工具失败必须响亮失败）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError(
            f"命令不存在: {cmd[0]}。请安装 Wireshark 套件 (tshark) 并加入 PATH。"
        ) from e
    if r.returncode != 0:
        tail = "\n".join(r.stderr.strip().splitlines()[-5:])
        raise RuntimeError(
            f"命令失败 (exit {r.returncode}): {' '.join(cmd)}"
            + (f"\n{tail}" if tail else ""))
    return r


def _tshark_fields(pcap: str, fields: list, display_filter: str = "") -> list:
    """tshark -T fields 输出，按制表符切分返回每行字段值列表。

    命令参数逐个拆分为独立 token（"-e", field），避免合并成单 token
    在 POSIX exec 下被 tshark 当作一个未知参数；同一协议的多个字段在
    同一次调用中提取以保证按包对齐。使用默认制表符分隔而非 "|"——
    http.request.uri 等字段值本身可能含 "|"，会破坏列对齐。
    """
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    out = _run(cmd).stdout
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


def build_timeline(pcap_path: str) -> list[dict]:
    """从 DNS/HTTP/FTP 明文协议提取事件，按捕获时间升序返回。

    每项含 timestamp（tshark 可读时间）、type、src、dst、detail、severity。
    排序键取 frame.time_epoch 数值——不依赖本地化时间串的字典序
    （部分 tshark 构建的 frame.time 格式无法按字符串正确排序）。
    """
    timed = []
    # DNS 查询事件（时间/源/目的/域名同一次调用按包对齐）
    dns_rows = _dns_extract(lambda f: _tshark_fields(
        pcap_path,
        ["frame.time_epoch", "frame.time", "ip.src", "ip.dst", f],
        "dns.flags.response==0"))
    for row in dns_rows:
        if len(row) >= 5 and row[0].strip():
            try:
                key = float(row[0])
            except ValueError:
                continue
            timed.append((key, {"timestamp": row[1].strip(), "type": "dns_query",
                "src": row[2].strip(), "dst": row[3].strip(),
                "detail": f"DNS 查询: {row[4].strip()}", "severity": "info"}))
    # HTTP 请求事件
    for row in _tshark_fields(pcap_path,
                              ["frame.time_epoch", "frame.time",
                               "ip.src", "ip.dst",
                               "http.request.method", "http.request.uri"],
                              "http.request"):
        if len(row) >= 6 and row[0].strip():
            try:
                key = float(row[0])
            except ValueError:
                continue
            timed.append((key, {"timestamp": row[1].strip(), "type": "http_request",
                "src": row[2].strip(), "dst": row[3].strip(),
                "detail": f"HTTP {row[4].strip()} {row[5].strip()}",
                "severity": "info"}))
    # FTP 凭据事件（PASS 明文口令为高危）
    for row in _tshark_fields(pcap_path,
                              ["frame.time_epoch", "frame.time",
                               "ip.src", "ip.dst",
                               "ftp.request.command", "ftp.request.arg"],
                              "ftp.request.command"):
        if len(row) >= 6 and row[0].strip():
            try:
                key = float(row[0])
            except ValueError:
                continue
            severity = "high" if row[4].strip().upper() == "PASS" else "medium"
            timed.append((key, {"timestamp": row[1].strip(), "type": "ftp_credential",
                "src": row[2].strip(), "dst": row[3].strip(),
                "detail": f"FTP {row[4].strip()} {row[5].strip()}",
                "severity": severity}))
    timed.sort(key=lambda x: x[0])
    return [e for _, e in timed]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python timeline_builder.py <pcap>", file=sys.stderr); sys.exit(1)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    import json
    print(json.dumps(build_timeline(sys.argv[1]), ensure_ascii=False, indent=2))
