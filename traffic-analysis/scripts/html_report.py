# scripts/html_report.py
"""HTML 可视化报告生成：占位符替换渲染自包含单文件报告，无构建步骤。

数据契约（消费者 <- 生产者）：
- profile: pcap_profile.profile() 的 JSON dict
- timeline: timeline_builder.build_timeline() 列表（severity ∈ info|medium|high）
- iocs: ioc_extract.extract_iocs() 的 dict

安全约定：
- 所有 pcap 派生字符串（域名/URI/UA 等，均属不可信输入）经 html.escape
  转义后再注入模板；
- Chart.js 经 CDN 加载：钉死完整版本号 URL + Subresource Integrity
  (sha384) + crossorigin=anonymous，模板内含校验命令注释。
"""
import html
import json
import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "html_report.tpl.html"


def _esc(value) -> str:
    """HTML 转义任意 pcap 派生值。"""
    return html.escape(str(value), quote=True)


def _empty_row(cols: int) -> str:
    return f'<tr><td colspan="{cols}" class="muted">无记录</td></tr>'


def _fmt_endpoints(endpoints: list) -> str:
    if not endpoints:
        return _empty_row(3)
    return "".join(
        f"<tr><td>{_esc(e.get('ip', ''))}</td>"
        f"<td>{_esc(e.get('packets', ''))}</td>"
        f"<td>{_esc(e.get('bytes', ''))}</td></tr>"
        for e in endpoints[:10])


def _fmt_dns(domains: list) -> str:
    if not domains:
        return _empty_row(2)
    return "".join(
        f"<tr><td>{_esc(d.get('domain', ''))}</td>"
        f"<td>{_esc(d.get('count', ''))}</td></tr>"
        for d in domains[:10])


def _fmt_timeline(events: list) -> str:
    if not events:
        return '<div class="timeline-item muted">无事件</div>'
    return "".join(
        '<div class="timeline-item">'
        f'<span class="severity-{_esc(e.get("severity", "info"))}">'
        f'[{_esc(e.get("type", ""))}]</span> '
        f'{_esc(e.get("src", ""))} → {_esc(e.get("dst", ""))}: '
        f'{_esc(e.get("detail", ""))} '
        f'<small>({e.get("timestamp", "")})</small></div>'
        for e in events[:50])


def _fmt_hypotheses(hypotheses: list) -> str:
    if not hypotheses:
        return _empty_row(3)
    rows = []
    for h in hypotheses[:20]:
        evidence = json.dumps(h.get("evidence", {}), ensure_ascii=False)
        rows.append(
            f'<tr><td><span class="severity-{_esc(h.get("severity", "info"))}">'
            f'{_esc(h.get("type", ""))}</span></td>'
            f'<td>{_esc(h.get("description", ""))}</td>'
            f'<td><code>{_esc(evidence)}</code></td></tr>')
    return "".join(rows)


def _fmt_iocs(iocs: dict) -> str:
    categories = [("ips", "ip"), ("domains", "domain"), ("urls", "url"),
                  ("hashes", "hash"), ("ja3", "ja3"),
                  ("user_agents", "user_agent")]
    rows = []
    for key, label in categories:
        for value in iocs.get(key, [])[:50]:
            rows.append(f"<tr><td>{label}</td><td>{_esc(value)}</td></tr>")
    if not rows:
        return _empty_row(2)
    return "".join(rows)


def generate_html_report(pcap_path: str, output_path: str,
                         profile: dict = None, timeline: list = None,
                         iocs: dict = None) -> str:
    """渲染 HTML 报告并写入 output_path，返回该路径。

    三个数据参数缺省时按 documented 回退路径懒加载对应生产者脚本。
    """
    if profile is None:
        from pcap_profile import profile as _profile_fn
        profile = _profile_fn(pcap_path)
    if timeline is None:
        from timeline_builder import build_timeline
        timeline = build_timeline(pcap_path)
    if iocs is None:
        from ioc_extract import extract_iocs
        iocs = extract_iocs(pcap_path)

    try:
        tpl = TEMPLATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"模板文件不存在: {TEMPLATE_PATH}"
            "。请确认 templates/html_report.tpl.html 与脚本一同分发。") from e

    capture = profile.get("capture", {})
    phs = profile.get("protocol_hierarchy", [])
    repl = {
        "{{PCAP_NAME}}": Path(pcap_path).name,
        "{{PACKETS_TOTAL}}": str(capture.get("packets_total", "")),
        "{{DURATION}}": str(capture.get("duration_seconds", "")),
        "{{SIZE_CLASS}}": str(profile.get("size_class", "")),
        "{{START_TIME}}": str(capture.get("start_time", "")),
        "{{LINK_TYPE}}": str(capture.get("link_type", "")),
        "{{ENDPOINTS_ROWS}}": _fmt_endpoints(profile.get("endpoints_top", [])),
        "{{DNS_ROWS}}": _fmt_dns(
            profile.get("dns_summary", {}).get("top_domains", [])),
        "{{TIMELINE_ITEMS}}": _fmt_timeline(timeline),
        "{{HYPOTHESES_ROWS}}": _fmt_hypotheses(
            profile.get("suspicious_hypotheses", [])),
        "{{IOC_ROWS}}": _fmt_iocs(iocs),
        # 图表注入点为 JS 数组字面量：json.dumps 保证合法转义，
        # 协议名来自 tshark io,phs（ASCII），无引号冲突风险。
        "{{PROTO_LABELS}}": json.dumps([p["protocol"] for p in phs[:6]],
                                       ensure_ascii=False),
        "{{PROTO_DATA}}": json.dumps([p["packets"] for p in phs[:6]]),
    }

    # 契约守卫：模板缺任一占位符说明模板与代码漂移，响亮报错而非静默漏渲染。
    missing = [k for k in repl if k not in tpl]
    if missing:
        raise RuntimeError(
            f"模板缺少必需占位符: {', '.join(missing)} (模板: {TEMPLATE_PATH})")

    for k, v in repl.items():
        tpl = tpl.replace(k, v)

    Path(output_path).write_text(tpl, encoding="utf-8")
    return output_path


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python html_report.py <pcap> <output.html>",
              file=sys.stderr); sys.exit(1)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    generate_html_report(sys.argv[1], sys.argv[2])
    print(f"报告已生成: {sys.argv[2]}")
