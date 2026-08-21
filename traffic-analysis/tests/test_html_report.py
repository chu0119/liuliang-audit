# tests/test_html_report.py
import sys; sys.path.insert(0, "scripts")
import json
import os
import re
import subprocess

import pytest

import html_report
from html_report import TEMPLATE_PATH, generate_html_report

CONTRACT_PLACEHOLDERS = [
    "{{PCAP_NAME}}", "{{PACKETS_TOTAL}}", "{{DURATION}}", "{{SIZE_CLASS}}",
    "{{START_TIME}}", "{{LINK_TYPE}}", "{{ENDPOINTS_ROWS}}", "{{DNS_ROWS}}",
    "{{TIMELINE_ITEMS}}", "{{IOC_ROWS}}", "{{PROTO_LABELS}}", "{{PROTO_DATA}}",
]


def _full_generate(pcap, out):
    """带显式数据的完整管线（brief 用法）：profile + timeline + iocs 全传入。"""
    from ioc_extract import extract_iocs
    from pcap_profile import profile
    from timeline_builder import build_timeline
    return generate_html_report(str(pcap), str(out), profile(str(pcap)),
                                build_timeline(str(pcap)), extract_iocs(str(pcap)))


def _synthetic_profile():
    """不依赖 tshark 的最小合法 profile（契约键齐全），供纯单元测试。"""
    return {
        "file": "x.pcap",
        "capture": {"packets_total": 18, "bytes_total": 895,
                    "duration_seconds": 230.5,
                    "start_time": "2026-01-01 00:00:00",
                    "link_type": "Ethernet", "truncated": False},
        "size_class": "small",
        "protocol_hierarchy": [{"protocol": "tcp", "packets": 14, "pct": 77.78},
                               {"protocol": "udp", "packets": 3, "pct": 16.67}],
        "endpoints_top": [{"ip": "10.0.0.5", "packets": 18, "bytes": 895}],
        "conversations_top": [], "ports_top": [], "time_distribution": [],
        "dns_summary": {"queries_total": 1, "unique_domains": 1,
                        "top_domains": [{"domain": "example.com", "count": 1}]},
        "tls_summary": {"handshakes": 0, "unique_sni": [], "ja3_fingerprints": []},
        "suspicious_hypotheses": [{"type": "dga_dns", "severity": "medium",
                                   "description": "高熵域名疑似 DGA: a1b2.example.com",
                                   "evidence": {"domain": "a1b2.example.com",
                                                "entropy": 3.61}}],
    }


def test_generates_html_file(test_pcap, tmp_path):
    out = tmp_path / "report.html"
    result = _full_generate(test_pcap, out)
    assert out.exists()
    assert result == str(out)
    content = out.read_text(encoding="utf-8")
    assert "<html" in content
    assert "185.220.101.42" in content
    assert "</html>" in content


def test_all_contract_placeholders_replaced(test_pcap, tmp_path):
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    for ph in CONTRACT_PLACEHOLDERS:
        assert ph not in content, f"占位符未被替换: {ph}"


def test_basic_info_values_rendered(test_pcap, tmp_path):
    """基本信息卡渲染 profile 的真实值（文件名/包数/大小类/时间/链路类型）。"""
    from pcap_profile import profile
    prof = profile(str(test_pcap))
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    assert "test_full.pcap" in content          # PCAP_NAME 取文件名而非全路径
    assert str(prof["capture"]["packets_total"]) in content
    assert prof["size_class"] in content
    assert prof["capture"]["start_time"] in content
    assert prof["capture"]["link_type"] in content


def test_chart_data_is_valid_json(test_pcap, tmp_path):
    """PROTO_LABELS/PROTO_DATA 必须是合法 JSON 数组，Chart.js 才能消费。"""
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    m_labels = re.search(r"labels:(\[[^\]]*\])", content)
    m_data = re.search(r"data:(\[[^\]]*\]),backgroundColor", content)
    assert m_labels and m_data, "未找到图表数据注入点"
    labels = json.loads(m_labels.group(1))
    data = json.loads(m_data.group(1))
    assert isinstance(labels, list) and labels
    assert isinstance(data, list) and len(data) == len(labels)
    assert "tcp" in labels


def test_chartjs_script_has_sri(test_pcap, tmp_path):
    """安全要求：CDN script 必须携带可验证的 SRI（sha384）+ crossorigin=anonymous，
    且版本钉死为完整版本号 URL（不得用 @4 或 @latest 浮动标签）。"""
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    tags = re.findall(r"<script[^>]*chart\.js@[\w.]+[^>]*></script>", content)
    assert len(tags) == 1, "应恰好一个 Chart.js CDN script 标签"
    tag = tags[0]
    assert 'src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"' in tag
    # sha384 摘要 48 字节 -> base64 恰 64 字符、无 padding
    m = re.search(r'integrity="(sha384-[A-Za-z0-9+/]{64})"', tag)
    assert m, "script 标签必须含 sha384 integrity 属性"
    assert 'crossorigin="anonymous"' in tag


def test_timeline_items_and_severity_classes(test_pcap, tmp_path):
    """时间线渲染为 timeline-item，severity 类名与模板 CSS 对齐（high 来自 FTP PASS）。"""
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    assert 'class="timeline-item"' in content
    assert "severity-high" in content
    assert "ftp_credential" in content
    assert "a1b2c3d4e5f6g7h8i9j0.example.com" in content


def test_ioc_rows_cover_all_categories(test_pcap, tmp_path):
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    assert ">ip<" in content and "185.220.101.42" in content
    assert ">domain<" in content and "a1b2c3d4e5f6g7h8i9j0.example.com" in content
    assert ">url<" in content and "http://evil.com/secret.txt" in content


def test_suspicious_hypotheses_section(test_pcap, tmp_path):
    """夹具中的高熵 DGA 域名应触发假设并进入报告专属区块。"""
    out = tmp_path / "report.html"
    _full_generate(test_pcap, out)
    content = out.read_text(encoding="utf-8")
    assert "dga_dns" in content
    assert "高熵域名疑似 DGA" in content


def test_fallback_imports_when_args_none(test_pcap, tmp_path):
    """documented 回退路径：不传数据时懒加载三个生产者脚本，输出同样完整。"""
    out = tmp_path / "fallback.html"
    result = generate_html_report(str(test_pcap), str(out))
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    for ph in CONTRACT_PLACEHOLDERS:
        assert ph not in content, f"占位符未被替换: {ph}"
    assert "185.220.101.42" in content


def test_html_escapes_attacker_controlled_values(tmp_path):
    """pcap 内字符串（域名/UA/明细）是不可信输入，注入 HTML 前必须转义。"""
    profile = _synthetic_profile()
    profile["dns_summary"]["top_domains"] = [
        {"domain": '<script>alert(1)</script>', "count": 1}]
    profile["endpoints_top"] = [{"ip": '"><img src=x onerror=alert(1)>',
                                 "packets": 1, "bytes": 1}]
    timeline = [{"timestamp": "t", "type": "http_request", "src": "1.1.1.1",
                 "dst": "2.2.2.2", "detail": "<b>bold</b>", "severity": "info"}]
    iocs = {"ips": ["1.1.1.1"], "domains": ["<script>x</script>"],
            "urls": [], "hashes": [], "ja3": ["e7d705a3286ef19405f687c6ce926d66"],
            "user_agents": ['Mozilla/5.0 "<svg onload=alert(1)>']}
    out = tmp_path / "escape.html"
    generate_html_report("ignored.pcap", str(out), profile, timeline, iocs)
    content = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "<img src=x" not in content
    assert "<svg onload" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "&lt;b&gt;bold&lt;/b&gt;" in content
    assert "e7d705a3286ef19405f687c6ce926d66" in content  # ja3 也进 IOC 清单


def test_synthetic_profile_renders_hypotheses_and_totals(tmp_path):
    out = tmp_path / "synthetic.html"
    generate_html_report("x.pcap", str(out), _synthetic_profile(), [], {})
    content = out.read_text(encoding="utf-8")
    assert "18" in content            # PACKETS_TOTAL
    assert "230.5" in content         # DURATION
    assert "2026-01-01 00:00:00" in content  # START_TIME
    assert "dga_dns" in content       # HYPOTHESES 区块
    assert "example.com" in content   # DNS 行
    assert "10.0.0.5" in content      # 端点行
    for ph in CONTRACT_PLACEHOLDERS:
        assert ph not in content


def test_placeholder_lookalike_data_not_reprocessed(tmp_path):
    """数据值中出现占位符样式字符串时不得被二次替换（单遍替换守卫）。"""
    profile = _synthetic_profile()
    profile["capture"]["link_type"] = "{{DNS_ROWS}}"
    out = tmp_path / "lookalike.html"
    generate_html_report("x.pcap", str(out), profile, [], {})
    content = out.read_text(encoding="utf-8")
    assert "<td>{{DNS_ROWS}}</td>" in content


def test_pcap_name_is_escaped(tmp_path):
    """文件名同样不可信，注入 <title>/基本信息前必须转义。
    （payload 不能含 '/'——那会被 Path 当作目录分隔符截断。）"""
    out = tmp_path / "name.html"
    generate_html_report('"><svg onload=alert(1)>.pcap', str(out),
                         _synthetic_profile(), [], {})
    content = out.read_text(encoding="utf-8")
    assert "<svg onload=alert(1)>" not in content
    assert "&quot;&gt;&lt;svg onload=alert(1)&gt;.pcap" in content


def test_missing_template_raises_loudly(monkeypatch, tmp_path):
    """全局约束：模板缺失必须响亮报错，不得静默产出空壳文件。"""
    monkeypatch.setattr(html_report, "TEMPLATE_PATH",
                        tmp_path / "no_such_template.tpl.html")
    with pytest.raises(FileNotFoundError, match="模板"):
        generate_html_report("x.pcap", str(tmp_path / "out.html"),
                             _synthetic_profile(), [], {})


def test_template_placeholder_drift_raises(monkeypatch, tmp_path):
    """契约守卫：模板缺任一占位符时 RuntimeError 指名缺失项，防模板/代码漂移。"""
    tpl = tmp_path / "drifted.tpl.html"
    tpl.write_text("<html><body>{{PCAP_NAME}}</body></html>", encoding="utf-8")
    monkeypatch.setattr(html_report, "TEMPLATE_PATH", tpl)
    with pytest.raises(RuntimeError, match="IOC_ROWS"):
        generate_html_report("x.pcap", str(tmp_path / "out.html"),
                             _synthetic_profile(), [], {})


def test_cli_generates_report_with_utf8_stdout(test_pcap, tmp_path):
    """CLI 冒烟：退出码 0、文件落盘、GBK 管道下中文提示仍以 UTF-8 输出。"""
    out = tmp_path / "cli.html"
    env = dict(os.environ, PYTHONIOENCODING="gbk")
    r = subprocess.run(
        [sys.executable, "scripts/html_report.py", str(test_pcap), str(out)],
        capture_output=True, env=env)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    assert out.exists()
    assert "报告已生成" in r.stdout.decode("utf-8")
    assert "<html" in out.read_text(encoding="utf-8")


def test_cli_usage_guard_exits_nonzero():
    r = subprocess.run([sys.executable, "scripts/html_report.py"],
                       capture_output=True)
    assert r.returncode == 1
    assert b"Usage" in r.stderr
