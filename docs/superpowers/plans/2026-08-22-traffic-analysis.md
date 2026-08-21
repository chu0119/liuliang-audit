# traffic-analysis Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建面向专业安全人士的流量分析审计 skill，对 pcap 包进行全类型分析（识别→画像→筛查→研判→输出），输出 Markdown 报告 + HTML 可视化报告 + 标准化 IOC 清单。

**Architecture:** SKILL.md 定义阶段式工作流，Claude 调度 tshark 完成统计/过滤/提取，7 个确定性 Python 脚本完成聚合计算（信标检测、熵分析、IOC 提取、时间线构建、HTML 报告）。所有统计走 tshark C 实现，Python 仅做聚合，禁止全量载入内存。pcap_profile.py 的 JSON 输出是核心契约，timeline_builder.py 与 html_report.py 消费它。

**Tech Stack:** Python 3.12（标准库为主，scapy/pyshark 仅增强）、tshark（Wireshark 套件，必装）、Zeek/Suricata 可选（未装自动降级）、Chart.js via CDN（HTML 报告内嵌图表）

## Global Constraints

- 平台：Windows 11，Git Bash 环境，路径分隔符兼容
- 编码：所有脚本强制 UTF-8 读写，tshark 输出用 `-T fields` 规避表格对齐问题
- 性能红线：禁止 `rdpcap` 全量载入内存；GB 级文件强制切片/流切割路径
- 检测引擎：tshark 必装核心；Zeek/Suricata 可选，未装自动降级并在报告标注
- 脚本风格：独立可运行 `python scripts/xxx.py`，无共享包，无 `__init__.py`
- 依赖：核心功能仅标准库 + tshark 输出解析；scapy/pyshark 缺失不阻塞主流程
- 输出目录：自动创建（pcap 名 + 时间戳），权限不足明确提示
- 报告降级：HTML 模板纯占位符替换无构建步骤，最坏只剩 MD 仍可交付
- 测试：脚本级用 scapy 构造测试 pcap + pytest；文档级验证覆盖要点

---

## File Structure

```
traffic-analysis/                      # skill 根目录
├── SKILL.md                           # 主入口：触发词 + 场景路由 + 阶段式工作流
├── references/
│   ├── 01-pcap-basics.md
│   ├── 02-traffic-profiling.md
│   ├── 03-protocol-deepdive.md
│   ├── 04-attack-detection.md
│   ├── 05-ctf-forensics.md
│   ├── 06-incident-response.md
│   ├── 07-visualization.md
│   └── 08-ids-engines.md
├── scripts/
│   ├── pcap_profile.py                # 核心契约：一键画像 → JSON
│   ├── beacon_detect.py               # C2 信标检测
│   ├── entropy_dns.py                 # DNS 熵 / DGA 检测
│   ├── extract_files.py               # 对象提取 + SHA-256
│   ├── ioc_extract.py                 # IOC 标准化（MISP）
│   ├── timeline_builder.py            # 事件时间线
│   └── html_report.py                 # HTML 可视化报告生成
├── templates/
│   ├── report_ctf.md
│   ├── report_ir.md
│   ├── report_attackdef.md
│   ├── ioc_misp.csv.tpl
│   └── html_report.tpl.html
├── examples/
│   └── ctf-http-flag-walkthrough.md
└── tests/
    ├── conftest.py                    # 共享测试夹具（测试 pcap 生成器）
    ├── testdata/
    ├── test_pcap_profile.py
    ├── test_beacon_detect.py
    ├── test_entropy_dns.py
    ├── test_extract_files.py
    ├── test_ioc_extract.py
    ├── test_timeline_builder.py
    ├── test_html_report.py
    └── test_integration.py
```

**数据契约（pcap_profile.py → 消费者）：**

```json
{
  "file": "path.pcap",
  "capture": {
    "packets_total": 12345,
    "bytes_total": 67890,
    "duration_seconds": 300.5,
    "start_time": "2026-08-21T10:00:00",
    "link_type": "Ethernet",
    "truncated": false
  },
  "size_class": "small|medium|large",
  "protocol_hierarchy": [{"protocol": "eth", "packets": 12000, "pct": 97.2}],
  "endpoints_top": [{"ip": "10.0.0.5", "packets": 5000, "bytes": 30000}],
  "conversations_top": [{"src": "10.0.0.5:443", "dst": "10.0.0.1:52334", "packets": 800, "bytes": 120000}],
  "ports_top": [{"port": 443, "protocol": "tcp", "packets": 4000}],
  "time_distribution": [{"bucket": "0-60s", "packets": 2000}],
  "dns_summary": {"queries_total": 47, "unique_domains": 23, "top_domains": [{"domain": "example.com", "count": 10}]},
  "tls_summary": {"handshakes": 10, "unique_sni": ["example.com"], "ja3_fingerprints": [{"ja3": "abc123", "count": 5}]},
  "suspicious_hypotheses": [{"type": "c2_beacon", "severity": "high", "description": "...", "evidence": {"dst": "1.2.3.4:443", "interval": 60}}]
}
```

---

## Tasks

### Task 1: 项目脚手架与测试基础设施

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/testdata/.gitkeep`

**Interfaces:**
- Produces: `test_pcap` pytest fixture — 生成含以下流量的临时 pcap 文件路径：HTTP 文件下载、高熵 DNS 查询、周期信标流（每 30s 一次，共 10 次）、ICMP 隧道包、明文 FTP 凭据。返回 `pathlib.Path`。

- [ ] **Step 1: 创建目录结构**

```bash
mkdir -p traffic-analysis/{references,scripts,templates,examples,tests/testdata}
touch traffic-analysis/tests/__init__.py traffic-analysis/tests/testdata/.gitkeep
```

- [ ] **Step 2: 编写 conftest.py（测试 pcap 生成器）**

```python
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
```

- [ ] **Step 3: 验证 conftest.py 语法正确**

```bash
cd traffic-analysis
python -c "import ast; ast.parse(open('tests/conftest.py').read()); print('conftest.py 语法 OK')"
```
Expected: 输出 "conftest.py 语法 OK"

- [ ] **Step 4: 提交**

```bash
cd traffic-analysis
git add tests/ && git commit -m "chore: add test infrastructure and test pcap generator"
```

---

### Task 2: pcap_profile.py（核心契约脚本）

**Files:**
- Create: `scripts/pcap_profile.py`
- Test: `tests/test_pcap_profile.py`

**Interfaces:**
- Produces: `profile(pcap_path: str) -> dict` — 返回数据契约中的 JSON 结构
- Produces: CLI `python scripts/pcap_profile.py <pcap>` — 打印 JSON 到 stdout
- Consumes: `capinfos`, `tshark -z io,phs/endpoints,ip/dns,tree` 输出（文本解析）

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_pcap_profile.py
import json, subprocess, sys
sys.path.insert(0, "scripts")
from pcap_profile import profile

def test_profile_returns_contract_keys(test_pcap):
    result = profile(str(test_pcap))
    assert "file" in result
    assert "capture" in result
    assert "size_class" in result
    assert result["size_class"] in ("small", "medium", "large")
    assert "protocol_hierarchy" in result
    assert "endpoints_top" in result
    assert "suspicious_hypotheses" in result

def test_profile_detects_high_entropy_dns(test_pcap):
    result = profile(str(test_pcap))
    dns = result.get("dns_summary", {})
    assert dns["queries_total"] >= 1
    types = [h["type"] for h in result["suspicious_hypotheses"]]
    assert any("dns" in t or "dga" in t for t in types)

def test_profile_cli_prints_json(test_pcap):
    result = subprocess.run(
        [sys.executable, "scripts/pcap_profile.py", str(test_pcap)],
        capture_output=True, text=True
    )
    parsed = json.loads(result.stdout)
    assert parsed["capture"]["packets_total"] > 0
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_pcap_profile.py -v
```
Expected: FAIL，"module not found"

- [ ] **Step 3: 实现 pcap_profile.py**

```python
# scripts/pcap_profile.py
"""一键 pcap 画像：封装 capinfos + tshark -z 统计，输出标准化 JSON。"""
import json, re, subprocess, sys
from pathlib import Path

def _run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
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

def _parse_phs(out: str) -> list[dict]:
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\w[\w ]*?)\s{2,}(\d+)\s+([\d.]+)%", line)
        if m:
            rows.append({"protocol": m.group(1).strip(), "packets": int(m.group(2)), "pct": float(m.group(3))})
    return rows

def _parse_endpoints(out: str) -> list[dict]:
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)", line)
        if m:
            rows.append({"ip": m.group(1), "packets": int(m.group(2)), "bytes": int(m.group(3))})
    return rows[:10]

def _parse_dns_tree(out: str) -> list[dict]:
    domains = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(\S+\.\w+)\s+(\d+)", line)
        if m:
            domains[m.group(1)] = int(m.group(2))
    return [{"domain": d, "count": c} for d, c in sorted(domains.items(), key=lambda x: -x[1])[:10]]

def _size_class(packets: int, duration: float) -> str:
    if packets < 50_000 and duration < 600:
        return "small"
    if packets < 500_000 and duration < 3600:
        return "medium"
    return "large"

def _detect_hypotheses(dns_domains: list[dict]) -> list[dict]:
    import math
    from collections import Counter
    def entropy(s):
        p = [n/len(s) for n in Counter(s).values()]
        return -sum(x * math.log2(x) for x in p if x > 0)
    hypotheses = []
    for d in dns_domains:
        sub = d["domain"].split(".")[0]
        if entropy(sub) > 3.5 and len(sub) > 10:
            hypotheses.append({"type": "dga_dns", "severity": "medium",
                "description": f"高熵域名疑似 DGA: {d['domain']}",
                "evidence": {"domain": d["domain"], "entropy": round(entropy(sub), 2)}})
    return hypotheses

def profile(pcap_path: str) -> dict:
    info = _capinfos(pcap_path)
    packets = int(info.get("Number of packets", "0").replace(",", ""))
    duration = float(info.get("Capture duration", "0").split()[0]) if "Capture duration" in info else 0
    phs = _parse_phs(_tshark_z(pcap_path, "io,phs"))
    endpoints = _parse_endpoints(_tshark_z(pcap_path, "endpoints,ip"))
    dns_tree = _parse_dns_tree(_tshark_z(pcap_path, "dns,tree"))
    return {
        "file": str(Path(pcap_path).resolve()),
        "capture": {
            "packets_total": packets,
            "bytes_total": int(info.get("File size", "0").replace(",", "")) if "File size" in info else 0,
            "duration_seconds": duration,
            "start_time": info.get("First packet time", ""),
            "link_type": info.get("Capture type", ""),
            "truncated": "truncated" in info.get("File comment", "").lower()
        },
        "size_class": _size_class(packets, duration),
        "protocol_hierarchy": phs,
        "endpoints_top": endpoints,
        "conversations_top": [],
        "ports_top": [],
        "time_distribution": [],
        "dns_summary": {"queries_total": sum(d["count"] for d in dns_tree), "unique_domains": len(dns_tree), "top_domains": dns_tree},
        "tls_summary": {"handshakes": 0, "unique_sni": [], "ja3_fingerprints": []},
        "suspicious_hypotheses": _detect_hypotheses(dns_tree)
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_profile.py <pcap>", file=sys.stderr); sys.exit(1)
    print(json.dumps(profile(sys.argv[1]), ensure_ascii=False, indent=2))
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_pcap_profile.py -v
```
Expected: 3 PASSED

- [ ] **Step 5: 提交**

```bash
cd traffic-analysis
git add scripts/pcap_profile.py tests/test_pcap_profile.py
git commit -m "feat: add pcap_profile.py core contract script"
```

---

### Task 3: beacon_detect.py（C2 信标检测）

**Files:**
- Create: `scripts/beacon_detect.py`
- Test: `tests/test_beacon_detect.py`

**Interfaces:**
- Produces: `detect_beacons(pcap_path: str, min_count: int = 5, max_jitter: float = 30.0) -> list[dict]` — 每项含 `dst`, `count`, `avg_interval`, `stdev`, `jitter_pct`, `verdict`
- Consumes: `tshark -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport -Y "tcp.flags.syn==1"`

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_beacon_detect.py
import sys; sys.path.insert(0, "scripts")
from beacon_detect import detect_beacons

def test_detects_periodic_beacon(test_pcap):
    beacons = detect_beacons(str(test_pcap))
    assert len(beacons) >= 1
    b = beacons[0]
    assert b["dst"] == "185.220.101.42:443"
    assert b["count"] >= 5
    assert 25 < b["avg_interval"] < 35
    assert b["verdict"] == "LIKELY_BEACON"

def test_no_beacon_sparse_traffic(tmp_path):
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)
    assert detect_beacons(str(p)) == []
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_beacon_detect.py -v
```
Expected: FAIL

- [ ] **Step 3: 实现 beacon_detect.py**

```python
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
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_beacon_detect.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: 提交**

```bash
cd traffic-analysis
git add scripts/beacon_detect.py tests/test_beacon_detect.py
git commit -m "feat: add beacon_detect.py C2 beacon detection"
```

---

### Task 4: entropy_dns.py（DNS 熵 / DGA 检测）

**Files:**
- Create: `scripts/entropy_dns.py`
- Test: `tests/test_entropy_dns.py`

**Interfaces:**
- Produces: `analyze_dns_entropy(pcap_path: str, entropy_threshold: float = 3.5, min_len: int = 10) -> list[dict]` — 每项含 `domain`, `subdomain`, `entropy`, `verdict`
- Consumes: `tshark -T fields -e dns.qry.name -Y "dns.flags.response==0"`

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_entropy_dns.py
import sys; sys.path.insert(0, "scripts")
from entropy_dns import analyze_dns_entropy

def test_detects_dga_domain(test_pcap):
    results = analyze_dns_entropy(str(test_pcap))
    domains = [r["domain"] for r in results]
    assert any("a1b2c3d4e5f6" in d for d in domains)
    assert results[0]["verdict"] == "HIGH_ENTROPY"

def test_no_dns_returns_empty(tmp_path):
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "nodns.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)
    assert analyze_dns_entropy(str(p)) == []
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_entropy_dns.py -v
```
Expected: FAIL

- [ ] **Step 3: 实现 entropy_dns.py**

```python
# scripts/entropy_dns.py
"""DNS 熵分析：检测高熵子域名（DGA 特征）。"""
import math, subprocess, sys
from collections import Counter

def _entropy(s: str) -> float:
    p = [n/len(s) for n in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p if x > 0)

def analyze_dns_entropy(pcap_path: str, entropy_threshold: float = 3.5, min_len: int = 10) -> list[dict]:
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "dns.qry.name",
           "-Y", "dns.flags.response==0"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
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
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_entropy_dns.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: 提交**

```bash
cd traffic-analysis
git add scripts/entropy_dns.py tests/test_entropy_dns.py
git commit -m "feat: add entropy_dns.py DGA detection"
```

---

### Task 5: extract_files.py（对象提取 + 哈希）

**Files:**
- Create: `scripts/extract_files.py`
- Test: `tests/test_extract_files.py`

**Interfaces:**
- Produces: `extract_objects(pcap_path: str, output_dir: str, protocols: list[str] = None) -> list[dict]` — 每项含 `filename`, `size`, `sha256`, `protocol`
- Consumes: `tshark --export-objects <proto>,<dir>`

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_extract_files.py
import sys; sys.path.insert(0, "scripts")
from extract_files import extract_objects

def test_extracts_http_objects(test_pcap, tmp_path):
    out = tmp_path / "extracted"
    result = extract_objects(str(test_pcap), str(out))
    assert len(result) >= 1
    assert result[0]["protocol"] == "http"
    assert "sha256" in result[0]
    assert len(result[0]["sha256"]) == 64

def test_empty_pcap_returns_empty(tmp_path):
    from scapy.all import wrpcap, IP, TCP
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [IP()/TCP()] * 3)
    result = extract_objects(str(p), str(tmp_path / "out"))
    assert result == []
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_extract_files.py -v
```
Expected: FAIL

- [ ] **Step 3: 实现 extract_files.py**

```python
# scripts/extract_files.py
"""对象提取封装：调用 tshark --export-objects 并计算 SHA-256。"""
import hashlib, subprocess, sys
from pathlib import Path

def extract_objects(pcap_path: str, output_dir: str, protocols: list[str] = None) -> list[dict]:
    if protocols is None:
        protocols = ["http", "smb", "tftp"]
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for proto in protocols:
        proto_dir = out / proto
        proto_dir.mkdir(exist_ok=True)
        subprocess.run(["tshark", "-r", pcap_path, "--export-objects", f"{proto},{proto_dir}"],
            capture_output=True, encoding="utf-8", errors="replace")
        for f in proto_dir.iterdir():
            if f.is_file():
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                results.append({"filename": f.name, "size": f.stat().st_size,
                    "sha256": h, "protocol": proto, "path": str(f)})
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_files.py <pcap> <output_dir>", file=sys.stderr); sys.exit(1)
    import json
    print(json.dumps(extract_objects(sys.argv[1], sys.argv[2]), ensure_ascii=False, indent=2))
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_extract_files.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: 提交**

```bash
cd traffic-analysis
git add scripts/extract_files.py tests/test_extract_files.py
git commit -m "feat: add extract_files.py object extraction with SHA-256"
```

---

### Task 6: ioc_extract.py（IOC 标准化）

**Files:**
- Create: `scripts/ioc_extract.py`
- Test: `tests/test_ioc_extract.py`

**Interfaces:**
- Produces: `extract_iocs(pcap_path: str) -> dict` — `{"ips": [...], "domains": [...], "urls": [...], "hashes": [...], "ja3": [...], "user_agents": [...]}`
- Produces: `to_misp_csv(iocs: dict, output_path: str)` — 写入 MISP 格式 CSV
- Consumes: tshark 多协议字段提取

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_ioc_extract.py
import sys; sys.path.insert(0, "scripts")
from ioc_extract import extract_iocs, to_misp_csv

def test_extracts_ips_and_domains(test_pcap):
    iocs = extract_iocs(str(test_pcap))
    assert "185.220.101.42" in iocs["ips"]
    assert any("example.com" in d for d in iocs["domains"])

def test_misp_csv_writes(test_pcap, tmp_path):
    iocs = extract_iocs(str(test_pcap))
    csv_path = tmp_path / "iocs.csv"
    to_misp_csv(iocs, str(csv_path))
    assert csv_path.exists()
    content = csv_path.read_text(encoding="utf-8")
    assert "185.220.101.42" in content
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_ioc_extract.py -v
```
Expected: FAIL

- [ ] **Step 3: 实现 ioc_extract.py**

```python
# scripts/ioc_extract.py
"""IOC 提取标准化：从 pcap 提取 IP/域名/URL/哈希/UA/JA3，输出 MISP 格式。"""
import csv, subprocess, sys
from collections import OrderedDict

def _tshark_fields(pcap: str, fields: list[str], display_filter: str = "") -> list[str]:
    cmd = ["tshark", "-r", pcap, "-T", "fields"] + [f"-e {f}" for f in fields]
    if display_filter:
        cmd += ["-Y", display_filter]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]

def extract_iocs(pcap_path: str) -> dict:
    ips = list(OrderedDict.fromkeys(_tshark_fields(pcap_path, ["ip.dst"], "ip.dst")))
    domains = list(OrderedDict.fromkeys(_tshark_fields(pcap_path, ["dns.qry.name"], "dns.flags.response==0")))
    hosts = _tshark_fields(pcap_path, ["http.host"], "http.request")
    uris = _tshark_fields(pcap_path, ["http.request.uri"], "http.request")
    urls = list(OrderedDict.fromkeys(f"{h}{u}" for h, u in zip(hosts, uris) if h and u))
    ja3 = list(OrderedDict.fromkeys(_tshark_fields(pcap_path, ["tls.handshake.ja3"], "tls.handshake.type==1")))
    uas = list(OrderedDict.fromkeys(_tshark_fields(pcap_path, ["http.user_agent"], "http.request")))
    return {"ips": ips, "domains": domains, "urls": urls, "hashes": [], "ja3": ja3, "user_agents": uas}

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
            w.writerow(["ja3-fingerprint", ja3, "Payload delivery"])
        for ua in iocs["user_agents"]:
            w.writerow(["user-agent", ua, "Payload delivery"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ioc_extract.py <pcap> [output.csv]", file=sys.stderr); sys.exit(1)
    import json
    iocs = extract_iocs(sys.argv[1])
    if len(sys.argv) >= 3:
        to_misp_csv(iocs, sys.argv[2])
    else:
        print(json.dumps(iocs, ensure_ascii=False, indent=2))
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_ioc_extract.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: 提交**

```bash
cd traffic-analysis
git add scripts/ioc_extract.py tests/test_ioc_extract.py
git commit -m "feat: add ioc_extract.py IOC standardization with MISP export"
```

---

### Task 7: timeline_builder.py（事件时间线）

**Files:**
- Create: `scripts/timeline_builder.py`
- Test: `tests/test_timeline_builder.py`

**Interfaces:**
- Produces: `build_timeline(pcap_path: str) -> list[dict]` — 按时间排序的事件列表，每项含 `timestamp`, `type`, `src`, `dst`, `detail`, `severity`
- Consumes: tshark 多协议字段 + beacon_detect + entropy_dns 结果

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_timeline_builder.py
import sys; sys.path.insert(0, "scripts")
from timeline_builder import build_timeline

def test_timeline_sorted_by_time(test_pcap):
    events = build_timeline(str(test_pcap))
    assert len(events) >= 3
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)

def test_timeline_contains_dns_and_http(test_pcap):
    events = build_timeline(str(test_pcap))
    types = [e["type"] for e in events]
    assert "dns_query" in types
    assert "http_request" in types
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_timeline_builder.py -v
```
Expected: FAIL

- [ ] **Step 3: 实现 timeline_builder.py**

```python
# scripts/timeline_builder.py
"""事件时间线构建：从多协议字段提取事件并按时间排序。"""
import subprocess, sys
from collections import defaultdict

def _tshark_fields(pcap: str, fields: list[str], display_filter: str = "") -> list[list[str]]:
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=|"] + [f"-e {f}" for f in fields]
    if display_filter:
        cmd += ["-Y", display_filter]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return [l.split("|") for l in r.stdout.strip().splitlines() if l.strip()]

def build_timeline(pcap_path: str) -> list[dict]:
    events = []
    # DNS 事件
    for row in _tshark_fields(pcap_path, ["frame.time", "ip.src", "dns.qry.name"], "dns.flags.response==0"):
        if len(row) >= 3:
            events.append({"timestamp": row[0].strip(), "type": "dns_query",
                "src": row[1].strip(), "dst": "", "detail": f"DNS 查询: {row[2].strip()}", "severity": "info"})
    # HTTP 事件
    for row in _tshark_fields(pcap_path, ["frame.time", "ip.src", "ip.dst", "http.request.method", "http.request.uri"], "http.request"):
        if len(row) >= 5:
            events.append({"timestamp": row[0].strip(), "type": "http_request",
                "src": row[1].strip(), "dst": row[2].strip(),
                "detail": f"HTTP {row[3].strip()} {row[4].strip()}", "severity": "info"})
    # FTP 凭据事件
    for row in _tshark_fields(pcap_path, ["frame.time", "ip.src", "ftp.request.command", "ftp.request.arg"], "ftp.request.command"):
        if len(row) >= 4:
            severity = "high" if row[2].strip().upper() == "PASS" else "medium"
            events.append({"timestamp": row[0].strip(), "type": "ftp_credential",
                "src": row[1].strip(), "dst": "", "detail": f"FTP {row[2].strip()} {row[3].strip()}", "severity": severity})
    events.sort(key=lambda x: x["timestamp"])
    return events

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python timeline_builder.py <pcap>", file=sys.stderr); sys.exit(1)
    import json
    print(json.dumps(build_timeline(sys.argv[1]), ensure_ascii=False, indent=2))
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_timeline_builder.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: 提交**

```bash
cd traffic-analysis
git add scripts/timeline_builder.py tests/test_timeline_builder.py
git commit -m "feat: add timeline_builder.py event timeline construction"
```

---

### Task 8: html_report.py（HTML 可视化报告生成）

**Files:**
- Create: `scripts/html_report.py`
- Create: `templates/html_report.tpl.html`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Produces: `generate_html_report(pcap_path: str, output_path: str, profile: dict = None, timeline: list = None, iocs: dict = None) -> str` — 返回生成的 HTML 文件路径
- Consumes: pcap_profile.py JSON、timeline_builder.py 列表、iocs dict；模板占位符替换

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_html_report.py
import sys; sys.path.insert(0, "scripts")
from html_report import generate_html_report
from pcap_profile import profile
from timeline_builder import build_timeline
from ioc_extract import extract_iocs

def test_generates_html_file(test_pcap, tmp_path):
    out = tmp_path / "report.html"
    p = profile(str(test_pcap))
    tl = build_timeline(str(test_pcap))
    iocs = extract_iocs(str(test_pcap))
    result = generate_html_report(str(test_pcap), str(out), p, tl, iocs)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<html" in content
    assert "185.220.101.42" in content
    assert "</html>" in content
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_html_report.py -v
```
Expected: FAIL

- [ ] **Step 3: 实现 html_report.tpl.html 模板**

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>流量分析报告 - {{PCAP_NAME}}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#f5f5f5;color:#333}
h1{border-bottom:3px solid #2563eb;padding-bottom:10px}
.card{background:#fff;border-radius:8px;padding:20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{padding:8px 12px;border:1px solid #e5e7eb;text-align:left;font-size:14px}
th{background:#f9fafb}
.severity-high{color:#dc2626;font-weight:bold}
.severity-medium{color:#d97706}
.severity-info{color:#2563eb}
.timeline{position:relative;padding-left:24px}
.timeline-item{border-left:2px solid #2563eb;padding:4px 0 4px 16px;position:relative}
.timeline-item::before{content:"";position:absolute;left:-6px;top:10px;width:10px;height:10px;border-radius:50%;background:#2563eb}
.chart-container{position:relative;height:300px}
</style>
</head>
<body>
<h1>流量分析审计报告</h1>
<div class="card"><h2>基本信息</h2>
<table><tr><th>文件</th><td>{{PCAP_NAME}}</td><th>总包数</th><td>{{PACKETS_TOTAL}}</td></tr>
<tr><th>时长</th><td>{{DURATION}}s</td><th>大小类</th><td>{{SIZE_CLASS}}</td></tr>
<tr><th>开始时间</th><td>{{START_TIME}}</td><th>链路类型</th><td>{{LINK_TYPE}}</td></tr></table></div>

<div class="card"><h2>协议分布</h2><div class="chart-container"><canvas id="protoChart"></canvas></div></div>

<div class="grid">
<div class="card"><h2>Top 端点</h2><table><tr><th>IP</th><th>包数</th><th>字节</th></tr>{{ENDPOINTS_ROWS}}</table></div>
<div class="card"><h2>Top 域名</h2><table><tr><th>域名</th><th>次数</th></tr>{{DNS_ROWS}}</table></div>
</div>

<div class="card"><h2>事件时间线</h2><div class="timeline">{{TIMELINE_ITEMS}}</div></div>

<div class="card"><h2>IOC 清单</h2><table><tr><th>类型</th><th>值</th></tr>{{IOC_ROWS}}</table></div>

<script>
const protoCtx=document.getElementById('protoChart').getContext('2d');
new Chart(protoCtx,{type:'doughnut',data:{labels:{{PROTO_LABELS}},datasets:[{data:{{PROTO_DATA}},backgroundColor:['#2563eb','#dc2626','#d97706','#059669','#7c3aed','#0891b2']}]});
</script>
</body>
</html>
```

- [ ] **Step 4: 实现 html_report.py**

```python
# scripts/html_report.py
"""HTML 可视化报告生成：占位符替换，无构建步骤，自包含单文件。"""
import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "html_report.tpl.html"

def _fmt_endpoints(endpoints: list[dict]) -> str:
    return "".join(f"<tr><td>{e['ip']}</td><td>{e['packets']}</td><td>{e.get('bytes','')}</td></tr>" for e in endpoints[:10])

def _fmt_dns(domains: list[dict]) -> str:
    return "".join(f"<tr><td>{d['domain']}</td><td>{d['count']}</td></tr>" for d in domains[:10])

def _fmt_timeline(events: list[dict]) -> str:
    return "".join(
        f'<div class="timeline-item"><span class="severity-{e["severity"]}">[{e["type"]}]</span> '
        f'{e["src"]} → {e["dst"]}: {e["detail"]} <small>({e["timestamp"]})</small></div>'
        for e in events[:50]
    )

def _fmt_iocs(iocs: dict) -> str:
    rows = []
    for ip in iocs.get("ips", []):
        rows.append(f"<tr><td>ip</td><td>{ip}</td></tr>")
    for d in iocs.get("domains", []):
        rows.append(f"<tr><td>domain</td><td>{d}</td></tr>")
    for u in iocs.get("urls", []):
        rows.append(f"<tr><td>url</td><td>{u}</td></tr>")
    return "".join(rows[:100])

def generate_html_report(pcap_path: str, output_path: str, profile: dict = None, timeline: list = None, iocs: dict = None) -> str:
    if profile is None:
        from pcap_profile import profile as _p
        profile = _p(pcap_path)
    if timeline is None:
        from timeline_builder import build_timeline
        timeline = build_timeline(pcap_path)
    if iocs is None:
        from ioc_extract import extract_iocs
        iocs = extract_iocs(pcap_path)
    tpl = TEMPLATE_PATH.read_text(encoding="utf-8")
    phs = profile.get("protocol_hierarchy", [])
    dns = profile.get("dns_summary", {}).get("top_domains", [])
    repl = {
        "{{PCAP_NAME}}": Path(pcap_path).name,
        "{{PACKETS_TOTAL}}": str(profile["capture"]["packets_total"]),
        "{{DURATION}}": str(profile["capture"]["duration_seconds"]),
        "{{SIZE_CLASS}}": profile["size_class"],
        "{{START_TIME}}": profile["capture"]["start_time"],
        "{{LINK_TYPE}}": profile["capture"]["link_type"],
        "{{ENDPOINTS_ROWS}}": _fmt_endpoints(profile.get("endpoints_top", [])),
        "{{DNS_ROWS}}": _fmt_dns(dns),
        "{{TIMELINE_ITEMS}}": _fmt_timeline(timeline),
        "{{IOC_ROWS}}": _fmt_iocs(iocs),
        "{{PROTO_LABELS}}": str([p["protocol"] for p in phs[:6]]).replace("'", '"'),
        "{{PROTO_DATA}}": str([p["packets"] for p in phs[:6]]),
    }
    for k, v in repl.items():
        tpl = tpl.replace(k, v)
    Path(output_path).write_text(tpl, encoding="utf-8")
    return output_path

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python html_report.py <pcap> <output.html>", file=sys.stderr); sys.exit(1)
    generate_html_report(sys.argv[1], sys.argv[2])
    print(f"报告已生成: {sys.argv[2]}")
```

- [ ] **Step 5: 运行测试确认通过**

```bash
cd traffic-analysis && python -m pytest tests/test_html_report.py -v
```
Expected: 1 PASSED

- [ ] **Step 6: 提交**

```bash
cd traffic-analysis
git add scripts/html_report.py templates/html_report.tpl.html tests/test_html_report.py
git commit -m "feat: add html_report.py standalone HTML visualization report"
```

---

### Task 9: 报告模板（3 套场景模板 + MISP 模板）

**Files:**
- Create: `templates/report_ctf.md`
- Create: `templates/report_ir.md`
- Create: `templates/report_attackdef.md`
- Create: `templates/ioc_misp.csv.tpl`

**Interfaces:**
- Produces: 三套 Markdown 报告模板，含占位符 `{{PCAP_NAME}}`、`{{FINDINGS}}`、`{{TIMELINE}}`、`{{IOCS}}`、`{{EVIDENCE}}`
- Produces: MISP CSV 模板（表头行）

- [ ] **Step 1: 编写 report_ctf.md**

```markdown
# CTF 流量取证报告

**题目文件：** {{PCAP_NAME}}
**分析时间：** {{ANALYSIS_TIME}}
**分析员：** {{ANALYST}}

## 一、题目概述

{{OVERVIEW}}

## 二、解题思路

{{APPROACH}}

## 三、关键发现

{{FINDINGS}}

## 四、Flag / 答案

{{FLAG}}

## 五、证据链

| 时间 | 事件 | 证据 |
|------|------|------|
{{EVIDENCE_TABLE}}

## 六、提取文件

| 文件名 | 大小 | SHA-256 |
|--------|------|---------|
{{FILES_TABLE}}

## 七、参考

- 工具：tshark {{TSHARK_VERSION}}
- 分析方法：{{METHOD_NOTES}}
```

- [ ] **Step 2: 编写 report_ir.md**

```markdown
# 应急响应流量分析报告

**事件编号：** {{INCIDENT_ID}}
**PCAP 文件：** {{PCAP_NAME}}
**分析时间：** {{ANALYSIS_TIME}}
**分析员：** {{ANALYST}}
**密级：** {{CLASSIFICATION}}

## 一、事件摘要

{{EXECUTIVE_SUMMARY}}

## 二、攻击时间线

| 时间 (UTC) | 阶段 | 事件 | 源 | 目标 |
|-----------|------|------|-----|------|
{{TIMELINE_TABLE}}

## 三、攻击链还原

{{ATTACK_CHAIN}}

## 四、关键发现

{{FINDINGS}}

## 五、IOC 清单

| 类型 | 值 | 置信度 |
|------|-----|--------|
{{IOC_TABLE}}

## 六、影响评估

{{IMPACT_ASSESSMENT}}

## 七、处置建议

{{RECOMMENDATIONS}}

## 八、证据附件

| 文件名 | SHA-256 | 说明 |
|--------|---------|------|
{{EVIDENCE_TABLE}}
```

- [ ] **Step 3: 编写 report_attackdef.md**

```markdown
# 攻防演练流量复盘报告

**演练名称：** {{EXERCISE_NAME}}
**PCAP 文件：** {{PCAP_NAME}}
**分析时间：** {{ANALYSIS_TIME}}
**红队视角 / 蓝队视角：** {{PERSPECTIVE}}

## 一、演练概述

{{OVERVIEW}}

## 二、流量画像

{{TRAFFIC_PROFILE}}

## 三、攻击路径分析

{{ATTACK_PATH}}

## 四、检测盲区

{{DETECTION_GAPS}}

## 五、关键发现

{{FINDINGS}}

## 六、IOC 清单

| 类型 | 值 | 关联 TTP |
|------|-----|----------|
{{IOC_TABLE}}

## 七、改进建议

{{IMPROVEMENTS}}

## 八、附录：证据

{{EVIDENCE}}
```

- [ ] **Step 4: 编写 ioc_misp.csv.tpl**

```csv
type,value,category,comment
{{MISP_ROWS}}
```

- [ ] **Step 5: 验证模板占位符一致**

```bash
cd traffic-analysis
grep -oE '\{\{[A-Z_]+\}\}' templates/report_ctf.md templates/report_ir.md templates/report_attackdef.md | sort -u
```
Expected: 输出占位符列表，无报错

- [ ] **Step 6: 提交**

```bash
cd traffic-analysis
git add templates/
git commit -m "feat: add 3 scenario report templates + MISP CSV template"
```

---

### Task 10: references 知识库（8 个文档）

**Files:**
- Create: `references/01-pcap-basics.md`
- Create: `references/02-traffic-profiling.md`
- Create: `references/03-protocol-deepdive.md`
- Create: `references/04-attack-detection.md`
- Create: `references/05-ctf-forensics.md`
- Create: `references/06-incident-response.md`
- Create: `references/07-visualization.md`
- Create: `references/08-ids-engines.md`

**Interfaces:**
- Produces: 8 个编号知识库文档，供 SKILL.md 工作流引用

- [ ] **Step 1: 编写 01-pcap-basics.md**

```markdown
# 01 · pcap 基础与规模自适应

## 文件识别（capinfos）

```bash
capinfos -M file.pcap          # 机器可读元信息
capinfos file.pcap              # 人类可读摘要
```

关键字段：Number of packets、Capture duration、File size、Capture type、File comment（截断标记）。

## 规模自适应策略

| 规模 | 条件 | 策略 |
|------|------|------|
| small | <50MB 且 <600s | 全量深析，直接跑全部脚本 |
| medium | <500MB 且 <1h | 先画像 → 过滤可疑流 → 定向深析 |
| large | ≥500MB 或 ≥1h | editcap 时间切片 + 流切割，分批处理 |

## 文件修复与切割

```bash
editcap -F pcap broken.pcap fixed.pcap        # 修复截断
editcap -i 60 large.pcap slice_%03d.pcap      # 按 60s 切片
editcap -A "2026-08-21 10:00:00" -B "2026-08-21 10:05:00" large.pcap segment.pcap
mergecap -w merged.pcap p1.pcap p2.pcap       # 多文件合并
```

## 链路类型

常见：Ethernet、Raw IP、Loopback、Linux SLL。影响 tshark 解析偏移，通常无需手动处理。
```

- [ ] **Step 2: 编写 02-traffic-profiling.md**

```markdown
# 02 · 流量画像与筛查

## 统计命令库（全部 tshark -z，C 实现，快）

```bash
tshark -r f.pcap -q -z io,phs              # 协议层级
tshark -r f.pcap -q -z endpoints,ip         # 端点 Top N
tshark -r f.pcap -q -z conv,tcp            # TCP 会话
tshark -r f.pcap -q -z conv,udp            # UDP 会话
tshark -r f.pcap -q -z dns,tree            # DNS 查询树
tshark -r f.pcap -q -z io,stat,0,"SUM(frame.len)frame.len"  # 时间分布
```

## 筛查假设生成规则

| 观察 | 假设 | 优先级 |
|------|------|--------|
| 443 大流量 + TLS 异常 | C2 信标 | high |
| 53 高熵域名 | DGA / DNS 隧道 | high |
| 单 IP 大量 SYN | 端口扫描 | medium |
| 单端口大量失败登录 | 爆破 | high |
| 出站流量异常大 | 数据外传 | high |
| ICMP payload 非空 | ICMP 隧道 | medium |
| SMB/Kerberos 跨主机 | 横向移动 | high |
```

- [ ] **Step 3: 编写 03-protocol-deepdive.md**

```markdown
# 03 · 协议专项分析

## HTTP

```bash
tshark -r f.pcap -T fields -e http.host -e http.request.uri -e http.request.method -Y "http.request"
tshark -r f.pcap -T fields -e http.host -e http.file_data -Y "http.request.method==POST"
tshark -r f.pcap --export-objects http,http_objects/    # 对象还原
```

webshell 特征：POST 请求含 `eval`、`base64_decode`、`system`、`exec`；响应含系统命令输出。

## DNS

```bash
tshark -r f.pcap -T fields -e dns.qry.name -Y "dns.flags.response==0"
tshark -r f.pcap -T fields -e dns.qry.name -e dns.txt -Y "dns.resp.type==16 and dns.resp.len>100"  # 隧道
```

DGA：子域名熵 >3.5 且长度 >10。隧道：TXT 响应 >100 字节。

## TLS

```bash
tshark -r f.pcap -T fields -e tls.handshake.extensions_server_name -Y "tls.handshake.type==1"  # SNI
tshark -r f.pcap -T fields -e tls.handshake.ja3 -Y "tls.handshake.type==1"                    # JA3
tshark -r f.pcap -T fields -e x509ce.dNSName -e x509af.serialNumber -Y "tls.handshake.type==11"  # 证书
```

异常：自签证书、过期证书、JA3 匹配恶意指纹库。

## SMB / FTP / 邮件 / 数据库 / 远程管理

```bash
tshark -r f.pcap -T fields -e smb.cmd -e smb.path -Y "smb"
tshark -r f.pcap -T fields -e ftp.request.command -e ftp.request.arg -Y "ftp.request.command"
tshark -r f.pcap -T fields -e smtp.req.command -e smtp.req.parameter -Y "smtp"
tshark -r f.pcap -T fields -e mysql.query -Y "mysql"
tshark -r f.pcap -T fields -e tdsp.query -Y "tds"  # MSSQL
```
```

- [ ] **Step 4: 编写 04-attack-detection.md**

```markdown
# 04 · 攻击行为检测

## 扫描检测

```bash
# 单源多目标 SYN → 端口扫描
tshark -r f.pcap -T fields -e ip.src -e tcp.dstport -Y "tcp.flags.syn==1 and tcp.flags.ack==0"
```

判定：单 src 对 >20 个不同 dport 发 SYN。

## 爆破检测

```bash
# SSH/FTP/HTTP 登录失败频率
tshark -r f.pcap -T fields -e frame.time -e ip.src -e ftp.response.code -Y "ftp.response.code==530"
```

判定：单 src 对单 dst >10 次失败/分钟。

## C2 信标

使用 beacon_detect.py：间隔 10s-1h，抖动 <30%。

## 隧道检测

- DNS 隧道：TXT 响应 >100B，高熵子域名
- ICMP 隧道：payload 非标准（非 abcdefghi...）
- HTTP 隧道：固定间隔 POST，UA 异常

## 横向移动

```bash
tshark -r f.pcap -T fields -e ip.src -e ip.dst -e smb.cmd -Y "smb.cmd==0x25"  # SMB Trans
tshark -r f.pcap -T fields -e ip.src -e ip.dst -Y "kerberos"                  # Kerberos
tshark -r f.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport -Y "tcp.dstport==5985 or tcp.dstport==5986"  # WinRM
```

## 数据外传

判定：单 dst 出站流量 > 历史基线 3σ；非业务端口大流量；工作时间外突发。
```

- [ ] **Step 5: 编写 05-ctf-forensics.md**

```markdown
# 05 · CTF 流量取证专项

## 常见题型

| 类型 | 特征 | 解法 |
|------|------|------|
| HTTP 对象还原 | HTTP 含文件下载 | --export-objects http |
| 图片尾部藏数据 | TCP 流末尾附加 | follow tcp stream → 提取 |
| 协议字段隐写 | DNS TXT/ICMP payload | 提取 payload → 解码 |
| Base64/十六进制编码 | HTTP POST/响应体 | 提取 → 解码 |
| 畸形协议 | 非标准端口协议 | 按流分析，逆向协议结构 |
| 明文凭据 | FTP/Telnet/HTTP Basic | 提取 USER/PASS/Authorization |
| USB/键盘流量 | usb.capdata | 解析 HID 码 |

## Flag 搜索

```bash
# 在全部 payload 中搜索 flag 格式
tshark -r f.pcap -T fields -e data.data -Y "data.data" | grep -oE "flag\{[^}]+\}"
tshark -r f.pcap -T fields -e http.file_data | grep -oE "flag\{[^}]+\}"
```

## 文件还原

```bash
tshark -r f.pcap --export-objects http,http/
tshark -r f.pcap --export-objects smb,smb/
tshark -r f.pcap --export-objects tftp,tftp/
# 手动：follow TCP stream → Save As
```

## 编码识别

常见：Base64、Hex、URL 编码、XOR、ROT13、Gzip 压缩。
```

- [ ] **Step 6: 编写 06-incident-response.md**

```markdown
# 06 · 应急响应研判

## 时间线重建

使用 timeline_builder.py 生成事件序列，按攻击阶段归类：

1. 初始访问（钓鱼、漏洞利用）
2. 持久化（后门、计划任务）
3. C2 通信（信标、命令下发）
4. 横向移动（SMB、RDP、PsExec）
5. 数据外传（大流量出站）

## 攻击链还原模板

```
[初始访问] → [执行] → [持久化] → [C2] → [横向] → [外传]
```

## IOC 提取清单

- IP（恶意 C2、扫描源）
- 域名（DGA、C2）
- URL（payload 下载、webshell）
- 哈希（恶意文件 SHA-256）
- JA3（TLS 指纹）
- UA（恶意工具特征）

## ATT&CK 映射

| 行为 | TTP |
|------|-----|
| C2 信标 | T1071.001 |
| 数据外传 | T1041 |
| 隧道 | T1572 |
| 横向移动 | T1021 |
| 持久化 | T1053 |

## 误报排除

- CDN IP（Cloudflare、Akamai）
- 云厂商 IP（AWS、Azure、阿里云）
- 正常 TLS 指纹（浏览器 JA3）
- 业务正常流量基线
```

- [ ] **Step 7: 编写 07-visualization.md**

```markdown
# 07 · HTML 可视化报告规范

## 报告结构

1. 基本信息卡（文件/包数/时长/规模）
2. 协议分布环形图（Chart.js doughnut）
3. Top 端点表
4. Top 域名表
5. 事件时间线（纵向时间轴）
6. IOC 清单表

## 图表类型

| 数据 | 图表 |
|------|------|
| 协议分布 | 环形图 doughnut |
| 时间趋势 | 折线图 line |
| 端点 Top N | 表格 |
| 会话关系 | 桑基图 sankey（可选） |

## 生成方式

html_report.py 读取 html_report.tpl.html 模板，占位符替换，无构建步骤。Chart.js 通过 CDN 加载（离线时图表不显示，但表格数据仍完整）。

## 降级策略

- CDN 不可达：图表不渲染，表格数据完整
- 模板缺失：回退到 Markdown 报告
- 全部失败：至少输出 IOC JSON
```

- [ ] **Step 8: 编写 08-ids-engines.md**

```markdown
# 08 · Zeek / Suricata 可选增强

## 启用检测

```bash
command -v zeek >/dev/null 2>&1 && echo "zeek available" || echo "zeek not found"
command -v suricata >/dev/null 2>&1 && echo "suricata available" || echo "suricata not found"
```

## Zeek 使用

```bash
zeek -r f.pcap    # 生成 conn.log/dns.log/http.log/ssl.log/files.log
```

关键日志：conn.log（连接元数据）、http.log（HTTP 详情）、ssl.log（TLS 详情）、files.log（文件提取）。

## Suricata 使用

```bash
suricata -r f.pcap -l suricata_out/ -c /etc/suricata/suricata.yaml
cat suricata_out/fast.log    # 告警
```

## 降级策略

未安装时，以下检测用 tshark 规则化实现：

| IDS 检测 | tshark 降级 |
|----------|-------------|
| 端口扫描 | SYN 计数阈值 |
| 恶意域名 | 熵分析 + 威胁情报 |
| C2 信标 | beacon_detect.py |
| 漏洞利用 | HTTP URI 特征匹配 |

报告标注："IDS 引擎未启用，部分检测基于 tshark 规则化实现"。
```

- [ ] **Step 9: 验证 8 个文档均存在且非空**

```bash
cd traffic-analysis
for f in references/*.md; do echo "$f: $(wc -l < $f) lines"; done
```
Expected: 8 个文件，每个 >5 行

- [ ] **Step 10: 提交**

```bash
cd traffic-analysis
git add references/
git commit -m "feat: add 8 reference knowledge base documents"
```

---

### Task 11: SKILL.md（主入口）

**Files:**
- Create: `SKILL.md`

**Interfaces:**
- Produces: skill 主入口，含触发关键词、场景路由、阶段式工作流、工具调度指令

- [ ] **Step 1: 编写 SKILL.md**

```markdown
---
name: traffic-analysis
description: 专业流量分析审计 skill，对 pcap 流量包进行全类型分析（识别→画像→筛查→研判→输出）。覆盖安全攻防复盘、应急响应、CTF 流量取证三大场景。输出 Markdown 报告 + HTML 可视化报告 + MISP 格式 IOC 清单。触发关键词：流量分析、pcap 分析、流量取证、CTF 流量、应急响应流量、网络取证、packet capture、traffic audit、pcap forensics、流量研判。
---

# 流量分析审计

## 何时使用

- 分析 pcap/pcapng 流量包，提取攻击行为、C2 通信、数据外传等
- CTF 流量取证题解题（文件还原、隐藏数据、flag 定位）
- 应急响应中的网络行为研判与 IOC 提取
- 攻防演练流量复盘

**不适用：** 实时抓包监听（本 skill 仅分析已有 pcap 文件）、TLS 无密钥解密。

## 前置条件

- Wireshark 套件（tshark/capinfos/editcap/mergecap）—— 必装
- Python 3.8+（标准库即可，scapy/pyshark 可选增强）
- Zeek / Suricata —— 可选，未装自动降级

## 工作流（阶段式，每阶段结束请分析师确认）

### 阶段 0 · 识别

```bash
capinfos -M {{PCAP_PATH}}
```

1. 读取元信息（包数/时长/大小/链路类型/是否截断）
2. 规模定级：small（<50MB,<600s）/ medium / large（≥500MB 或 ≥1h）
3. 初步场景判定

**汇报：** 文件画像 + 规模策略 + 场景初判，请分析师确认方向。

### 阶段 1 · 画像

```bash
python scripts/pcap_profile.py {{PCAP_PATH}} > profile.json
```

1. 读取 profile.json
2. 列出协议层级、Top 端点、Top 域名、可疑假设

**汇报：** 画像结果 + 可疑点排序，请分析师选择筛查优先级。

### 阶段 2 · 筛查（按假设定向深挖，可多轮）

按分析师选择的优先级，依次执行：

```bash
# 信标检测
python scripts/beacon_detect.py {{PCAP_PATH}}
# DNS 熵分析
python scripts/entropy_dns.py {{PCAP_PATH}}
# 对象提取
python scripts/extract_files.py {{PCAP_PATH}} extracted/
# 协议专项（按需）
tshark -r {{PCAP_PATH}} -T fields -e http.host -e http.request.uri -Y "http.request"
tshark -r {{PCAP_PATH}} -T fields -e tls.handshake.ja3 -Y "tls.handshake.type==1"
```

Zeek/Suricata 若可用则交叉验证。

**汇报：** 每条假设给"证实/排除/存疑"结论。

### 阶段 3 · 研判

```bash
python scripts/timeline_builder.py {{PCAP_PATH}} > timeline.json
python scripts/ioc_extract.py {{PCAP_PATH}} iocs.csv
```

1. 时间线重建 → 攻击链还原
2. IOC 标准化（MISP 格式）
3. ATT&CK 映射
4. 误报排除

**汇报：** 研判结论 + 证据链，请分析师确认。

### 阶段 4 · 输出

```bash
python scripts/html_report.py {{PCAP_PATH}} report.html
```

1. Markdown 报告（按场景选模板：templates/report_ctf.md / report_ir.md / report_attackdef.md）
2. HTML 可视化报告（report.html，浏览器直接打开）
3. IOC 清单（iocs.csv，MISP 格式）
4. 提取文件证据清单

## 场景路由

| 场景 | 重心 | 报告模板 |
|------|------|----------|
| CTF 取证 | 文件还原、隐藏数据、flag 定位 | report_ctf.md |
| 应急响应 | 时效、IOC、溯源链 | report_ir.md |
| 攻防演练 | 攻击路径复盘、检测盲区 | report_attackdef.md |

## 规模自适应

| 规模 | 策略 |
|------|------|
| small | 全量深析 |
| medium | 画像 → 过滤 → 定向深析 |
| large | editcap 切片 + 流切割，分批处理 |

## 错误处理

- pcap 损坏：editcap 修复或跳过
- Zeek/Suricata 未装：自动降级，报告标注
- Python 依赖缺失：核心功能不依赖 scapy/pyshark
- 中文乱码：强制 UTF-8，tshark 用 -T fields
- 报告生成失败：HTML 模板纯占位符替换，最坏只剩 MD

## 知识库

- [01-pcap-basics.md](references/01-pcap-basics.md) — 文件识别、切割、规模自适应
- [02-traffic-profiling.md](references/02-traffic-profiling.md) — 画像统计与筛查
- [03-protocol-deepdive.md](references/03-protocol-deepdive.md) — 协议专项
- [04-attack-detection.md](references/04-attack-detection.md) — 攻击行为检测
- [05-ctf-forensics.md](references/05-ctf-forensics.md) — CTF 专项
- [06-incident-response.md](references/06-incident-response.md) — 研判与溯源
- [07-visualization.md](references/07-visualization.md) — HTML 可视化规范
- [08-ids-engines.md](references/08-ids-engines.md) — Zeek/Suricata 可选增强
```

- [ ] **Step 2: 验证 SKILL.md 存在且含触发关键词**

```bash
cd traffic-analysis
grep -c "流量分析\|pcap\|CTF\|应急响应" SKILL.md
```
Expected: >5

- [ ] **Step 3: 提交**

```bash
cd traffic-analysis
git add SKILL.md
git commit -m "feat: add SKILL.md main entry with phased workflow"
```

---

### Task 12: 案例走查与端到端测试

**Files:**
- Create: `examples/ctf-http-flag-walkthrough.md`
- Create: `tests/test_integration.py`

**Interfaces:**
- Produces: CTF HTTP 题完整走查文档（使用范例 + 冒烟测试）
- Produces: 端到端测试（全要素测试包跑全部脚本）

- [ ] **Step 1: 编写失败测试**

```python
# tests/test_integration.py
import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from pcap_profile import profile
from beacon_detect import detect_beacons
from entropy_dns import analyze_dns_entropy
from extract_files import extract_objects
from ioc_extract import extract_iocs
from timeline_builder import build_timeline
from html_report import generate_html_report

def test_full_pipeline(test_pcap, tmp_path):
    """端到端：全要素测试包跑全部脚本，验证数据流贯通。"""
    p = profile(str(test_pcap))
    assert p["capture"]["packets_total"] > 0
    assert p["size_class"] in ("small", "medium", "large")

    beacons = detect_beacons(str(test_pcap))
    assert len(beacons) >= 1

    dns = analyze_dns_entropy(str(test_pcap))
    assert len(dns) >= 1

    files = extract_objects(str(test_pcap), str(tmp_path / "extracted"))
    assert len(files) >= 1

    iocs = extract_iocs(str(test_pcap))
    assert len(iocs["ips"]) > 0

    timeline = build_timeline(str(test_pcap))
    assert len(timeline) >= 3

    html_path = tmp_path / "report.html"
    generate_html_report(str(test_pcap), str(html_path), p, timeline, iocs)
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")
    assert "185.220.101.42" in content
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd traffic-analysis && python -m pytest tests/test_integration.py -v
```
Expected: FAIL（依赖前面任务）

- [ ] **Step 3: 确认测试通过（前置任务完成后）**

```bash
cd traffic-analysis && python -m pytest tests/ -v
```
Expected: 全部 PASSED

- [ ] **Step 4: 编写 examples/ctf-http-flag-walkthrough.md**

```markdown
# CTF HTTP 流量取证案例走查

## 题目

给定 `http_flag.pcap`，找出隐藏的 flag。

## 解题过程

### 阶段 0 · 识别

```bash
capinfos -M http_flag.pcap
# Number of packets: 42
# Capture duration: 5.2s
# → small，全量深析
```

### 阶段 1 · 画像

```bash
python scripts/pcap_profile.py http_flag.pcap
# 协议：TCP 95%，HTTP 80%
# 可疑：单 IP 多 HTTP 请求
```

### 阶段 2 · 筛查

```bash
tshark -r http_flag.pcap -T fields -e http.request.uri -Y "http.request"
# /index.html
# /secret.txt   ← 可疑
# /logo.png

tshark -r http_flag.pcap --export-objects http,http/
# 提取 secret.txt → 内容：FLAG{h1dd3n_in_http}
```

### 答案

`FLAG{h1dd3n_in_http}`

## 关键命令

- `tshark -T fields -e http.request.uri -Y "http.request"` — 列出所有请求
- `tshark --export-objects http,dir/` — 还原 HTTP 对象
```

- [ ] **Step 5: 全量测试**

```bash
cd traffic-analysis && python -m pytest tests/ -v --tb=short
```
Expected: 全部 PASSED

- [ ] **Step 6: 提交**

```bash
cd traffic-analysis
git add examples/ tests/test_integration.py
git commit -m "feat: add CTF walkthrough example and end-to-end integration test"
```

---

## Self-Review Checklist

**Spec coverage:**
- 三场景全覆盖 → SKILL.md 场景路由 + 3 套报告模板 ✓
- 阶段式工作流 → SKILL.md 5 阶段 + Task 11 ✓
- 规模自适应 → references/01 + SKILL.md + Task 1 ✓
- tshark 核心 + Zeek/Suricata 可选 → references/08 + SKILL.md ✓
- MD 报告 + HTML 可视化 → templates/ + html_report.py ✓
- 7 个脚本 → Tasks 2-8 ✓
- 8 个 references → Task 10 ✓
- 错误处理 → SKILL.md + 各脚本 ✓
- 测试 → Tasks 1-12 每任务 TDD + Task 12 端到端 ✓

**Placeholder scan:** 无 TBD/TODO，所有步骤含实际代码 ✓

**Type consistency:**
- `profile() -> dict` 契约在 Task 2 定义，Task 8 消费 ✓
- `detect_beacons() -> list[dict]` Task 3 ✓
- `extract_iocs() -> dict` Task 6，`to_misp_csv()` 签名一致 ✓
- 模板占位符 `{{PCAP_NAME}}` 等在 Task 9 定义、Task 8 使用 ✓
