---
name: liuliang-audit
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
- Python 3.9+（标准库即可，scapy/pyshark 可选增强；脚本使用了 list[str] 内置泛型注解，3.8 需 __future__ 导入）
- Zeek / Suricata —— 可选，未装自动降级

## 工作流（阶段式，每阶段结束请分析师确认）

### 阶段 0 · 识别

```bash
capinfos -M {{PCAP_PATH}}
```

1. 读取元信息（包数/时长/大小/链路类型/是否截断）
2. 规模定级（由 `pcap_profile.py` 按 File size + Capture duration 自动判定）：small（<50MB 且 <600s）/ medium（<500MB 且 <1h）/ large（≥500MB 或 ≥1h）
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

#### 报告模板与占位符填充（必读）

**Markdown 模板**（手工填充，占位符名称以模板内实际文本为准）：

- `templates/report_ctf.md`（CTF 取证）：
  `{{PCAP_NAME}}`、`{{ANALYSIS_TIME}}`、`{{ANALYST}}`、`{{OVERVIEW}}`、`{{APPROACH}}`、`{{FINDINGS}}`、`{{FLAG}}`、`{{EVIDENCE_TABLE}}`、`{{FILES_TABLE}}`、`{{TSHARK_VERSION}}`、`{{METHOD_NOTES}}`
- `templates/report_ir.md`（应急响应）：
  `{{INCIDENT_ID}}`、`{{PCAP_NAME}}`、`{{ANALYSIS_TIME}}`、`{{ANALYST}}`、`{{CLASSIFICATION}}`、`{{EXECUTIVE_SUMMARY}}`、`{{TIMELINE_TABLE}}`、`{{ATTACK_CHAIN}}`、`{{FINDINGS}}`、`{{IOC_TABLE}}`、`{{IMPACT_ASSESSMENT}}`、`{{RECOMMENDATIONS}}`、`{{EVIDENCE_TABLE}}`
- `templates/report_attackdef.md`（攻防演练）：
  `{{EXERCISE_NAME}}`、`{{PCAP_NAME}}`、`{{ANALYSIS_TIME}}`、`{{PERSPECTIVE}}`、`{{OVERVIEW}}`、`{{TRAFFIC_PROFILE}}`、`{{ATTACK_PATH}}`、`{{DETECTION_GAPS}}`、`{{FINDINGS}}`、`{{IOC_TABLE}}`、`{{IMPROVEMENTS}}`、`{{EVIDENCE}}`

注意：

- 时间线/IOC 表格占位符的实际名称是 `{{TIMELINE_TABLE}}` 与 `{{IOC_TABLE}}`（模板中不存在 `{{TIMELINE}}`/`{{IOCS}}` 这类简写，填充时务必使用 `_TABLE` 后缀的实际名称）。
- 证据占位符按模板区分：report_ctf.md 与 report_ir.md 使用 `{{EVIDENCE_TABLE}}`（表格形式），report_attackdef.md 使用 `{{EVIDENCE}}`（附录自由文本），两者并存，按所选模板填写对应名称。

**MISP CSV**：

- 脚本 `python scripts/ioc_extract.py {{PCAP_PATH}} iocs.csv` 直接生成 3 列（type,value,category）MISP 最小集。
- `templates/ioc_misp.csv.tpl` 供人工整理/富化时参照：表头为 `type,value,category,comment`（4 列），行占位符为 `{{MISP_ROWS}}`。第 4 列 `comment` 是**可选的人工富化列**——分析师手工填表时可逐行补充注释；直接使用脚本输出时该列不存在，无需补齐。

**HTML 报告**：

- `templates/html_report.tpl.html` 的全部占位符由 `python scripts/html_report.py {{PCAP_PATH}} report.html` 自动填充并做 HTML 转义，无需手动替换。

## 场景路由

| 场景 | 重心 | 报告模板 |
|------|------|----------|
| CTF 取证 | 文件还原、隐藏数据、flag 定位 | report_ctf.md |
| 应急响应 | 时效、IOC、溯源链 | report_ir.md |
| 攻防演练 | 攻击路径复盘、检测盲区 | report_attackdef.md |

## 规模自适应

| 规模 | 判定条件 | 策略 |
|------|----------|------|
| small | <50MB 且 <600s | 全量深析 |
| medium | <500MB 且 <1h | 画像 → 过滤 → 定向深析 |
| large | ≥500MB 或 ≥1h | editcap 切片 + 流切割，分批处理 |

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
