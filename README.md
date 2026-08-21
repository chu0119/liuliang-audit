# liuliang-audit — 专业流量分析审计 Skill

面向专业安全人士的 Claude Code skill：对 pcap 流量包进行**全类型分析**（识别 → 画像 → 筛查 → 研判 → 输出），覆盖**安全攻防、应急响应、CTF 取证**三大场景，最终产出 Markdown 报告 + 自包含 HTML 可视化报告 + MISP 格式 IOC 清单。

## 场景覆盖

| 场景 | 重心 | 报告模板 |
|------|------|----------|
| **CTF 流量取证** | 文件还原、隐藏数据、flag 定位、畸形协议 | `report_ctf.md` |
| **应急响应** | 时效、恶意行为检测、IOC 提取、溯源链还原 | `report_ir.md` |
| **攻防演练复盘** | 攻击路径分析、检测盲区、TTP 关联 | `report_attackdef.md` |

## 六层能力

```
输入处理 ──── 文件识别（capinfos）/ 合并切割（mergecap/editcap）/ 损坏包修复 / 规模自适应
流量画像 ──── 协议层级 / 端点 Top N / 会话统计 / 端口分布 / 时间突发（全部 tshark -z C 实现）
深度检测 ──── 协议专项（HTTP/DNS/TLS/SMB/FTP/邮件/数据库/远程管理）
              攻击行为（扫描/爆破/webshell/C2 信标/隧道/横向移动/数据外传）
              文件提取+SHA-256 / 明文凭据提取 / CTF 专项 / Zeek·Suricata 可选增强
研判关联 ──── 时间线重建 / 攻击链还原 / IOC 标准化（MISP）/ ATT&CK 映射 / 误报排除
输出交付 ──── 三套场景报告模板 + HTML 可视化（协议环形图/时间线/IOC 表）+ MISP CSV
交互编排 ──── 阶段式人工节点：每阶段汇报发现、列下一步选项、分析师拍板方向
```

## 快速开始

### 前置条件

- **必装**：Wireshark 套件（`tshark`/`capinfos`/`editcap`/`mergecap`）— [wireshark.org](https://www.wireshark.org/)
- **Python 3.9+**（核心功能仅标准库；`scapy`/`pyshark` 可选增强，缺失不阻塞）
- **可选**：Zeek / Suricata — 已安装则启用 IDS 特征检测，未装自动降级为 tshark 规则化检测

### 安装

```bash
# 克隆并安装为 Claude Code 个人技能
git clone https://github.com/chu0119/liuliang-audit.git
cp -r liuliang-audit ~/.claude/skills/liuliang-audit
```

之后对 Claude 说"分析这个 pcap"或"CTF 流量取证"即可触发。

### 使用

```
分析 D:\case\incident.pcap，应急响应场景
```

Skill 按五阶段工作流执行，每阶段结束汇报发现并等待你确认方向：

```
阶段 0 识别 → capinfos 元信息 / 规模定级 / 场景初判     → 你确认方向
阶段 1 画像 → 协议/端点/会话统计 → 生成筛查假设清单      → 你选优先级
阶段 2 筛查 → 信标检测/DGA/对象提取/协议深挖（多轮循环） → 每条假设给结论
阶段 3 研判 → 时间线重建/攻击链/IOC/ATT&CK 映射/误报排除 → 你确认结论
阶段 4 输出 → MD 报告 + HTML 可视化 + MISP IOC 清单
```

## 目录结构

```
liuliang-audit/
├── SKILL.md                  # 主入口：触发词 + 场景路由 + 阶段式工作流
├── references/               # 8 个知识库（协议要点/检测规则/CTF 模式/研判方法…）
├── scripts/                  # 7 个确定性分析脚本（独立可运行，标准库 + tshark）
│   ├── pcap_profile.py       #   一键画像 → 标准化 JSON（核心契约）
│   ├── beacon_detect.py      #   C2 信标检测（间隔 + 抖动统计）
│   ├── entropy_dns.py        #   DNS 熵分析 / DGA 检测
│   ├── extract_files.py      #   对象提取 + SHA-256（HTTP/SMB/TFTP）
│   ├── ioc_extract.py        #   IOC 提取标准化（MISP CSV/JSON）
│   ├── timeline_builder.py   #   事件时间线构建
│   └── html_report.py        #   自包含 HTML 可视化报告生成
├── templates/                # 3 套场景报告模板 + MISP CSV + HTML 模板
└── examples/                 # CTF HTTP 题完整走查（使用范例）
```

## 设计要点

- **性能红线**：所有统计走 tshark C 实现，Python 仅做聚合；禁止全量载入内存，GB 级包强制切片/流切割
- **规模自适应**：<50MB 全量深析 / 50MB-500MB 画像后过滤 / ≥500MB 时间切片分批
- **大声失败**：tshark/capinfos 失败立即 RuntimeError（含 stderr 摘要），绝不静默返回空结果——下游不会把"工具故障"误读为"无数据"
- **报告降级**：HTML 模板纯占位符替换无构建步骤，CDN 不可达时表格数据仍完整，最坏只剩 MD 报告仍可交付
- **安全加固**：pcap 派生值全部 HTML 转义（文件名在 CTF 场景是攻击者可控的）；Chart.js 带 SRI 完整性校验
- **Windows 友好**：全链路强制 UTF-8（含 GBK 控制台管道下的 stdout reconfigure）

## 测试

```bash
cd liuliang-audit
python -m pytest tests/ -v    # 71 个测试：单测 + 真实 tshark 集成 + 端到端全流程
```

测试数据集由 scapy 构造（HTTP 下载 + 高熵 DNS + 周期信标 + ICMP 隧道 + 明文 FTP 凭据），端到端测试验证七脚本全链路数据贯通。

## 文档

- 设计规格：[docs/superpowers/specs/2026-08-21-traffic-analysis-skill-design.md](docs/superpowers/specs/2026-08-21-traffic-analysis-skill-design.md)
- 实施计划：[docs/superpowers/plans/2026-08-22-traffic-analysis.md](docs/superpowers/plans/2026-08-22-traffic-analysis.md)

## License

MIT
