# traffic-analysis Skill 发布信息

## 基本信息 (必填)

**Skill 名称**：traffic-analysis

**版本号**：1.0.0

**简介\***：

专业流量分析审计 Skill。对 pcap/pcapng 流量包进行全类型分析（识别→画像→筛查→研判→输出），覆盖安全攻防复盘、应急响应、CTF 流量取证三大场景。

内置 7 个确定性分析脚本（流量画像 / C2 信标检测 / DNS 熵与 DGA 识别 / 对象提取+SHA-256 取证 / IOC 标准化 / 事件时间线 / HTML 可视化报告）+ 8 个协议与检测知识库 + 3 套场景报告模板。

基于 tshark C 实现做统计（GB 级大包切片处理不爆内存），输出 Markdown 报告、自包含 HTML 可视化报告（协议环形图/事件时间线/IOC 表）及 MISP 格式 IOC 清单，支持 ATT&CK 映射与误报排除。阶段式人工节点交互，每阶段汇报发现、分析师拍板方向。

## 场景分类 (支持多选)\*

- ✅ 报告编写
- ✅ 告警研判
- ✅ 威胁溯源
- ✅ 样本分析（流量中恶意样本文件提取与哈希固定）
- ✅ 数据处理（pcap 切片/合并/统计画像）
- ✅ 实用工具

## 使用方法

### 触发词示例

> "分析这个 pcap 流量包，应急响应场景"
>
> "CTF 流量取证：这个包里藏着 flag，帮我找出来"
>
> "对这个 pcap 做威胁研判，提取 IOC 并还原攻击时间线"
>
> "攻防演练复盘：分析这次演练的流量包，找检测盲区"

内置触发关键词：流量分析、pcap 分析、流量取证、CTF 流量、应急响应流量、网络取证、packet capture、traffic audit、pcap forensics、流量研判

## 联动平台

- **claude**（Claude Code / Claude Desktop — 本 Skill 原生运行环境）
- 可扩展：微步X情报中心、FOFA、VirusTotal（对提取出的 IOC 做情报富度查询——当前版本未内置 API 联动，IOC 以 MISP CSV 输出可直接导入上述平台）

## 运行依赖

### 操作系统要求

- ✅ Windows
- ✅ macOS/Linux

### 依赖软件包

| 依赖 | 必要性 | 说明 |
|------|--------|------|
| Wireshark 套件（tshark/capinfos/editcap/mergecap） | **必装** | 核心分析引擎，[wireshark.org](https://www.wireshark.org/) |
| Python 3.9+ | 必装 | 分析脚本仅用标准库 |
| scapy / pyshark | 可选 | 测试数据构造与增强解析，缺失不阻塞 |
| Zeek / Suricata | 可选 | 已装启用 IDS 特征检测；未装自动降级 tshark 规则化检测 |

## 附：交付物清单

| 文件/目录 | 说明 |
|-----------|------|
| `traffic-analysis-v1.0.0.zip` | 技能压缩包（22 文件），解压到 `~/.claude/skills/` 即用 |
| `traffic-analysis/SKILL.md` | 主入口：触发词 + 场景路由 + 五阶段工作流 |
| `traffic-analysis/scripts/` ×7 | pcap_profile / beacon_detect / entropy_dns / extract_files / ioc_extract / timeline_builder / html_report |
| `traffic-analysis/references/` ×8 | pcap 基础 / 流量画像 / 协议深挖 / 攻击检测 / CTF 取证 / 应急研判 / 可视化规范 / IDS 引擎 |
| `traffic-analysis/templates/` ×5 | CTF / 应急响应 / 攻防复盘报告模板 + MISP CSV + HTML 模板 |
| `traffic-analysis/examples/` | CTF HTTP 题完整走查范例 |

开源地址：<https://github.com/chu0119/traffic-analysis>（License: MIT）
