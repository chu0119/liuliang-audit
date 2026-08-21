# 更新日志

本项目的所有重要变更都记录在本文件中。
格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-08-22

### Added

- 阶段式分析工作流：识别 → 画像 → 筛查 → 研判 → 输出，每阶段人工节点确认方向
- 场景路由：CTF 流量取证 / 应急响应 / 攻防演练复盘三套报告模板
- 核心脚本 `pcap_profile.py`：capinfos + tshark -z 一键画像，输出标准化 JSON 契约（含 DGA 假设自动生成）
- `beacon_detect.py`：C2 信标检测（SYN 分组 + 间隔抖动统计）
- `entropy_dns.py`：DNS 子域名熵分析 / DGA 检测
- `extract_files.py`：HTTP/SMB/TFTP 对象提取 + SHA-256 固定（含陈旧目录清理、协议名注入防护）
- `ioc_extract.py`：IOC 提取标准化（IP/域名/URL/JA3/UA）+ MISP CSV 导出
- `timeline_builder.py`：多协议事件时间线（按 epoch 数值排序）
- `html_report.py`：自包含单文件 HTML 可视化报告（协议环形图 / 事件时间线 / IOC 表 / 截断提示），Chart.js 带 SRI 完整性校验，pcap 派生值全量 HTML 转义
- 规模自适应：<50MB 全量深析 / <500MB 画像后过滤 / ≥500MB 时间切片分批
- Zeek / Suricata 可选增强：已装启用 IDS 特征检测，未装自动降级 tshark 规则化检测并在报告标注
- 8 个知识库文档：pcap 基础 / 流量画像 / 协议深挖 / 攻击检测 / CTF 取证 / 应急研判 / 可视化规范 / IDS 引擎
- 测试套件：71 个测试（单元 + 真实 tshark 集成 + 端到端全流程），GitHub Actions CI

### Security

- 所有 tshark/capinfos 子进程失败立即 RuntimeError（含 stderr 摘要），杜绝静默空结果
- pcap 派生字符串全部 HTML 转义后进入报告（文件名在 CTF 场景属攻击者可控面）
- 协议名参数白名单校验，阻断路径穿越
- 全链路强制 UTF-8（含 GBK 控制台管道下的 stdout reconfigure）
