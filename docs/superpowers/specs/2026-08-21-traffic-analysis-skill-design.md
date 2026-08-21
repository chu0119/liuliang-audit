# traffic-analysis Skill 设计文档

日期：2026-08-21
状态：已确认（用户逐节批准）

## 1. 背景与目标

为专业安全人士制作一个流量分析审计 Claude Code skill，覆盖三大场景：

- **安全攻防**：攻击路径复盘、可疑流量筛查
- **应急响应**：恶意行为检测、IOC 提取、溯源链还原（重时效）
- **CTF 比赛**：pcap 取证题（文件还原、隐藏数据、flag 定位，重取证深度）

目标：对 pcap 流量包进行全类型分析（清晰、筛查、研判），最终输出 Markdown 报告 + HTML 可视化报告 + 标准化 IOC 清单。

## 2. 环境约束（本机实测）

| 组件 | 状态 |
|---|---|
| Wireshark 套件（tshark/wireshark/capinfos/editcap/mergecap） | ✅ 已装（核心依赖） |
| Python 3.12（scapy 2.7 / pyshark / matplotlib） | ✅ 已装 |
| Zeek / Suricata | ❌ 未装（设计为可选增强） |
| 平台 | Windows 11 |

## 3. 已确认的决策

1. **场景**：三场景通用全覆盖，按阶段编排，各阶段提供不同深度选项
2. **输出**：Markdown 报告 + 自包含 HTML 可视化报告（内嵌图表/时间线/拓扑）
3. **检测引擎**：tshark 为必装核心；Zeek/Suricata 可选，探测到已装则启用，未装自动降级到 tshark 规则化检测
4. **规模**：内置规模自适应（<50MB 全量 / 50MB-1GB 画像后过滤 / >1GB 时间切片+流切割）
5. **交互**：阶段式人工节点——每阶段汇报发现、列下一步选项、分析师拍板
6. **实现方案**：A 方案——SKILL.md 工作流 + scripts/ 确定性脚本库（非 MCP、非纯提示词）

## 4. 能力矩阵（六层）

| 层 | 能力 | 支撑文件 |
|---|---|---|
| 输入处理 | 文件识别（capinfos）、合并/切割（mergecap/editcap）、损坏包处理、规模自适应 | references/01 |
| 流量画像 | 协议层级、端点 Top N、会话统计、端口分布、时间突发（全部 tshark -z C 实现） | references/02 |
| 深度检测 | 协议专项（HTTP/DNS/TLS/SMB/FTP/邮件/数据库/远程管理）、攻击行为（扫描/爆破/webshell/C2 信标/隧道/横向/外传）、文件提取+哈希、明文凭据提取、CTF 专项（文件还原/隐藏数据/flag 定位）、Zeek/Suricata 可选增强 | references/03-05, 08 |
| 研判关联 | 时间线重建、攻击链还原、IOC 标准化（MISP）、ATT&CK 映射、误报排除 | references/06 |
| 输出 | 三套场景报告模板 + HTML 可视化报告 + IOC 清单 | templates/ + scripts/html_report.py |
| 交互 | 阶段式人工节点（识别→画像→筛查→研判→输出） | SKILL.md |

## 5. 目录结构

```
traffic-analysis/
├── SKILL.md                    # 主入口：触发词 + 场景路由 + 阶段式工作流
├── references/
│   ├── 01-pcap-basics.md       # 文件识别、切割合并、规模自适应策略
│   ├── 02-traffic-profiling.md # 画像统计与筛查命令库
│   ├── 03-protocol-deepdive.md # 协议专项分析要点
│   ├── 04-attack-detection.md  # 攻击行为检测（扫描/爆破/webshell/信标/隧道/横向/外传）
│   ├── 05-ctf-forensics.md     # CTF 专项：文件还原/隐藏数据/flag 定位/畸形协议
│   ├── 06-incident-response.md # 时间线重建/攻击链/IOC 提取/溯源
│   ├── 07-visualization.md     # HTML 可视化报告设计规范
│   └── 08-ids-engines.md       # Zeek/Suricata 可选增强 + 降级策略
├── scripts/
│   ├── pcap_profile.py         # 一键画像 → JSON（封装 capinfos + tshark -z）
│   ├── beacon_detect.py        # C2 信标检测（间隔+抖动+包长统计）
│   ├── entropy_dns.py          # DNS 熵分析 / DGA 检测
│   ├── ioc_extract.py          # IOC 提取标准化（MISP CSV/JSON）
│   ├── extract_files.py        # 对象提取封装 + SHA-256
│   ├── timeline_builder.py     # 事件时间线构建
│   └── html_report.py          # 自包含 HTML 可视化报告生成
├── templates/
│   ├── report_ctf.md           # CTF 题解报告模板
│   ├── report_ir.md            # 应急响应报告模板
│   ├── report_attackdef.md     # 攻防演练复盘报告模板
│   ├── ioc_misp.csv.tpl        # MISP 格式 IOC 模板
│   └── html_report.tpl.html    # HTML 可视化模板（占位符替换，无构建步骤）
└── examples/
    └── ctf-http-flag-walkthrough.md  # 案例走查（冒烟测试 + 使用范例）
```

## 6. 阶段式工作流

```
阶段 0 · 识别
  ├─ capinfos 元信息（大小/时长/包数/链路类型/是否截断）
  ├─ 规模定级 → 决定深析策略（全量/过滤/切片）
  └─ 初步场景判定（扫描流量→攻防，明文登录+下载→应急，隐藏数据→CTF）
      ↓ 汇报：文件画像 + 规模策略 + 场景初判，确认方向

阶段 1 · 画像
  ├─ 协议层级 / 端点 Top N / 会话统计 / 端口分布 / 时间突发
  └─ 产出"筛查假设清单"（例：443 大流量+TLS 异常→疑似 C2；53 高熵域名→DGA）
      ↓ 汇报：画像结果 + 可疑点排序，选择筛查优先级

阶段 2 · 筛查（按假设定向深挖，可多轮循环）
  ├─ 可疑流提取（tshark -Y 过滤 → 按流切割）
  ├─ 协议专项深析（HTTP 对象还原/webshell 特征、DNS 熵、TLS JA3/证书、隧道检测）
  ├─ 攻击行为检测（信标周期、爆破频率、扫描模式、数据外传体量）
  ├─ 文件提取 + 哈希（--export-objects）
  └─ Zeek/Suricata 若可用：IDS 特征匹配交叉验证
      ↓ 每条假设给"证实/排除/存疑"结论

阶段 3 · 研判
  ├─ 时间线重建 → 攻击链还原（初始访问→C2→横向→外传）
  ├─ IOC 提取标准化（IP/域名/URL/哈希/UA/JA3 → MISP）
  ├─ ATT&CK 映射（T1071/T1041/T1572…）
  └─ 误报排除（CDN/云厂商 IP、正常 TLS 指纹白名单交叉验证）
      ↓ 汇报：研判结论 + 证据链，确认后进入输出

阶段 4 · 输出
  ├─ Markdown 报告（按场景选模板）
  ├─ HTML 可视化报告（自包含单文件，浏览器直接打开）
  └─ IOC 清单（CSV/JSON/MISP）+ 提取文件证据清单
```

交互节奏：阶段 0/1 后各有一次方向确认；筛查阶段多轮循环至假设清空；每阶段输出结构化小结（发现/证据/下一步选项），分析师用"继续/深挖 X/换方向"控制。

## 7. 数据流与性能原则

```
pcap → capinfos 识别 → tshark -z 统计画像（JSON）
     → 过滤/流切割 → 脚本深析（信标/熵/IOC）→ 时间线 JSON
     → 模板渲染（MD + HTML + MISP CSV）
```

**性能红线**：所有统计走 tshark C 实现，Python 只做聚合计算；禁止 `rdpcap` 全量加载（现有同类 skill 在 GB 级文件上内存爆炸的通病）。

## 8. 错误处理

| 故障 | 策略 |
|---|---|
| pcap 损坏/截断 | capinfos 检测 → editcap 跳过损坏段或按时间恢复，不静默失败 |
| GB 级大文件 | 规模定级强制切片/流切割；脚本流式处理 |
| Zeek/Suricata 未装 | 启动探测，自动降级并在报告标注"IDS 引擎未启用" |
| Python 依赖缺失 | 核心脚本仅标准库 + tshark 输出解析；scapy/pyshark 仅增强，缺失不阻塞 |
| Windows 中文乱码 | 强制 UTF-8；tshark 用 `-T fields` 规避表格问题 |
| 输出目录/权限 | 自动创建（pcap 名+时间戳），权限不足明确提示 |
| 报告生成失败 | HTML 模板纯占位符替换无构建步骤，最坏只剩 MD 仍可交付 |

## 9. 测试策略

1. **测试数据集**：scapy 构造"全要素"测试包（HTTP 文件下载 + 高熵 DNS + 周期信标 + ICMP 隧道 + 明文 FTP 凭据 + 图片尾部藏 flag），验证六层能力
2. **脚本级验证**：每个脚本跑测试包，核对输出 JSON/HTML
3. **模板渲染验证**：三套 MD + HTML 模板用测试数据渲染，浏览器检查
4. **案例走查**：examples/ 写完整 CTF HTTP 题走查（冒烟测试 + 使用范例）
5. **规模路径验证**：放大测试包验证切片路径逻辑（不 OOM）

## 10. 范围外（YAGNI）

- 不做实时抓包/监听（只分析已有 pcap 文件）
- 不做 TLS 解密（无密钥场景为主，密钥可用时作为可选能力在 references 提及）
- 不做 MCP 服务器化（方案 A 已定）
- 不做恶意软件沙箱联动（属另一个 skill 的职责）
