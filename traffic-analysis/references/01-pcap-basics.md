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
