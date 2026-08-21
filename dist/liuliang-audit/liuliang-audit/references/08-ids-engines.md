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
