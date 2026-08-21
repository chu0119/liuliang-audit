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
