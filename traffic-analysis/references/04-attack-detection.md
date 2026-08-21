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
