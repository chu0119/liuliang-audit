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
