# 05 · CTF 流量取证专项

## 常见题型

| 类型 | 特征 | 解法 |
|------|------|------|
| HTTP 对象还原 | HTTP 含文件下载 | --export-objects http |
| 图片尾部藏数据 | TCP 流末尾附加 | follow tcp stream → 提取 |
| 协议字段隐写 | DNS TXT/ICMP payload | 提取 payload → 解码 |
| Base64/十六进制编码 | HTTP POST/响应体 | 提取 → 解码 |
| 畸形协议 | 非标准端口协议 | 按流分析，逆向协议结构 |
| 明文凭据 | FTP/Telnet/HTTP Basic | 提取 USER/PASS/Authorization |
| USB/键盘流量 | usb.capdata | 解析 HID 码 |

## Flag 搜索

```bash
# 在全部 payload 中搜索 flag 格式
tshark -r f.pcap -T fields -e data.data -Y "data.data" | grep -oE "flag\{[^}]+\}"
tshark -r f.pcap -T fields -e http.file_data | grep -oE "flag\{[^}]+\}"
```

## 文件还原

```bash
tshark -r f.pcap --export-objects http,http/
tshark -r f.pcap --export-objects smb,smb/
tshark -r f.pcap --export-objects tftp,tftp/
# 手动：follow TCP stream → Save As
```

## 编码识别

常见：Base64、Hex、URL 编码、XOR、ROT13、Gzip 压缩。
