# CTF HTTP 流量取证案例走查

## 题目

给定 `http_flag.pcap`，找出隐藏的 flag。

## 解题过程

### 阶段 0 · 识别

```bash
capinfos -M http_flag.pcap
# Number of packets: 42
# Capture duration: 5.2s
# → small，全量深析
```

### 阶段 1 · 画像

```bash
python scripts/pcap_profile.py http_flag.pcap
# 协议：TCP 95%，HTTP 80%
# 可疑：单 IP 多 HTTP 请求
```

### 阶段 2 · 筛查

```bash
tshark -r http_flag.pcap -T fields -e http.request.uri -Y "http.request"
# /index.html
# /secret.txt   ← 可疑
# /logo.png

tshark -r http_flag.pcap --export-objects http,http/
# 提取 secret.txt → 内容：FLAG{h1dd3n_in_http}
```

### 答案

`FLAG{h1dd3n_in_http}`

## 关键命令

- `tshark -T fields -e http.request.uri -Y "http.request"` — 列出所有请求
- `tshark --export-objects http,dir/` — 还原 HTTP 对象
