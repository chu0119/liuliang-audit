# 贡献指南

感谢关注 liuliang-audit！欢迎以 Issue / PR 形式贡献。

## 开发环境

```bash
git clone https://github.com/chu0119/liuliang-audit.git
cd liuliang-audit

# 前置：Wireshark 套件（tshark/capinfos/editcap/mergecap）
# Windows: https://www.wireshark.org/  |  Ubuntu: sudo apt install tshark
pip install scapy pytest
```

## 运行测试

```bash
cd liuliang-audit
python -m pytest tests/ -v
```

所有提交前测试必须全绿。测试数据由 `tests/conftest.py` 的 scapy 夹具动态生成，无需外部样本。

## 项目约定（PR 审查会检查）

1. **性能红线**：统计必须走 tshark C 实现，Python 只做聚合；禁止 `rdpcap` 全量载入内存
2. **大声失败**：子进程必须检查 returncode，失败抛 `RuntimeError`（含 stderr 摘要）；禁止静默返回空结果
3. **编码**：全链路强制 UTF-8；CLI 入口需 `sys.stdout.reconfigure(encoding="utf-8")`
4. **脚本独立**：scripts/ 下脚本互不 import、无共享包，可单独 `python scripts/xxx.py` 运行
5. **安全**：进入报告的 pcap 派生字符串必须转义；外部输入参数需校验（参考 `extract_files.py` 的协议名白名单）
6. **TDD**：新功能先写失败测试再实现；修复缺陷先写复现测试
7. 每个变更更新 `CHANGELOG.md`

## 提交规范

- 格式：`type: subject`（英文小写），如 `feat: add smb lateral movement detection`
- type ∈ feat / fix / docs / chore / refactor / test

## 新增检测能力的建议流程

1. 在 `references/04-attack-detection.md` 补充检测原理与判定阈值依据
2. 实现脚本或扩展既有脚本（遵循上述约定）
3. 在 `tests/` 用 scapy 构造该行为的合成流量并断言检出
4. 若产出新报告字段，同步更新 `pcap_profile.py` 契约与 HTML 模板占位符
