# scripts/extract_files.py
"""对象提取封装：调用 tshark --export-objects 并计算 SHA-256。"""
import hashlib, re, shutil, subprocess, sys
from pathlib import Path


def _run(cmd: list):
    """执行 tshark 并显式报错（与 pcap_profile.py 约定一致：工具失败必须响亮失败）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError(
            f"命令不存在: {cmd[0]}。请安装 Wireshark 套件 (tshark) 并加入 PATH。"
        ) from e
    if r.returncode != 0:
        tail = "\n".join(r.stderr.strip().splitlines()[-5:])
        raise RuntimeError(
            f"命令失败 (exit {r.returncode}): {' '.join(cmd)}"
            + (f"\n{tail}" if tail else ""))
    return r


def extract_objects(pcap_path: str, output_dir: str, protocols: list[str] = None) -> list[dict]:
    """按协议导出 pcap 中的传输对象，返回含 filename/size/sha256/protocol 的列表。

    每个协议子目录导出前先清空，避免上一个 pcap 的残留对象被误报为本次结果。
    """
    if protocols is None:
        protocols = ["http", "smb", "tftp"]
    invalid = [p for p in protocols if not re.fullmatch(r"[a-z0-9_-]+", p)]
    if invalid:
        raise ValueError(
            f"非法协议名: {', '.join(map(repr, invalid))}"
            "（协议名仅允许小写字母/数字/_/-，禁止路径分隔符等，"
            "防止把导出目录写到 output_dir 之外）")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for proto in protocols:
        proto_dir = out / proto
        if proto_dir.exists():
            # 清理残留必须响亮失败（ignore_errors=False）：
            # 文件被锁等异常不得静默留下陈旧文件污染本次结果。
            shutil.rmtree(proto_dir)
        proto_dir.mkdir(parents=True, exist_ok=True)
        _run(["tshark", "-r", pcap_path, "--export-objects", f"{proto},{proto_dir}"])
        for f in sorted(proto_dir.iterdir()):
            if f.is_file():
                data = f.read_bytes()
                results.append({"filename": f.name, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "protocol": proto, "path": str(f)})
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_files.py <pcap> <output_dir>", file=sys.stderr); sys.exit(1)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    import json
    print(json.dumps(extract_objects(sys.argv[1], sys.argv[2]), ensure_ascii=False, indent=2))
