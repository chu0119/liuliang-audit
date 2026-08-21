# scripts/extract_files.py
"""对象提取封装：调用 tshark --export-objects 并计算 SHA-256。"""
import hashlib, subprocess, sys
from pathlib import Path


def _run(cmd: list):
    """执行 tshark 并显式报错（与 pcap_profile.py 约定一致：工具失败必须响亮失败）。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError(
            f"命令不存在: {cmd[0]}。请安装 Wireshark 套件 (tshark/capinfos) 并加入 PATH。"
        ) from e
    if r.returncode != 0:
        tail = "\n".join(r.stderr.strip().splitlines()[-5:])
        raise RuntimeError(
            f"命令失败 (exit {r.returncode}): {' '.join(cmd)}\n{tail}")
    return r


def extract_objects(pcap_path: str, output_dir: str, protocols: list[str] = None) -> list[dict]:
    """按协议导出 pcap 中的传输对象，返回含 filename/size/sha256/protocol 的列表。"""
    if protocols is None:
        protocols = ["http", "smb", "tftp"]
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for proto in protocols:
        proto_dir = out / proto
        proto_dir.mkdir(exist_ok=True)
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
    import json
    print(json.dumps(extract_objects(sys.argv[1], sys.argv[2]), ensure_ascii=False, indent=2))
