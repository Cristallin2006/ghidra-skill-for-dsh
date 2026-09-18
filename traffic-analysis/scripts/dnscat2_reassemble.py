#!/usr/bin/env python
"""dnscat2_reassemble.py - DNS 查询名列表 -> dnscat2 隧道 payload 重组。

输入：每行一个 FQDN（tshark 导出）：
  tshark -r cap.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name \
      | python dnscat2_reassemble.py --domain skullseclabs.org --out payload.bin

配方（BSidesSF 2017 dnscap）：剥域名后缀 -> hex label 拼接 -> 去 9 字节
dnscat2 头（session/seq/ack）-> 相邻去重吃重传 -> 拼接。
去重比较的是**含头的整包**（重传的 seq/ack 相同所以整包相同）；
只比 payload 会把真实数据里的连续重复块（如长串 0x00）误折叠。

出口码：0 正常；2 = 一个 chunk 都没解出来（域名不对或编码不对）。
"""
from __future__ import annotations

import argparse
import base64
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"), (b"PK\x03\x04", "ZIP"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"), (b"\x7fELF", "ELF"), (b"MZ", "PE"), (b"Rar!", "RAR"),
    (b"%PDF", "PDF"), (b"\xff\xd8\xff", "JPEG"),
]


def detect_domain(lines):
    """没给 --domain 时猜：取所有行最后两个 label 的众数。"""
    from collections import Counter
    c = Counter()
    for ln in lines:
        parts = ln.rstrip(".").split(".")
        if len(parts) >= 2:
            c[".".join(parts[-2:])] += 1
    return c.most_common(1)[0][0] if c else None


def decode_labels(name: str, domain: str, use_b32: bool) -> bytes | None:
    n = name.lower().rstrip(".")
    d = domain.lower().rstrip(".")
    if not n.endswith(d):
        return None
    prefix = n[: -len(d)].strip(".")
    if not prefix:
        return None
    blob = "".join(prefix.split("."))
    try:
        if use_b32:
            blob += "=" * (-len(blob) % 8)
            return base64.b32decode(blob.upper())
        return bytes.fromhex(blob)
    except (ValueError, Exception):
        return None


def main():
    ap = argparse.ArgumentParser(description="dnscat2 DNS 隧道 payload 重组（hex label/去 9 字节头/去重传）")
    ap.add_argument("file", nargs="?", help="域名列表文件；缺省读 stdin")
    ap.add_argument("--domain", help="隧道域名后缀（缺省自动猜最后两个 label 的众数）")
    ap.add_argument("--base32", action="store_true", help="label 是 base32 而非 hex")
    ap.add_argument("--header-len", type=int, default=9, help="dnscat2 协议头长度（默认 9）")
    ap.add_argument("--out", help="payload 二进制写文件；缺省只打印预览")
    args = ap.parse_args()

    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    domain = args.domain or detect_domain(lines)
    if not domain:
        print("[!] 猜不出隧道域名，请 --domain 指定", file=sys.stderr)
        sys.exit(2)

    data = b""
    prev = None
    chunks = 0
    skipped = 0
    for ln in lines:
        raw = decode_labels(ln, domain, args.base32)
        if raw is None or len(raw) <= args.header_len:
            skipped += 1
            continue
        if raw == prev:            # 重传整包（含头）相同才丢弃
            continue
        prev = raw
        data += raw[args.header_len:]
        chunks += 1

    print(f"[+] domain={domain}  有效 chunk={chunks}  跳过={skipped}  重组={len(data)} 字节")
    if chunks == 0:
        print("[!] 0 个有效 chunk：检查 --domain / --base32 / --header-len", file=sys.stderr)
        sys.exit(2)

    kind = next((name for magic, name in MAGICS if data.startswith(magic)), None)
    if kind:
        print(f"[+] 魔数识别: {kind}")
    printable = sum(1 for b in data[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    if data and printable / min(len(data), 4096) > 0.85:
        print("-- 文本预览 --")
        print(data[:4096].decode("utf-8", errors="replace"))
    else:
        print("-- hex 预览（前 128 字节） --")
        print(data[:128].hex())
    if args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        print(f"[+] 写入 {args.out}")


if __name__ == "__main__":
    main()
