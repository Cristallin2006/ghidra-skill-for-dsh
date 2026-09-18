#!/usr/bin/env python
"""timing_decode.py - pcap 元数据隐信道解码：时序分档 / 包长 / 单字节字段。

三种取数模式：
  --mode interval  相邻包时间差 -> 阈值分档成 bit（EHAX 2026 / DefCamp 2018）
  --mode len       每包捕获长度即值（TokyoWesterns 2018：长度=可打印 ASCII）
  --mode byte      每包第 N 字节即值（TTL/IPID/flags 等，--offset 相对 IP 头）

过滤：--proto icmp|tcp|udp  --sport N  --dport N  --src IP  --dst IP

解码：取到值序列后，
  - 有 --threshold：v >= T 为 1 否则 0 -> 8bit MSB-first -> ASCII
  - 无 --threshold：值直接当字节 -> 可打印性检查 -> ASCII/hex
interval 模式无 --threshold 时自动取 (min+max)/2（直方图先打出来人工核对）。

出口码：0 正常；2 = 过滤后 0 包（过滤条件不对，换条件别硬解）。
"""
from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def ip4(b):
    return ".".join(str(x) for x in b)


def iter_packets(path):
    """内联自 pcap_triage.py：yield (ts: float, incl_len: int, pkt: bytes, ip_off: int|None)。
    ip_off = IPv4 头在 pkt 内的偏移；非 IPv4 为 None。"""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        print("[!] pcapng：先 editcap -F pcap 转换", file=sys.stderr)
        sys.exit(1)
    endian, resol = MAGICS[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _o = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ip_off = None
        if linktype == 1 and len(pkt) >= 14:
            et = struct.unpack(">H", pkt[12:14])[0]
            base = 14
            if et == 0x8100 and len(pkt) >= 18:
                et = struct.unpack(">H", pkt[16:18])[0]
                base = 18
            if et == 0x0800:
                ip_off = base
        elif linktype == 101:
            ip_off = 0
        elif linktype == 113 and len(pkt) >= 16 and pkt[14:16] == b"\x08\x00":
            ip_off = 16
        yield ts_sec + ts_frac / resol, incl, pkt, ip_off


def match(pkt, ip_off, args):
    if ip_off is None or len(pkt) < ip_off + 20:
        return False
    ip = pkt[ip_off:]
    proto = ip[9]
    if args.proto == "icmp" and proto != 1:
        return False
    if args.proto == "tcp" and proto != 6:
        return False
    if args.proto == "udp" and proto != 17:
        return False
    if args.src and ip4(ip[12:16]) != args.src:
        return False
    if args.dst and ip4(ip[16:20]) != args.dst:
        return False
    if (args.sport or args.dport) and proto in (6, 17):
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 4:
            return False
        sport, dport = struct.unpack(">HH", ip[ihl:ihl + 4])
        if args.sport and sport != args.sport:
            return False
        if args.dport and dport != args.dport:
            return False
    return True


def bits_to_bytes(bits):
    return bytes(int("".join(str(b) for b in bits[i:i + 8]), 2)
                 for i in range(0, len(bits) - 7, 8))


def try_render(data: bytes):
    if not data:
        return
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(data)
    print(f"[+] 解出 {len(data)} 字节，可打印率 {ratio:.0%}")
    if ratio > 0.7:
        print("-- ASCII --")
        print(data.decode("utf-8", errors="replace"))
    else:
        print("-- hex --")
        print(data.hex())


def main():
    ap = argparse.ArgumentParser(description="pcap 元数据隐信道解码（时序/长度/单字节字段）")
    ap.add_argument("pcap")
    ap.add_argument("--mode", choices=["interval", "len", "byte"], required=True)
    ap.add_argument("--proto", choices=["icmp", "tcp", "udp"])
    ap.add_argument("--sport", type=int)
    ap.add_argument("--dport", type=int)
    ap.add_argument("--src")
    ap.add_argument("--dst")
    ap.add_argument("--offset", type=int, default=8,
                    help="byte 模式：相对 IP 头的偏移（默认 8=TTL；IPID=4, TOS=1）")
    ap.add_argument("--threshold", type=float, help="分档阈值（interval=秒；len/byte=数值）")
    ap.add_argument("--invert", action="store_true", help="bit 极性翻转")
    args = ap.parse_args()

    rows = [(ts, incl, pkt, ip_off) for ts, incl, pkt, ip_off in iter_packets(args.pcap)
            if match(pkt, ip_off, args)]
    print(f"[+] 过滤命中 {len(rows)} 包")
    if not rows:
        print("[!] 0 包命中：换过滤条件（pcap_triage.py 先看协议分布）", file=sys.stderr)
        sys.exit(2)

    if args.mode == "interval":
        times = [ts for ts, *_ in rows]
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        hist = Counter(round(d, 3) for d in intervals)
        print("-- 时延直方图（秒: 次数） --")
        for v, c in sorted(hist.items()):
            print(f"  {v:>8.3f}  {c}")
        thr = args.threshold
        if thr is None:
            thr = (min(intervals) + max(intervals)) / 2
            print(f"[+] 自动阈值 = {thr:.4f}s（按直方图核对，双峰不齐就 --threshold 手给）")
        bits = [(1 if d >= thr else 0) ^ args.invert for d in intervals]
        print(f"[+] bits({len(bits)}): " + "".join(map(str, bits[:96])) + ("..." if len(bits) > 96 else ""))
        try_render(bits_to_bytes(bits))
    else:
        if args.mode == "len":
            values = [incl for _, incl, _, _ in rows]
        else:
            values = []
            for _, _, pkt, ip_off in rows:
                idx = ip_off + args.offset
                values.append(pkt[idx] if idx < len(pkt) else 0)
        hist = Counter(values)
        print("-- 值直方图（值: 次数，前 20） --")
        for v, c in sorted(hist.items())[:20]:
            tag = f"  '{chr(v)}'" if 32 <= v < 127 else ""
            print(f"  {v:>5}  {c}{tag}")
        if args.threshold is not None:
            bits = [(1 if v >= args.threshold else 0) ^ args.invert for v in values]
            print(f"[+] bits({len(bits)}): " + "".join(map(str, bits[:96])))
            try_render(bits_to_bytes(bits))
        else:
            try_render(bytes(values))


if __name__ == "__main__":
    main()
