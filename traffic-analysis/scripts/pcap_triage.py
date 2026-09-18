#!/usr/bin/env python
"""pcap_triage.py - 纯 stdlib 的 pcap 开局分诊：协议分布 / 包长直方图 / top 会话对。

只解析经典 pcap；pcapng 请先转换：  editcap -F pcap in.pcapng out.pcap
（或 tshark -r in.pcapng -w out.pcap）

用法：
  python pcap_triage.py <capture.pcap> [--json @out.json] [--min-packets N]

出口码：0 正常；2 = 某协议占比 >60%（明显信号载体，报告末尾给路由 hint）。
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # LE, us
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # BE, us
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # LE, ns
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # BE, ns
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPES = {
    1: "Ethernet", 101: "RAW-IP", 105: "802.11", 113: "Linux-SLL",
    127: "Radiotap+802.11", 189: "USB-Linux", 220: "USB-Linux-mmapped",
    288: "USB-Darwin",
}

# 端口语义猜测表（sport/dport 任一侧命中即归类）
PORT_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    139: "SMB", 445: "SMB", 161: "SNMP", 443: "TLS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 3389: "RDP", 5353: "mDNS",
    8000: "HTTP", 8080: "HTTP", 8443: "TLS",
}

LEN_BUCKETS = [(0, 63), (64, 127), (128, 255), (256, 511),
               (512, 1023), (1024, 1518), (1519, 1 << 30)]

ROUTE_HINTS = {
    "DNS": "DNS 隧道/隐写 -> references/tunnels.md #DNS + scripts/dnscat2_reassemble.py",
    "ICMP": "ICMP 隐信道（payload/长度/时延） -> references/tunnels.md #ICMP + scripts/timing_decode.py",
    "TLS": "TLS 解密（keylog/RSA 私钥/coredump） -> references/wifi-tls.md #TLS",
    "HTTP": "文件提取/凭据 -> references/pcap-triage.md #文件提取",
    "USB": "USB HID 键盘/鼠标 -> references/usb-hid.md + hid_keyboard.py / mouse_render.py",
    "SMB": "SMB 凭据或 SMB3 加密 -> references/pcap-triage.md #凭据 / wifi-tls.md #SMB3",
    "802.11": "WPA/WEP 解密 -> references/wifi-tls.md #WPA",
}


def ip4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def parse_ipv4(pkt: bytes):
    """返回 (proto, src, dst, sport, dport, l4_payload)；非 IPv4 返回 None。"""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    src, dst = ip4(pkt[12:16]), ip4(pkt[16:20])
    sport = dport = None
    l4 = pkt[ihl:]
    if proto in (6, 17) and len(l4) >= 4:
        sport, dport = struct.unpack(">HH", l4[:4])
    if proto == 6:
        off = (l4[12] >> 4) * 4 if len(l4) > 12 else 20
        l4_payload = l4[off:]
    elif proto == 17:
        l4_payload = l4[8:]
    else:
        l4_payload = l4[8:] if proto == 1 else l4  # ICMP 头 8 字节
    return proto, src, dst, sport, dport, l4_payload


def dns_qname_len(udp_payload: bytes) -> int:
    """DNS 查询名 wire 长度（含长度字节），解析失败返回 0。"""
    if len(udp_payload) < 13:
        return 0
    i, total = 12, 0
    while i < len(udp_payload):
        n = udp_payload[i]
        if n == 0:
            return total
        if n > 63:  # 压缩指针等，放弃
            return 0
        total += n
        i += n + 1
    return 0


def triage(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == PCAPNG_MAGIC:
        print("[!] pcapng 格式：先转换  editcap -F pcap in.pcapng out.pcap"
              "  （或 tshark -r in.pcapng -w out.pcap）", file=sys.stderr)
        sys.exit(1)
    magic = data[:4]
    if magic not in MAGICS:
        print(f"[!] 未知 magic: {magic.hex()} —— 先修文件，见 references/pcap-triage.md #修复",
              file=sys.stderr)
        sys.exit(1)
    endian, resol = MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    link_name = LINKTYPES.get(linktype, f"linktype-{linktype}")

    n = 0
    total_bytes = 0
    t_first = t_last = None
    protos = Counter()       # 服务名 -> 包数
    proto_bytes = Counter()
    convs = Counter()
    top_dports = Counter()
    lens = Counter()
    max_qname = 0
    eapol_hits = 0

    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        n += 1
        total_bytes += incl
        ts = ts_sec + ts_frac / resol
        t_first = ts if t_first is None else t_first
        t_last = ts
        for lo, hi in LEN_BUCKETS:
            if lo <= incl <= hi:
                lens[f"{lo}-{hi if hi < (1 << 30) else 'max'}"] += 1
                break

        service = None
        if linktype in (189, 220, 288):
            service = "USB"
        elif linktype in (105, 127):
            service = "802.11"
            if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in pkt:  # LLC SNAP EAPOL 启发式
                eapol_hits += 1
        else:
            l3 = None
            if linktype == 1 and len(pkt) >= 14:  # Ethernet
                et = struct.unpack(">H", pkt[12:14])[0]
                base = 14
                if et == 0x8100 and len(pkt) >= 18:  # VLAN
                    et = struct.unpack(">H", pkt[16:18])[0]
                    base = 18
                if et == 0x0800:
                    l3 = parse_ipv4(pkt[base:])
                elif et == 0x0806:
                    service = "ARP"
            elif linktype == 101:  # RAW
                l3 = parse_ipv4(pkt)
            elif linktype == 113 and len(pkt) >= 16:  # Linux SLL
                if struct.unpack(">H", pkt[14:16])[0] == 0x0800:
                    l3 = parse_ipv4(pkt[16:])
            if l3:
                proto, src, dst, sport, dport, l4_payload = l3
                if proto == 1:
                    service = "ICMP"
                elif proto in (6, 17):
                    p = sport if sport in PORT_SERVICES else dport
                    if p in PORT_SERVICES:
                        service = PORT_SERVICES[p]
                    else:
                        service = "TCP-other" if proto == 6 else "UDP-other"
                        if dport:
                            top_dports[dport] += 1
                    if service == "DNS" and proto == 17:
                        qlen = dns_qname_len(l4_payload)
                        max_qname = max(max_qname, qlen)
                    if sport and dport:
                        a, b = f"{src}:{sport}", f"{dst}:{dport}"
                        convs[tuple(sorted((a, b)))] += 1
                else:
                    service = f"IP-proto-{proto}"
                if proto == 1:
                    convs[tuple(sorted((src, dst)))] += 1
        if service is None:
            service = f"other({link_name})"
        protos[service] += 1
        proto_bytes[service] += incl

    return {
        "file": path, "linktype": link_name, "packets": n, "bytes": total_bytes,
        "time_span_s": round((t_last - t_first), 3) if n else 0,
        "protos": protos, "proto_bytes": proto_bytes, "convs": convs,
        "top_dports": top_dports, "len_hist": lens,
        "max_qname_len": max_qname, "eapol_hits": eapol_hits,
    }


def render(r, min_packets: int) -> int:
    print(f"== pcap 分诊 == {r['file']}")
    print(f"linktype={r['linktype']}  包数={r['packets']}  字节={r['bytes']}"
          f"  时间跨度={r['time_span_s']}s")
    print("\n-- 协议分布（端口语义猜测） --")
    total = max(r["packets"], 1)
    dominant, dominant_pct = None, 0.0
    for name, cnt in r["protos"].most_common():
        pct = cnt * 100.0 / total
        print(f"  {name:<12} {cnt:>8} 包  {pct:5.1f}%  {r['proto_bytes'][name]:>10} B")
        if pct > dominant_pct:
            dominant, dominant_pct = name, pct
    print("\n-- 包长直方图 --")
    for lo, hi in LEN_BUCKETS:
        k = f"{lo}-{hi if hi < (1 << 30) else 'max'}"
        c = r["len_hist"].get(k, 0)
        bar = "#" * int(c * 50 / total)
        print(f"  {k:>10} {c:>8} {bar}")
    print("\n-- top 会话对 --")
    for (a, b), c in r["convs"].most_common(10):
        print(f"  {c:>8}  {a} <-> {b}")
    if r["top_dports"]:
        print("\n-- 未识别 top dport --")
        for p, c in r["top_dports"].most_common(5):
            print(f"  {p:>6}  {c} 包")

    hints = []
    if r["linktype"] in ("USB-Linux", "USB-Linux-mmapped", "USB-Darwin"):
        hints.append(ROUTE_HINTS["USB"])
    if r["linktype"] in ("802.11", "Radiotap+802.11"):
        hints.append(ROUTE_HINTS["802.11"]
                     + (f"（EAPOL 启发式命中 {r['eapol_hits']} 次）" if r["eapol_hits"] else ""))
    if r["max_qname_len"] > 40:
        hints.append(f"DNS 查询名最长 {r['max_qname_len']} 字节（>40 疑隧道） -> " + ROUTE_HINTS["DNS"])
    if dominant_pct > 60 and total >= min_packets and dominant in ROUTE_HINTS:
        hints.insert(0, f"【信号载体】{dominant} 占比 {dominant_pct:.1f}% -> " + ROUTE_HINTS[dominant])
    if not hints:
        hints.append("协议分布无明显异常 -> 元数据直方图法找隐写："
                     "timing_decode.py --mode len / --mode byte --offset N（TTL=IP+8, IPID=IP+4），"
                     "方法论见 references/tunnels.md #通用检测")
    print("\n-- 路由 hint --")
    for h in hints:
        print(f"  * {h}")

    if dominant_pct > 60 and total >= min_packets:
        print(f"\n[GATE] {dominant} 占比 {dominant_pct:.1f}% > 60%（exit 2）", file=sys.stderr)
        return 2
    return 0


def main():
    ap = argparse.ArgumentParser(description="纯 stdlib pcap 开局分诊（协议分布/直方图/top 会话）")
    ap.add_argument("pcap")
    ap.add_argument("--json", metavar="@out.json", help="完整结果写 JSON 文件")
    ap.add_argument("--min-packets", type=int, default=20, help="占比闸门的最少包数（默认 20）")
    args = ap.parse_args()

    r = triage(args.pcap)
    rc = render(r, args.min_packets)
    if args.json:
        out = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in r.items()}
        out["convs"] = {f"{a} <-> {b}": c for (a, b), c in r["convs"].items()}
        with open(args.json.lstrip("@"), "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    sys.exit(rc)


if __name__ == "__main__":
    main()
