#!/usr/bin/env python
"""pcap_triage.py - 纯 stdlib 的 pcap 开局分诊：协议分布 / 包长直方图 / top 会话对 / 每流字段一致性矩阵。

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
from collections import Counter, defaultdict

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


def tcp_tsval(l4: bytes):
    """解析 TCP TS option（kind 8, len 10），返回 tsval 或 None。"""
    if len(l4) < 20:
        return None
    off = (l4[12] >> 4) * 4
    if off < 20 or off > len(l4):
        return None
    opts = l4[20:off]
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            return None
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            return None
        ln = opts[i + 1]
        if ln < 2 or i + ln > len(opts):
            return None
        if kind == 8 and ln == 10:
            return struct.unpack(">I", opts[i + 2:i + 6])[0]
        i += ln
    return None


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
    flow_pkts = defaultdict(list)  # TCP 会话 -> [(seq, payload, tsval, ttl, ipid, win, incl)]

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
            ip_bytes = None
            if linktype == 1 and len(pkt) >= 14:  # Ethernet
                et = struct.unpack(">H", pkt[12:14])[0]
                base = 14
                if et == 0x8100 and len(pkt) >= 18:  # VLAN
                    et = struct.unpack(">H", pkt[16:18])[0]
                    base = 18
                if et == 0x0800:
                    ip_bytes = pkt[base:]
                    l3 = parse_ipv4(ip_bytes)
                elif et == 0x0806:
                    service = "ARP"
            elif linktype == 101:  # RAW
                ip_bytes = pkt
                l3 = parse_ipv4(ip_bytes)
            elif linktype == 113 and len(pkt) >= 16:  # Linux SLL
                if struct.unpack(">H", pkt[14:16])[0] == 0x0800:
                    ip_bytes = pkt[16:]
                    l3 = parse_ipv4(ip_bytes)
            if l3:
                proto, src, dst, sport, dport, l4_payload = l3
                if proto == 6 and sport and dport and ip_bytes:
                    ihl = (ip_bytes[0] & 0x0F) * 4
                    l4 = ip_bytes[ihl:]
                    if len(l4) >= 20:
                        a, b = f"{src}:{sport}", f"{dst}:{dport}"
                        flow_pkts[tuple(sorted((a, b)))].append((
                            struct.unpack(">I", l4[4:8])[0],          # seq
                            bytes(l4_payload),                        # payload
                            tcp_tsval(l4),                            # tsval（无 TS option 为 None）
                            ip_bytes[8],                              # ttl
                            struct.unpack(">H", ip_bytes[4:6])[0],    # ipid
                            struct.unpack(">H", l4[14:16])[0],        # window
                            incl,
                        ))
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
        "flow_pkts": flow_pkts,
    }


def flow_consistency(flow_pkts, top_n: int = 5, min_pkts: int = 8):
    """每流字段变异性 + 重复键冲突检测（纯追加分析，不影响 exit 码）。"""
    out = []
    for conv, recs in sorted(flow_pkts.items(), key=lambda kv: -len(kv[1])):
        if len(recs) < min_pkts:
            continue
        fields = {
            "ttl": [r[3] for r in recs],
            "ipid": [r[4] for r in recs],
            "window": [r[5] for r in recs],
            "len": [r[6] for r in recs],
            "pay0": [(r[1][0] if r[1] else None) for r in recs],
            "tsval.lo": [(r[2] & 0xF if r[2] is not None else None) for r in recs],
        }
        stats = {}
        for name, vals in fields.items():
            u = len(set(vals))
            cls = "constant" if u == 1 else ("low-entropy" if u <= 4 else "variable")
            stats[name] = (u, cls)
        seq_conf = 0
        by_seq = defaultdict(set)
        for r in recs:
            by_seq[r[0]].add(r[1])
        seq_conf = sum(1 for v in by_seq.values() if len(v) > 1)
        by_idx = defaultdict(set)
        for r in recs:
            if r[2] is not None:
                by_idx[(r[2] >> 8) & 0xFF].add(r[2] & 0xF)
        idx_conf = sum(1 for v in by_idx.values() if len(v) > 1)
        out.append({"conv": conv, "packets": len(recs), "stats": stats,
                    "seq_conflicts": seq_conf, "tsval_idx_conflicts": idx_conf})
        if len(out) >= top_n:
            break
    return out


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
                     "timing_decode.py --mode len / --mode byte --offset N"
                     "（TTL=IP+8, TOS=IP+1；IPID 16 位大端 -> 高字节 IP+4/低字节 IP+5），"
                     "方法论见 references/tunnels.md #通用检测")
    print("\n-- 路由 hint --")
    for h in hints:
        print(f"  * {h}")

    fc = flow_consistency(r["flow_pkts"])
    if fc:
        print("\n-- 每流字段一致性矩阵（top TCP 流，包数 ≥8） --")
        for row in fc:
            a, b = row["conv"]
            print(f"  {a} <-> {b}  ({row['packets']} 包)")
            for name, (u, cls) in row["stats"].items():
                print(f"    {name:<9} unique={u:>3}  {cls}")
            if row["seq_conflicts"] or row["tsval_idx_conflicts"]:
                print(f"    ⚠ 重复键冲突（同 seq 载荷不同 ×{row['seq_conflicts']}，"
                      f"同 (tsval>>8)&0xff 低半字节冲突 ×{row['tsval_idx_conflicts']}）"
                      " → 复合值候选，走 conflict_oracle.py")

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
        out["flow_consistency"] = [
            {"conv": f"{row['conv'][0]} <-> {row['conv'][1]}",
             "packets": row["packets"],
             "stats": {n: {"unique": u, "class": c} for n, (u, c) in row["stats"].items()},
             "seq_conflicts": row["seq_conflicts"],
             "tsval_idx_conflicts": row["tsval_idx_conflicts"]}
            for row in flow_consistency(r["flow_pkts"])
        ]
        del out["flow_pkts"]
        with open(args.json.lstrip("@"), "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    sys.exit(rc)


if __name__ == "__main__":
    main()
