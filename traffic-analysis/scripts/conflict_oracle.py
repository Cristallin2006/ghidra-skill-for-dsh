#!/usr/bin/env python
"""conflict_oracle.py - 重复键字段冲突预言机：哪些字段在重复逻辑键上取值冲突，哪些算子组合能消除冲突。

用途：同一逻辑键（同下标/同 seq/重传）上某字段取值不一致
  ⇒ 该字段大概率不是明文本身，明文可能是 ≥2 字段的复合函数（xor/add/sub）。
本脚本报告冲突、并搜索 1~3 元字段组合 × {xor,add,sub} 中"让所有重复键取值一致"的组合。

注意：真实抓包中 TCP 重传的载荷可能合法不同，key 设计是用户的责任；
本工具只报告不裁决——冲突是假设生成器，不是排除器。

用法：
  python conflict_oracle.py cap.pcap --key-expr "(tsval>>8)&0xff"
  python conflict_oracle.py cap.pcap --stream "10.0.0.1:49622->10.0.0.9:8443" --key-expr "(tsval>>8)&0xff"
  python conflict_oracle.py cap.pcap --key ipid --fields tsval.n0,pay.lo,seq.n1
  python conflict_oracle.py cap.pcap --key-expr "seq" --json @out.json

排名纪律（T-A1 修复）：
  - 含"逐包唯一"宽字段（整 tsval/seq/ack/pkt 等，宽度≥16 且取值几乎每包不同）的组合
    消除冲突是平凡结果——单列 degenerate 区，不参与主排名；
  - 主排名按 消除数 desc、结果流熵 **desc**（真解是数据样高熵，低熵偏好会把真解压出 top）；
  - 冲突字段是复合值的**抵消项**：正确动作是纳入 XOR/ADD 组合，禁止判为"无信息"剔除。

出口码：0 正常；1 参数/输入错误。
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import re
import struct
import sys
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_triage import MAGICS, PCAPNG_MAGIC, tcp_tsval  # noqa: E402

OPS = ("xor", "add", "sub")

# (名字, 位宽, 提取函数)；pkt  dict 见 iter_tcp()。pay[i] 走动态正则。
def _nibble(v, i):
    return (v >> (4 * i)) & 0xF


def _pay_byte(p, i):
    return p["payload"][i] if i < len(p["payload"]) else 0


STATIC_FIELDS = {}


def _init_fields():
    def reg(name, width, fn):
        STATIC_FIELDS[name] = (width, fn)

    reg("pay.hi", 4, lambda p: (p["payload"][0] >> 4) & 0xF if p["payload"] else 0)
    reg("pay.lo", 4, lambda p: p["payload"][0] & 0xF if p["payload"] else 0)
    reg("pay[0]", 8, lambda p: _pay_byte(p, 0))
    reg("tsval", 32, lambda p: p["tsval"] or 0)
    reg("seq", 32, lambda p: p["seq"])
    reg("ack", 32, lambda p: p["ack"])
    for i in range(8):
        reg(f"tsval.n{i}", 4, lambda p, i=i: _nibble(p["tsval"] or 0, i))
        reg(f"seq.n{i}", 4, lambda p, i=i: _nibble(p["seq"], i))
        reg(f"ack.n{i}", 4, lambda p, i=i: _nibble(p["ack"], i))
    reg("sport", 16, lambda p: p["sport"])
    reg("dport", 16, lambda p: p["dport"])
    reg("ipid", 16, lambda p: p["ipid"])
    reg("ttl", 8, lambda p: p["ttl"])
    reg("win", 16, lambda p: p["win"])
    reg("flags", 8, lambda p: p["flags"])
    reg("len", 16, lambda p: p["len"])
    reg("pkt", 32, lambda p: p["pkt"])


_init_fields()

PAY_RE = re.compile(r"^pay\[(\d+)\]$")


def field_width(name):
    if name in STATIC_FIELDS:
        return STATIC_FIELDS[name][0]
    m = PAY_RE.match(name)
    if m:
        return 8
    raise KeyError(name)


def field_value(name, p):
    if name in STATIC_FIELDS:
        return STATIC_FIELDS[name][1](p)
    m = PAY_RE.match(name)
    if m:
        return _pay_byte(p, int(m.group(1)))
    raise KeyError(name)


def iter_tcp(path: str):
    """产出 TCP 包 dict：pkt/ts/src/dst/sport/dport/seq/ack/flags/win/ttl/ipid/tsval/payload/len。"""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == PCAPNG_MAGIC:
        raise SystemExit("[!] pcapng 格式：先转换 editcap -F pcap in.pcapng out.pcap")
    magic = data[:4]
    if magic not in MAGICS:
        raise SystemExit(f"[!] 未知 magic: {magic.hex()}")
    endian, resol = MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype not in (1, 101):
        raise SystemExit(f"[!] 暂不支持的 linktype {linktype}（支持 Ethernet=1 / RAW=101）")

    n = 0
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        raw = data[off:off + incl]
        off += incl
        n += 1
        if linktype == 1:
            if len(raw) < 14:
                continue
            et = struct.unpack(">H", raw[12:14])[0]
            base = 14
            if et == 0x8100 and len(raw) >= 18:
                et = struct.unpack(">H", raw[16:18])[0]
                base = 18
            if et != 0x0800:
                continue
            ip = raw[base:]
        else:
            ip = raw
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        l4 = ip[ihl:]
        if len(l4) < 20:
            continue
        doff = (l4[12] >> 4) * 4
        if doff < 20 or doff > len(l4):
            continue
        yield {
            "pkt": n,
            "ts": ts_sec + ts_frac / resol,
            "src": ".".join(str(x) for x in ip[12:16]),
            "dst": ".".join(str(x) for x in ip[16:20]),
            "sport": struct.unpack(">H", l4[0:2])[0],
            "dport": struct.unpack(">H", l4[2:4])[0],
            "seq": struct.unpack(">I", l4[4:8])[0],
            "ack": struct.unpack(">I", l4[8:12])[0],
            "flags": l4[13],
            "win": struct.unpack(">H", l4[14:16])[0],
            "ttl": ip[8],
            "ipid": struct.unpack(">H", ip[4:6])[0],
            "tsval": tcp_tsval(l4),
            "payload": l4[doff:],
            "len": incl,
        }


def eval_namespace(p):
    """受限 eval 的名字空间：字段名中的 '.'/'[]' 不是合法标识符，用 '__' 形式（tsval.n0 -> tsval__n0）。"""
    ns = {"__builtins__": {}}
    for name in STATIC_FIELDS:
        try:
            v = field_value(name, p)
        except KeyError:
            continue
        safe = re.sub(r"[^0-9A-Za-z_]", "__", name)
        ns[safe] = v
        if name.isidentifier():
            ns[name] = v
    return ns


def parse_keys(packets, key_expr, key_field):
    """返回 key -> [包下标列表]（按抓包顺序）。"""
    groups = defaultdict(list)
    for idx, p in enumerate(packets):
        if key_field:
            try:
                k = field_value(key_field, p)
            except KeyError:
                raise SystemExit(f"[!] 未知字段 --key {key_field}")
        else:
            try:
                k = eval(key_expr, eval_namespace(p))  # noqa: S307 - 受限名字空间
            except Exception as e:
                raise SystemExit(f"[!] --key-expr 求值失败（包 #{p['pkt']}）: {e}")
        groups[k].append(idx)
    return groups


def drop_key_colliding_empty(packets, key_expr, key_field):
    """剔除与数据包同键的无载荷包（握手/纯 ACK），返回 (kept, dropped)。

    T-A2#1：SYN 之类无载荷包的 key（如 (tsval>>8)&0xff==0）会抢走数据包 key 的
    "第一次出现"，既污染 decode_engine 的明文流，也污染 conflict_oracle 的冲突集
    （实测：71 包混合流 key=0 含 3 握手包+1 数据包，~20 个字段被算成假冲突）。
    仅当混合流（有载荷+无载荷共存）且发生同键碰撞时剔除；纯元数据信道（全流无载荷）不动。
    """
    with_pay = [p for p in packets if p["payload"]]
    no_pay = [p for p in packets if not p["payload"]]
    if not with_pay or not no_pay:
        return packets, []
    def kof(p):
        if key_field:
            return field_value(key_field, p)
        return eval(key_expr, eval_namespace(p))  # noqa: S307 - 受限名字空间
    pay_keys = {kof(p) for p in with_pay}
    colliding = [p for p in no_pay if kof(p) in pay_keys]
    if not colliding:
        return packets, []
    drop_ids = {id(p) for p in colliding}
    return [p for p in packets if id(p) not in drop_ids], colliding


def combine(op, values, width):
    mask = (1 << width) - 1
    if op == "xor":
        r = 0
        for v in values:
            r ^= v
        return r & mask
    if op == "add":
        return sum(values) & mask
    r = values[0]
    for v in values[1:]:
        r -= v
    return r & mask


def entropy(vals):
    if not vals:
        return 0.0
    c = Counter(vals)
    n = len(vals)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    ap = argparse.ArgumentParser(
        description="重复键字段冲突预言机：报告冲突字段 + 排名能消除冲突的算子组合（只报告不裁决）")
    ap.add_argument("pcap")
    ap.add_argument("--key-expr", help='受限 eval 逻辑键表达式，如 "(tsval>>8)&0xff"（字段名点号写成 __，如 tsval__n0）')
    ap.add_argument("--key", help="单字段简写，如 seq / ipid / tsval")
    ap.add_argument("--fields", help="逗号分隔字段子集（缺省全量）：pay.hi pay.lo pay[i] tsval[.n0..7] seq[.n0..7] ack[.n0..7] sport dport ipid ttl win flags len pkt")
    ap.add_argument("--stream", help='选流 "srcip:srcport->dstip:dstport"（缺省全量；多流时跨流键碰撞会污染冲突集，强烈建议选流）')
    ap.add_argument("--keep-empty", action="store_true",
                    help="保留与数据包同键的无载荷包（握手/纯 ACK）。缺省自动剔除并告警（T-A2#1）")
    ap.add_argument("--top", type=int, default=10, help="排名输出条数（默认 10）")
    ap.add_argument("--json", metavar="@out.json", help="完整结果写 JSON 文件")
    args = ap.parse_args()

    if bool(args.key_expr) == bool(args.key):
        raise SystemExit("[!] --key-expr 与 --key 必须二选一")

    packets = list(iter_tcp(args.pcap))
    if not packets:
        raise SystemExit("[!] 未解析到任何 TCP 包")

    # ---- 选流（T-A1#1：跨流键碰撞污染冲突集） ----
    flows = {}
    for p in packets:
        a, b = f"{p['src']}:{p['sport']}", f"{p['dst']}:{p['dport']}"
        flows.setdefault(tuple(sorted((a, b))), []).append(p)
    if args.stream:
        a, _, b = args.stream.partition("->")
        fkey = tuple(sorted((a.strip(), b.strip())))
        if fkey not in flows:
            raise SystemExit(f"[!] 流 {args.stream} 不存在；现有流: "
                             + ", ".join(f"{x}<->{y}({len(v)})" for (x, y), v in flows.items()))
        packets = flows[fkey]
        print(f"[i] 选流 {fkey[0]} <-> {fkey[1]}  包数 {len(packets)}")
    elif len(flows) > 1:
        print(f"[!] 检测到 {len(flows)} 条 TCP 流，跨流键碰撞会污染冲突集——建议 --stream 选流：",
              file=sys.stderr)
        for (x, y), v in sorted(flows.items(), key=lambda kv: -len(kv[1]))[:5]:
            print(f"      {x}<->{y} ({len(v)} 包)", file=sys.stderr)

    no_ts = sum(1 for p in packets if p["tsval"] is None)
    if no_ts:
        print(f"[!] {no_ts}/{len(packets)} 个 TCP 包无 TS option，tsval 字段按 0 处理", file=sys.stderr)

    if args.fields:
        fields = [f.strip() for f in args.fields.split(",") if f.strip()]
        for f in fields:
            try:
                field_width(f)
            except KeyError:
                raise SystemExit(f"[!] 未知字段: {f}")
    else:
        fields = list(STATIC_FIELDS)

    if args.keep_empty:
        dropped_empty = []
    else:
        packets, dropped_empty = drop_key_colliding_empty(packets, args.key_expr, args.key)
    if dropped_empty:
        print(f"[!] {len(dropped_empty)} 个无载荷包（握手/纯 ACK）与数据包同键——已剔除"
              f"（防假冲突污染）；要保留用 --keep-empty")

    groups = parse_keys(packets, args.key_expr, args.key)
    dups = {k: v for k, v in groups.items() if len(v) >= 2}

    print(f"== 冲突预言机 == {args.pcap}")
    print(f"TCP 包 {len(packets)} 个，逻辑键 {len(groups)} 个，重复键 {len(dups)} 个")
    print(f"key 定义: {args.key_expr or args.key}   字段池 {len(fields)} 个: {','.join(fields)}")

    # ---- 冲突检测 ----
    conflicts = {}  # field -> {key: [取值...]}
    for f in fields:
        per_key = {}
        for k, idxs in dups.items():
            vals = [field_value(f, packets[i]) for i in idxs]
            if len(set(vals)) > 1:
                per_key[k] = vals
        if per_key:
            conflicts[f] = per_key

    print("\n-- 重复键冲突字段 --")
    if not conflicts:
        print("  （无：所有字段在重复键上取值一致——单字段即可作明文候选，或 key 没有打到重复包）")
    for f, per_key in sorted(conflicts.items(), key=lambda kv: -len(kv[1])):
        ks = ", ".join(f"{k}:[{','.join(hex(v) for v in vs)}]" for k, vs in sorted(per_key.items()))
        print(f"  {f:<12} 冲突键 {len(per_key)}/{len(dups)}: {ks}")
    if conflicts:
        print("  ⇒ 这些字段大概率不是明文本身；明文可能是 ≥2 字段的复合函数")
        print("  ⇒ 注意：真实抓包中重传载荷可合法不同——冲突是假设生成器，不是排除器（key 设计是你的责任）")
        # ---- 联动判定（T-A6 核心：确定函数 × 同键冲突 ⇒ XOR 抵消项） ----
        print("\n-- 联动判定（确定函数 × 同键冲突） --")
        for f in conflicts:
            print(f"  {f}: 在 {len(conflicts[f])}/{len(dups)} 个重复键上冲突")
        print("  ⇒ 冲突字段若在非重复键上是键的确定函数（可用简单式拟合），它不是'无信息'，")
        print("    而是复合值的 XOR/ADD **抵消项**——必须纳入组合，禁止剔除。")
        print("    （判例：某载荷低位字段被判为 pure f(k) 剔除后，>2e5 手搓候选全部不在解空间）")

    # ---- 算子组合排名 ----
    # 修复假设必须含 ≥1 个冲突字段：纯由一致字段组成的组合与"消除冲突"无关
    # （例如 tsval.n3 是 key 的纯函数，天然一致，但不是明文修复）。
    results = []
    degenerate = []  # 含逐包唯一宽字段的组合：消除冲突是平凡结果，单列（T-A1#2）
    trivial = []  # 全流常量组合：平凡消除，单列
    if dups:
        pool = list(fields)
        if conflicts:
            conf_set = set(conflicts)
        vals_cache = {f: [field_value(f, p) for p in packets] for f in fields}
        # 逐包唯一宽字段：宽度≥16 且 >90% 包取值互不相同（整 tsval/seq/ack/pkt 之类）
        uniqueish = {f for f in fields
                     if field_width(f) >= 16
                     and len(set(vals_cache[f])) > 0.9 * len(packets)}
        for arity in (1, 2, 3):
            for combo in itertools.combinations(pool, arity):
                if conflicts and not any(f in conf_set for f in combo):
                    continue
                w = max(field_width(f) for f in combo)
                ops = ("xor",) if arity == 1 else OPS
                for op in ops:
                    stream = [combine(op, [vals_cache[f][i] for f in combo], w)
                              for i in range(len(packets))]
                    solved = sum(1 for idxs in dups.values()
                                 if len({stream[i] for i in idxs}) == 1)
                    if len(set(stream)) == 1:
                        trivial.append((op, combo))
                        continue
                    row = (solved, entropy(stream), op, combo)
                    if any(f in uniqueish for f in combo):
                        degenerate.append(row)
                    else:
                        results.append(row)

    note = "（只列含 ≥1 冲突字段的修复组合）" if conflicts else ""
    print(f"\n-- 算子组合排名（消除重复键数 desc, 结果流熵 desc{note}；重复键共 {len(dups)} 个） --")
    # T-A1#3：真解是数据样高熵；低熵偏好会把真解压出 top——熵降序
    results.sort(key=lambda r: (-r[0], -r[1]))
    shown = results[:args.top]
    full = [r for r in results if dups and r[0] == len(dups)]
    for solved, ent, op, combo in shown:
        mark = "  ★消除全部冲突" if dups and solved == len(dups) else ""
        print(f"  {op}({', '.join(combo)})  消除 {solved}/{len(dups)}  熵 {ent:.3f}{mark}")
    if degenerate:
        degenerate.sort(key=lambda r: (-r[0], -r[1]))
        print(f"\n-- 退化组合（含逐包唯一宽字段 {sorted(uniqueish)}，"
              "消除冲突是平凡结果，不参与主排名） --")
        for solved, ent, op, combo in degenerate[:5]:
            print(f"  {op}({', '.join(combo)})  消除 {solved}/{len(dups)}  熵 {ent:.3f}")
        if len(degenerate) > 5:
            print(f"  …另 {len(degenerate) - 5} 条")
    if trivial:
        print(f"  （另 {len(trivial)} 个全流常量组合平凡消除所有冲突，不列入排名，如 "
              + ", ".join(f"{op}({','.join(c)})" for op, c in trivial[:5]) + "…）")
    if dups and not full:
        print("  [!] 无消除全部冲突的非退化组合——注意：真复合不一定消除冲突")
        print("      （判例：冲突由重生字段携带时，真组合继承冲突，消不动；")
        print("       该走下面的『铺轴 + oracle 过滤』处方，不是调大 --top 死磕排名）")
    print("\n只报告不裁决：消除冲突 ≠ 就是明文；命中组合交给 decode_engine.py + oracle 验证。")

    # ---- 冲突诊断 + 下一步处方（可照抄；不执行须 ledger 落账理由） ----
    if dups and conflicts:
        # 重生字段诊断：tsval/ipid/pkt 在重传或时间戳重生时合法变化，
        # 其余字段全部一致 ⇒ 冲突是载体噪声，重复键取第一次出现即可，无需字段级修复
        REGEN = {"tsval", "pkt", "ipid"} | {f"tsval.n{i}" for i in range(8)}
        if set(conflicts) <= REGEN:
            print("\n-- 冲突诊断 --")
            print("  冲突全部由重传/时间戳重生字段携带（tsval/pkt/ipid），其余字段在重复键上一致")
            print("  ⇒ 重复键取第一次出现即可（decode_engine 键化去重已自动处理）；")
            print("  ⇒ 明文若是含重生字段的复合函数，冲突天然存在——不要试图'修掉'它。")
    if dups:
        print("\n-- 下一步（照抄执行，或 ledger.py --note 落账不执行的理由） --")
        key_arg = f"--key-expr \"{args.key_expr}\"" if args.key_expr else f"--key {args.key}"
        stream_arg = f" --stream \"{args.stream}\"" if args.stream else ""
        if full:
            for solved, ent, op, combo in full[:3]:
                print(f"  python3 decode_engine.py {args.pcap}{stream_arg} {key_arg} \\")
                print(f"    --fields \"{','.join(combo)}\" --ops {op} --arity {len(combo)} \\")
                print(f"    --order index --order seq --order tsval --packing hi --packing lo \\")
                print(f"    --oracle sha256:<目标hash>   # 无 hash 用 prefix:/printable（弱）")
        else:
            # 排名不收敛 ⇒ 铺轴 + oracle 过滤：全部窄字段（≤8bit 非常量）喂 decode_engine
            pool = [f for f in fields
                    if field_width(f) <= 8 and len({field_value(f, p) for p in packets}) > 1]
            print("  排名不含真解时改走『铺轴 + oracle 过滤』（decode_engine 全交叉）：")
            print(f"  python3 decode_engine.py {args.pcap}{stream_arg} {key_arg} \\")
            print(f"    --fields \"{','.join(pool)}\" --ops xor --arity 1-3 \\")
            print(f"    --order index --order seq --order tsval --packing hi --packing lo \\")
            print(f"    --oracle sha256:<目标hash>   # 附件二进制有零引用置换表时加 --order perm:<表文件>")

    if args.json:
        out = {
            "file": args.pcap,
            "key": args.key_expr or args.key,
            "packets": len(packets),
            "keys": len(groups),
            "duplicate_keys": {str(k): v for k, v in dups.items()},
            "conflicts": {f: {str(k): v for k, v in pk.items()} for f, pk in conflicts.items()},
            "ranking": [
                {"op": op, "fields": list(combo), "keys_solved": s, "entropy": round(e, 6)}
                for s, e, op, combo in results[:max(args.top, 50)]
            ],
            "degenerate_combos": [
                {"op": op, "fields": list(combo), "keys_solved": s, "entropy": round(e, 6)}
                for s, e, op, combo in degenerate[:50]
            ],
            "trivial_constant_combos": len(trivial),
            "caveat": "冲突是假设生成器，不是排除器；真实重传载荷可合法不同",
        }
        with open(args.json.lstrip("@"), "w", encoding="utf-8") as fp:
            json.dump(out, fp, ensure_ascii=False, indent=2)
        print(f"[+] JSON 已写入 {args.json.lstrip('@')}")


if __name__ == "__main__":
    main()
