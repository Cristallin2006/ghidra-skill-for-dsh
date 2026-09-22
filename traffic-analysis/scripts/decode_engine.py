#!/usr/bin/env python
"""decode_engine.py - 声明式多轴全交叉解码引擎（oracle 硬门）。

明文候选 = OP(字段₁..字段₃) × 顺序(下标/seq/TS/外部置换表) × 打包(半字节 hi|lo)。
引擎对声明的轴做**全交叉**，每个候选交给 --oracle 裁决；命中即输出。

为什么 --oracle 是硬门：没有校验手段的全交叉只会产出几千个看似可打印的候选，
人工逐个看就是本引擎要消灭的行为。oracle 可以是 hash 常量（附件/题目给的 sha256）、
已知前缀（flag{ / PNG 魔数）、或可打印率（弱，会告警）。

用法：
  python decode_engine.py cap.pcap --key-expr "(tsval>>8)&0xff" \
      --fields pay.lo,tsval.n0,seq.n1 --ops xor --arity 3 \
      --order perm:perm.txt --packing hi --oracle sha256:<64hex> --json @out.json

出口码：0 命中；1 跑完无命中；2 硬门拒绝（无 oracle / 候选超预算 / 参数错）。
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conflict_oracle import OPS, combine, field_value, field_width, iter_tcp, parse_keys  # noqa: E402

MAX_PACK_WIDTH = 8


def parse_oracle(spec: str):
    """返回 (kind, payload, check_fn)。"""
    if spec.startswith("sha256:"):
        target = spec[7:].strip().lower()
        if len(target) != 64:
            raise SystemExit("[!] sha256 oracle 需要 64 位 hex")
        return ("sha256", target, lambda b: hashlib.sha256(b).hexdigest() == target)
    if spec.startswith("sha256-hex:"):
        target = spec[11:].strip().lower()
        if len(target) != 64:
            raise SystemExit("[!] sha256-hex oracle 需要 64 位 hex")
        return ("sha256-hex", target,
                lambda b: hashlib.sha256(b.hex().encode()).hexdigest() == target)
    if spec == "printable":
        print("[!] 警告：printable 是弱 oracle（>=95% 可打印即算命中），命中需人工复核", file=sys.stderr)
        return ("printable", None,
                lambda b: bool(b) and sum(1 for c in b if 32 <= c <= 126) >= len(b) * 0.95)
    if spec.startswith("prefix:"):
        try:
            pre = bytes.fromhex(spec[7:].strip())
        except ValueError:
            raise SystemExit("[!] prefix oracle hex 解析失败")
        if not pre:
            raise SystemExit("[!] prefix oracle 不能为空")
        return ("prefix", pre.hex(), lambda b: b.startswith(pre))
    raise SystemExit(f"[!] 未知 oracle: {spec}（支持 sha256: / sha256-hex: / printable / prefix:）")


def load_perm(spec: str):
    """perm:<文件>：空格/逗号/换行分隔的整数表。语义：perm[j] = 第 j 个输入元素在输出中的位置。"""
    path = spec[5:]
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    perm = [int(t, 0) for t in text.replace(",", " ").split()]
    if sorted(perm) != list(range(len(perm))):
        raise SystemExit(f"[!] 置换表 {path} 不是 0..{len(perm)-1} 的全排列")
    return perm


def order_stream(order, keyed):
    """keyed: [(key, packet)]（重复 key 已取第一次）。返回排序后的 [packet]。"""
    if order == "index":
        return [p for _k, p in sorted(keyed, key=lambda kp: kp[0])]
    if order == "seq":
        return [p for _k, p in sorted(keyed, key=lambda kp: kp[1]["seq"])]
    if order == "tsval":
        return [p for _k, p in sorted(keyed, key=lambda kp: kp[1]["tsval"] or 0)]
    if order == "identity":
        return [p for _k, p in keyed]
    if order.startswith("perm:"):
        perm = load_perm(order)
        ps = [p for _k, p in sorted(keyed, key=lambda kp: kp[0])]
        if len(perm) != len(ps):
            raise SystemExit(f"[!] 置换表长度 {len(perm)} != 流长度 {len(ps)}")
        out = [None] * len(ps)
        for j, dst in enumerate(perm):
            out[dst] = ps[j]
        return out
    raise SystemExit(f"[!] 未知 --order: {order}")


def pack_stream(values, width, packing):
    """width<=4 按半字节打包（hi=先到的半字节占高位）；否则每值取低 8 位直接成字节。"""
    if width <= 4:
        out = bytearray()
        it = iter(values)
        for a in it:
            b = next(it, 0)
            out.append(((a & 0xF) << 4) | (b & 0xF) if packing == "hi" else (a & 0xF) | ((b & 0xF) << 4))
        return bytes(out)
    return bytes(v & 0xFF for v in values)


def parse_arity(spec: str):
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        rng = range(int(lo), int(hi) + 1)
    else:
        rng = range(int(spec), int(spec) + 1)
    if not all(1 <= a <= 3 for a in rng):
        raise SystemExit("[!] --arity 只支持 1~3")
    return list(rng)


def main():
    ap = argparse.ArgumentParser(description="声明式多轴全交叉解码引擎（无 --oracle 拒绝开跑）")
    ap.add_argument("pcap")
    ap.add_argument("--key-expr", help='逻辑键表达式，如 "(tsval>>8)&0xff"')
    ap.add_argument("--key", help="单字段简写")
    ap.add_argument("--stream", help='选流 "srcip:srcport->dstip:dstport"（缺省包数最多的 TCP 流）')
    ap.add_argument("--fields", required=True, help="逗号分隔字段池（见 conflict_oracle.py）")
    ap.add_argument("--ops", default="xor,add,sub", help="逗号分隔，缺省 xor,add,sub")
    ap.add_argument("--arity", default="1-3", help="1、2、3 或区间 1-3（缺省 1-3）")
    ap.add_argument("--order", action="append", required=True,
                    help="index|seq|tsval|identity|perm:<文件>，可多次给")
    ap.add_argument("--packing", action="append", choices=["hi", "lo"], required=True,
                    help="半字节打包先后，可多次给")
    ap.add_argument("--oracle", help="sha256:<hex> | sha256-hex:<hex> | printable | prefix:<hex>（硬门，缺省拒绝）")
    ap.add_argument("--max-candidates", type=int, default=2_000_000)
    ap.add_argument("--json", metavar="@out.json", help="命中候选 + 覆盖矩阵写 JSON 文件")
    args = ap.parse_args()

    # ---- 硬门 ----
    if not args.oracle:
        print("[GATE] 缺少 --oracle，拒绝开跑（exit 2）", file=sys.stderr)
        print("没有校验手段的全交叉只会产出几千个看似可打印的候选——"
              "正是本引擎要消灭的行为。先找 oracle：附件/题目里的 hash 常量、"
              "flag 格式前缀、或 conflict_oracle.py 的一致性过滤。", file=sys.stderr)
        sys.exit(2)
    if bool(args.key_expr) == bool(args.key):
        print("[!] --key-expr 与 --key 必须二选一", file=sys.stderr)
        sys.exit(2)
    oracle_kind, oracle_payload, check = parse_oracle(args.oracle)

    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    for f in fields:
        try:
            field_width(f)
        except KeyError:
            print(f"[!] 未知字段: {f}", file=sys.stderr)
            sys.exit(2)
    ops = [o.strip() for o in args.ops.split(",") if o.strip()]
    for o in ops:
        if o not in OPS:
            print(f"[!] 未知 op: {o}（支持 {','.join(OPS)}）", file=sys.stderr)
            sys.exit(2)
    arities = parse_arity(args.arity)

    packets = list(iter_tcp(args.pcap))
    if not packets:
        print("[!] 未解析到任何 TCP 包", file=sys.stderr)
        sys.exit(2)

    # ---- 选流 ----
    flows = {}
    for p in packets:
        a, b = f"{p['src']}:{p['sport']}", f"{p['dst']}:{p['dport']}"
        key = tuple(sorted((a, b)))
        flows.setdefault(key, []).append(p)
    if args.stream:
        a, _, b = args.stream.partition("->")
        key = tuple(sorted((a.strip(), b.strip())))
        if key not in flows:
            print(f"[!] 流 {args.stream} 不存在；现有流: "
                  + ", ".join(f"{x}<->{y}({len(v)})" for x, y in [k for k in flows] for v in [flows[k]]),
                  file=sys.stderr)
            sys.exit(2)
    else:
        key = max(flows, key=lambda k: len(flows[k]))
    stream_pkts = flows[key]
    print(f"[i] 选流 {key[0]} <-> {key[1]}  包数 {len(stream_pkts)}"
          + ("（缺省取包数最多）" if not args.stream else ""))

    # ---- 键化 + 重复 key 取第一次出现 ----
    groups = parse_keys(stream_pkts, args.key_expr, args.key)
    keyed = [(k, stream_pkts[idxs[0]]) for k, idxs in groups.items()]
    n_dup = sum(1 for idxs in groups.values() if len(idxs) > 1)
    if n_dup:
        print(f"[i] {n_dup} 个重复 key 已取第一次出现（冲突分析走 conflict_oracle.py）")

    # ---- 轴矩阵 + 预算 ----
    combos = []
    for a in arities:
        for c in itertools.combinations(fields, a):
            cops = ("xor",) if a == 1 else tuple(o for o in ops)
            for o in cops:
                combos.append((o, c))
    total = len(combos) * len(args.order) * len(args.packing)
    print("-- 轴矩阵 --")
    print(f"  字段池({len(fields)}): {','.join(fields)}")
    print(f"  ops: {','.join(ops)}   arity: {arities}   组合数: {len(combos)}")
    print(f"  order: {args.order}   packing: {args.packing}")
    print(f"  oracle: {oracle_kind}   流长度: {len(keyed)}")
    print(f"  候选总数 = {len(combos)} × {len(args.order)} × {len(args.packing)} = {total}")
    if total > args.max_candidates:
        print(f"[GATE] 候选总数 {total} > --max-candidates {args.max_candidates}（exit 2）："
              "剪轴（缩字段池/arity/order）或加更强 oracle 后再来", file=sys.stderr)
        sys.exit(2)

    # ---- 全交叉（不提前剪枝） ----
    hits = []
    tried = 0
    for order in args.order:
        ordered = order_stream(order, keyed)
        for op, combo in combos:
            w = max(field_width(f) for f in combo)
            values = [combine(op, [field_value(f, p) for f in combo], w) for p in ordered]
            for packing in args.packing:
                tried += 1
                cand = pack_stream(values, min(w, MAX_PACK_WIDTH), packing)
                if check(cand):
                    hits.append({"op": op, "fields": list(combo), "order": order,
                                 "packing": packing, "hex": cand.hex(),
                                 "ascii": "".join(chr(c) if 32 <= c <= 126 else "." for c in cand)})
    print(f"[i] 全交叉完成：{tried}/{total} 候选，命中 {len(hits)}")

    if hits:
        print("\n-- 命中 --")
        for h in hits:
            print(f"  {h['op']}({', '.join(h['fields'])})  order={h['order']}  packing={h['packing']}")
            print(f"    hex:   {h['hex']}")
            print(f"    ascii: {h['ascii']}")
    else:
        print("无命中。轴声明没覆盖到真解——扩字段池/换顺序源（附件二进制零引用置换表？"
              "ghidra-core unreferenced_data.py）/换打包，或 oracle 本身不对。")

    if args.json:
        coverage = {
            "fields": fields,
            "ops": [o for o in ops],
            "arity": arities,
            "order": list(args.order),
            "packing": list(args.packing),
            "oracle": {"kind": oracle_kind, "value": oracle_payload},
            "stream": f"{key[0]} <-> {key[1]}",
            "stream_len": len(keyed),
            "candidates_tried": tried,
        }
        out = {"file": args.pcap, "coverage": coverage, "hits": hits}
        with open(args.json.lstrip("@"), "w", encoding="utf-8") as fp:
            json.dump(out, fp, ensure_ascii=False, indent=2)
        print(f"[+] JSON 已写入 {args.json.lstrip('@')}")
    sys.exit(0 if hits else 1)


if __name__ == "__main__":
    main()
