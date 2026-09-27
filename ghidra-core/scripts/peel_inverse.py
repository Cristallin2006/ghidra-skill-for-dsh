#!/usr/bin/env python
"""peel_inverse.py - 掩码依赖图 + 滞后-k 可剥离递推判定（铁律 6 工具形态：先剥离，再考虑 z3/SMT）。

Host-side tool (any Python 3.8+, stdlib only; 纯本地文件工具，不经 daemon)。

依据（858e13b3 复盘 §5.4 / Reverse-chal 实测）：ARX 链的 8 个 32 位掩码满足二阶
递推  mask_i = (mask_{i-2} + F_i(mask_{i-1})) & 0xffffffff，F_i 只依赖更早掩码与
常量 ⇒ 从已知的两个末端掩码逐层反解  mask_{i-2} = (mask_i - F_i(mask_{i-1})) & mask，
完全不需要 SMT。本脚本在 ssa_reconstruct 产出的直线程序上把这种"滞后-2 递推段"
检出来；检不出干净结构时才放行 z3/SMT（或先做 S-box 反查/常量折叠）。

用法: peel_inverse.py <recon.txt> [--min-run N]
  <recon.txt> 为 ssa_reconstruct.py --out 的直线程序；
  --min-run 为判定为递推段的最少连续掩码数（默认 4）。
exit: 0 判定完成（发现/未发现可剥离段都是正常结论，看 stdout 判词）; 2 用法/输入文件错误。
"""
from __future__ import annotations

import argparse
import re
import sys

for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

DEF_BIN = re.compile(r"^(\w+) = \((.*)\) ([-+*^&|<>%/]+) \((.*)\)$")
DEF_CALL = re.compile(r"^(\w+) = (\w+)\((.*)\)$")
MASK_LITERALS = ("4294967295", "0xffffffff")


def direct_mask_deps(name, defs, masks, acc=None, seen=None):
    """展开表达式树，遇到**其它掩码变量**就当叶子记下并停止展开（只算直接依赖）。"""
    acc = set() if acc is None else acc
    seen = set() if seen is None else seen
    if name in seen or name not in defs:
        return acc
    seen.add(name)
    a, _op, b = defs[name]
    for tok in (a, b):
        if not tok or tok.isdigit():
            continue
        if tok in masks and tok != name:
            acc.add(tok)          # 叶子：不再展开
        else:
            direct_mask_deps(tok, defs, masks, acc, seen)
    return acc


def main():
    ap = argparse.ArgumentParser(prog="peel_inverse.py")
    ap.add_argument("recon", help="ssa_reconstruct.py --out 的直线程序")
    ap.add_argument("--min-run", type=int, default=4,
                    help="判定为递推段的最少连续掩码数（默认 4）")
    args = ap.parse_args()

    try:
        with open(args.recon, encoding="utf-8") as fh:
            src = [l.strip() for l in fh if l.strip()]
    except OSError as e:
        print("recon 读取失败: %s" % e, file=sys.stderr)
        return 2

    defs = {}
    for ln in src:
        m = DEF_BIN.match(ln)
        if m:
            defs[m.group(1)] = (m.group(2), m.group(3), m.group(4))
            continue
        m = DEF_CALL.match(ln)
        if m:
            defs[m.group(1)] = (m.group(3), m.group(2), None)

    masks = [n for n, (a, op, b) in defs.items()
             if op == "&" and b in MASK_LITERALS]
    print("掩码变量（& 0xffffffff）: %d" % len(masks))
    if not masks:
        print("可剥离判定: 无掩码变量——输入不是含 & 0xffffffff 的直线程序？"
              "先跑 ssa_trace.py -> ssa_reconstruct.py。")
        return 0

    dep_masks = {m: direct_mask_deps(defs[m][0], defs, masks) for m in masks}
    print("掩码间依赖:")
    for m in masks:
        ds = sorted(dep_masks[m], key=masks.index)
        print("   %-10s <- %s" % (m, ds if ds else "(无其它掩码，含种子/常量)"))

    # 找「滞后-2 递推段」：连续若干掩码，第 i 个恰好依赖前两个
    runs, cur = [], []
    for i, m in enumerate(masks):
        if i >= 2 and dep_masks[m] == {masks[i - 1], masks[i - 2]}:
            if not cur:
                cur = [masks[i - 2], masks[i - 1]]
            cur.append(m)
        else:
            if len(cur) >= args.min_run:
                runs.append(cur)
            cur = []
    if len(cur) >= args.min_run:
        runs.append(cur)

    print()
    print("可剥离判定:")
    if runs:
        for r in runs:
            print("   滞后-2 递推段 (%d 项): %s" % (len(r), " -> ".join(r)))
            print("      => mask_{i-2} = (mask_i - F_i(mask_{i-1})) & 0xffffffff，"
                  "从段末两个已知掩码逐层反解，无需 z3/SMT")
    else:
        print("   未发现干净的滞后-2 结构 ⇒ 再考虑 z3/SMT"
              "（或先做 S-box 反查/常量折叠）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
