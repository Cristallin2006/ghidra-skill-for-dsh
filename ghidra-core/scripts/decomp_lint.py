#!/usr/bin/env python
"""decomp_lint.py - mechanical "physical exam" for decompiled pseudocode.

Host-side tool (any Python 3.8+, stdlib only). Runs BEFORE reading any
pseudocode: mechanically screens out untrustworthy decompiler output so the
agent never quotes poisoned C as evidence. Two verdicts:

  - fatal functions: pseudocode must NOT be quoted (jumptable not recovered,
    indirect JMP rendered as CALL, too many branches, ...). Read the bytes
    and decode rel32 tables by hand instead.
  - render traps: literals at those spots are untrustworthy (vectorized
    auVar rendering, CONCAT/SUB16 splits, small integers rendered as
    &DAT_0000xxxx addresses, ...) and must be cross-checked against bytes.

Usage:
  python rpc_driver.py @out/all.c decompile-all <bin>
  python decomp_lint.py out/all.c [--json out/lint.json] [--top 40]
  python decomp_lint.py some_plain.c        # non-JSON input: whole-file scan

Exit codes: 0 no fatal functions, 1 usage error,
2 fatal functions found (read stdout; do not quote their pseudocode).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter

for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# 反编译器告警 → 严重级（fatal=该函数伪码不可直接引用；warn=需抽查；info=备注）
WARNINGS = [
    ("Could not recover jumptable", "fatal", "跳转表未恢复：必须读表字节手工解 rel32"),
    ("Treating indirect jump as call", "fatal", "间接 JMP 被渲染成 CALL：语义错误"),
    ("Too many branches", "fatal", "分支过多未恢复：同上"),
    ("Removing unreachable block", "warn", "不可达块被删：可能有死代码/混淆"),
    ("Subroutine does not return", "info", "noreturn 桩（通常是 panic）"),
    ("unrecognized", "fatal", "指令未识别"),
]

# 危险渲染：出现即表示"该处的字面值不可信，必须回字节核对"
RENDER_TRAPS = [
    (r"\bauVar\d+", "向量化渲染：按语义读，勿按字面"),
    (r"\bSUB16\d\d?\(", "位域/向量拆分：字面值不可信"),
    (r"\bSUB8[14]\(", "字节拆分：字面值不可信"),
    (r"CONCAT\d\d?\(", "拼接渲染：字面值不可信"),
    (r"&DAT_0000[0-9a-f]{4}\b", "小整数量被渲染成地址（长度/常量漂移高发）"),
    (r"\(\.\.\.\)\(&DAT_\w+ \+ \*\(int \*\)", "未恢复跳转表调用点"),
    (r"-\s*\(\s*\w+\s*==\s*'", "字节比较向量化：语义是 memcmp，非取负"),
    (r"\bundefined\d?\b", "类型未恢复（噪声，修类型后应消失）"),
]

MAXLEN_RE = re.compile(r"memcpy\([^;]*?,\s*0x([0-9a-f]+)\)", re.I)


def lint(text):
    rows = []
    for name, sev, why in WARNINGS:
        n = text.count(name)
        if n:
            rows.append((sev, name, n, why))
    return rows


def traps(text):
    out = []
    for pat, why in RENDER_TRAPS:
        n = len(re.findall(pat, text))
        if n:
            out.append((pat, n, why))
    return out


def load_functions(path):
    """decompile-all JSON -> function list; 非 JSON 输入降级为整体单块扫描。"""
    text = open(path, encoding="utf-8", errors="replace").read()
    try:
        funcs = json.loads(text)["result"]["functions"]
        if isinstance(funcs, list):
            return funcs, "json"
    except (ValueError, KeyError, TypeError):
        pass
    return [{"address": "-", "name": "<whole-file>", "c_code": text}], "text"


def main():
    ap = argparse.ArgumentParser(
        description="反编译伪码体检器：fatal 函数清单 + 危险渲染计数")
    ap.add_argument("allc", help="decompile-all 的 @out JSON，或任意 .c 文本")
    ap.add_argument("--json", help="JSON 报告输出路径")
    ap.add_argument("--top", type=int, default=40, help="fatal 清单最多打印条数")
    a = ap.parse_args()

    funcs, mode = load_functions(a.allc)
    if mode == "text":
        print("[提示] 输入不是 decompile-all JSON，已降级为整体单块扫描。")
    print("函数总数: %d" % len(funcs))

    sev_rank = {"fatal": 0, "warn": 1, "info": 2}
    per = []
    gcount = Counter()
    gtraps = Counter()
    for f in funcs:
        c = f.get("c_code") or ""
        w = lint(c)
        t = traps(c)
        for s, n, cnt, _ in w:
            gcount[n] += cnt
        for pat, cnt, _ in t:
            gtraps[pat] += cnt
        if w:
            worst = min(sev_rank[s] for s, _, _, _ in w)
            per.append((worst, f["address"], f["name"], len(c), w, t))

    print("\n=== 全样本告警汇总 ===")
    for n, cnt in gcount.most_common():
        sev = next(s for k, s, _ in WARNINGS if k == n)
        print("  [%-5s] %-34s %d" % (sev, n, cnt))

    fatal = [p for p in per if p[0] == 0]
    print("\n=== fatal 函数（伪码不可直接引用）: %d / %d ===" % (len(fatal), len(funcs)))
    for _, addr, name, sz, w, _ in sorted(fatal)[: a.top]:
        tags = ",".join(n for s, n, _, _ in w if s == "fatal")
        print("  %s  %-14s size=%-6d %s" % (addr, name, sz, tags))

    print("\n=== 危险渲染计数（字面值必须回字节核对）===")
    for pat, cnt in gtraps.most_common():
        why = next(w for p, w in RENDER_TRAPS if p == pat)
        print("  %-46s %-6d %s" % (pat[:46], cnt, why))

    if a.json:
        json.dump(
            {
                "functions": len(funcs),
                "warnings": dict(gcount),
                "render_traps": dict(gtraps),
                "fatal_functions": [
                    {"address": ad, "name": nm, "size": sz,
                     "warnings": [n for _, n, _, _ in w]}
                    for _, ad, nm, sz, w, _ in sorted(fatal)
                ],
            },
            open(a.json, "w", encoding="utf-8"), indent=2, ensure_ascii=False,
        )
        print("\nJSON -> %s" % a.json)

    if fatal:
        print("\n[结论] 存在 %d 个 fatal 函数：这些伪码不可直接引用，回字节核对。" % len(fatal))
        return 2
    print("\n[结论] 无 fatal 函数；注意上方危险渲染计数处仍需回字节核对。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
