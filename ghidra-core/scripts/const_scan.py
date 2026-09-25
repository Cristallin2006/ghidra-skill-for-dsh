#!/usr/bin/env python
"""const_scan.py - rebuild Python constant literals from decompiled Cython C.

Host-side tool (any Python 3.8+, stdlib only). Pure local text scan - no
daemon needed. Motivation (CTF retro): in a Cython-compiled .so a Python list
literal such as L = [173, 7, 131, ...] is NOT a byte string in the binary; in
decompiled C it appears as PyList_New(0x30) followed by 48 constant writes
(PyLong_FromLong(<small int>) inline, or slot writes from the Cython cached
int-object pool, e.g. `puVar25[3] = DAT_00128fe0;`). Searching the .so for
the byte pattern `AD 07` is guaranteed to miss the table. This script
mechanically reconstructs those literals so the constant table is never lost
again.

Two detection modes per function:
  1. Literal rebuild: PyList_New(n) / PyTuple_New(n), then the next n
     constant items (PyLong_FromLong / PyLong_FromString / PyFloat_FromDouble
     / PyBytes_FromString(AndSize) / PyUnicode_FromString, or slot writes
     `ptr[i] = IDENT` / PyList_SET_ITEM / PyTuple_SET_ITEM) inside a window
     of n*4 lines, re-emitted as a Python list/tuple literal. Slot writes
     that reference globals (DAT_xxx) are reported as refs - resolve them via
     the mstate object pool / get_data_at_address to recover the values.
  2. Alert mode: even without PyList_New, >= --min-cluster PyLong_FromLong
     calls with values in 0..255 clustered in one function fire a
     "suspected byte-level constant table (padding table / S-box /
     permutation table)" warning listing the values in order.
PyBytes_FromString / Py_BuildValue call sites are also reported as leads.

Usage:
  python const_scan.py <decompiled.c | decompile-all @out JSON> [--json out.json]
  python const_scan.py chal.p3pf.clean.c --min-cluster 8
  python const_scan.py decompile_all_out.json --json report.json

Input is auto-detected: JSON containing result.functions[].c_code (or a
single result.c_code, or a top-level functions list) is treated as
decompile-all / decompile-function output; anything else is treated as plain
C text (decompile_all .c sidecar `/* ===== name @ addr ===== */` markers are
used to attribute functions when present).

Exit codes: 0 scan completed, 1 usage error (missing file / malformed input).
"""
from __future__ import annotations

import argparse
import json
import re
import sys

for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

LIST_NEW_RE = re.compile(r"\b(PyList_New|PyTuple_New)\s*\(\s*(0[xX][0-9a-fA-F]+|\d+)")
BYTES_RE = re.compile(r"\b(PyBytes_FromString(?:AndSize)?|PyUnicode_FromString(?:AndSize)?)"
                      r'\s*\(\s*"((?:[^"\\]|\\.)*)"')
BUILDVALUE_RE = re.compile(r'\bPy_BuildValue\s*\(\s*"((?:[^"\\]|\\.)*)"')

LONG_RE = re.compile(r"\bPyLong_FromLong(?:Long)?\s*\(\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*[lL]?\s*\)")
LONG_STR_RE = re.compile(r'\bPyLong_FromString\s*\(\s*"([^"]*)"\s*,\s*[^,]+,\s*(\d+)')
FLOAT_RE = re.compile(r"\bPyFloat_FromDouble\s*\(\s*(-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)")
UNICODE_RE = re.compile(r'\bPyUnicode_FromString(?:AndSize)?\s*\(\s*"((?:[^"\\]|\\.)*)"')
BYTES_ITEM_RE = re.compile(r'\bPyBytes_FromString(?:AndSize)?\s*\(\s*"((?:[^"\\]|\\.)*)"')

SET_ITEM_RE = re.compile(r"\b(PyList_SET_ITEM|PyTuple_SET_ITEM)\s*\("
                         r"\s*\w+\s*,\s*(0[xX][0-9a-fA-F]+|\d+)\s*,\s*([^;()]+?)\s*\)")
SLOT_WRITE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]"
                           r"\s*=\s*([A-Za-z_]\w*)\s*;")
DEREF_WRITE_RE = re.compile(r"^\s*\*\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;")
ALIAS_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;")

FUNC_MARKER_RE = re.compile(r"/\*\s*=+\s*(.+?)\s*@\s*([0-9a-fA-Fx]+)\s*=+\s*\*/")

PREVIEW_ITEMS = 16
CLUSTER_MAX_GAP = 8


def parse_int(token: str) -> int:
    return int(token, 16) if token.lower().startswith("0x") else int(token)


def c_unescape(s: str) -> str:
    """Best-effort C string unescape for display."""
    def rep(m):
        esc = m.group(1)
        table = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
        if esc.startswith("x"):
            try:
                return chr(int(esc[1:], 16))
            except ValueError:
                return "\\" + esc
        if esc.isdigit():
            try:
                return chr(int(esc, 8))
            except ValueError:
                return "\\" + esc
        return table.get(esc, "\\" + esc)
    return re.sub(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", rep, s)


def load_functions(path: str) -> tuple[str, list[dict]]:
    """Return (input_kind, [{name, address, c_code}])."""
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        result = data.get("result") if isinstance(data.get("result"), dict) else data
        if isinstance(result.get("functions"), list):
            funcs = [fn for fn in result["functions"]
                     if isinstance(fn, dict) and isinstance(fn.get("c_code"), str)]
            if funcs:
                return "json", [{"name": fn.get("name", "?"),
                                 "address": fn.get("address", "?"),
                                 "c_code": fn["c_code"]} for fn in funcs]
        if isinstance(result.get("c_code"), str):
            return "json", [{"name": result.get("name", "?"),
                             "address": result.get("address", "?"),
                             "c_code": result["c_code"]}]
        print(f"[错误] 输入是 JSON 但找不到 functions[].c_code / result.c_code: {path}",
              file=sys.stderr)
        sys.exit(1)
    # plain text: split on decompile_all .c sidecar markers when present
    lines = text.splitlines()
    funcs = []
    cur = {"name": "<whole-file>", "address": "?", "lines": []}
    for ln in lines:
        m = FUNC_MARKER_RE.search(ln)
        if m:
            if cur["lines"]:
                funcs.append(cur)
            cur = {"name": m.group(1), "address": m.group(2), "lines": []}
        else:
            cur["lines"].append(ln)
    if cur["lines"]:
        funcs.append(cur)
    return "text", [{"name": f["name"], "address": f["address"],
                     "c_code": "\n".join(f["lines"])} for f in funcs]


def match_const_item(line: str):
    """Return item dict if the line builds a constant, else None."""
    m = LONG_RE.search(line)
    if m:
        return {"kind": "int", "value": parse_int(m.group(1))}
    m = LONG_STR_RE.search(line)
    if m:
        try:
            return {"kind": "int", "value": int(m.group(1), int(m.group(2)))}
        except ValueError:
            return {"kind": "int", "value": None, "raw": m.group(1)}
    m = FLOAT_RE.search(line)
    if m:
        return {"kind": "float", "value": float(m.group(1))}
    m = BYTES_ITEM_RE.search(line)
    if m:
        return {"kind": "bytes", "value": c_unescape(m.group(1))}
    m = UNICODE_RE.search(line)
    if m:
        return {"kind": "str", "value": c_unescape(m.group(1))}
    return None


def collect_items(lines: list[str], start: int, n: int):
    """Collect up to n items from lines[start : start + window]."""
    items = []
    # Cython expands each item to ~5 lines (INCREF check + slot write), so
    # n*4 is not enough in the wild; n*8 covers the pooled-constant pattern.
    end = min(len(lines), start + max(n * 8, 64))
    alias: dict[str, str] = {}

    def resolve(name: str) -> str:
        seen = set()
        while name in alias and name not in seen:
            seen.add(name)
            name = alias[name]
        return name

    for i in range(start, end):
        if len(items) >= n:
            break
        line = lines[i]
        m = ALIAS_RE.match(line)
        if m and m.group(1) != m.group(2):
            alias[m.group(1)] = resolve(m.group(2))
            continue
        item = match_const_item(line)
        if item is not None:
            item["line"] = i + 1
            items.append(item)
            continue
        m = SET_ITEM_RE.search(line)
        if m:
            expr = m.group(3).strip()
            inner = match_const_item(expr)
            if inner is None:
                inner = {"kind": "ref", "name": resolve(expr)}
            inner["index"] = parse_int(m.group(2))
            inner["line"] = i + 1
            items.append(inner)
            continue
        m = SLOT_WRITE_RE.search(line)
        if m:
            items.append({"kind": "ref", "name": resolve(m.group(3)),
                          "index": parse_int(m.group(2)), "line": i + 1})
            continue
        m = DEREF_WRITE_RE.match(line)
        if m:
            items.append({"kind": "ref", "name": resolve(m.group(2)),
                          "index": 0, "line": i + 1})
    # de-dup by (index) keeping code order; sort by index when indices exist
    if any("index" in it for it in items):
        seen = set()
        uniq = []
        for it in items:
            key = it.get("index")
            if key in seen:
                continue
            seen.add(key)
            uniq.append(it)
        items = sorted(uniq, key=lambda it: it.get("index", 0))
    return items


def render_literal(items: list[dict], kind: str, limit: int | None = None):
    shown = items if limit is None else items[:limit]

    def fmt(it):
        if it["kind"] == "ref":
            return "<%s>" % it["name"]
        if it["kind"] == "bytes":
            return "b%r" % it["value"]
        if it["kind"] == "str":
            return repr(it["value"])
        return repr(it.get("value"))

    body = ", ".join(fmt(it) for it in shown)
    if limit is not None and len(items) > limit:
        body += ", ..."
    open_c, close_c = ("(", ")") if kind == "tuple" else ("[", "]")
    return open_c + body + close_c


def scan_function(fn: dict, min_cluster: int):
    c_code = fn["c_code"]
    lines = c_code.splitlines()
    literals = []
    leads = []
    consumed_lines = set()

    for i, line in enumerate(lines):
        m = LIST_NEW_RE.search(line)
        if not m:
            continue
        kind = "list" if m.group(1) == "PyList_New" else "tuple"
        n = parse_int(m.group(2))
        items = collect_items(lines, i + 1, n)
        for it in items:
            consumed_lines.add(it["line"])
        n_ref = sum(1 for it in items if it["kind"] == "ref")
        note = None
        if items and n_ref == len(items):
            note = ("全部列表项来自缓存全局对象（Cython int 对象池 / mstate）——"
                    "对 ref 名做 xref 或在模块 init 函数里找对应 PyLong_FromLong 初始化")
        elif n_ref:
            note = f"{n_ref}/{len(items)} 项是全局对象引用，需到对象池解析"
        literals.append({
            "function": fn["name"], "address": fn["address"],
            "kind": kind, "declared_len": n, "found_len": len(items),
            "line": i + 1, "complete": len(items) >= n,
            "preview": render_literal(items, kind, PREVIEW_ITEMS),
            "literal": render_literal(items, kind, None),
            "items": items, "note": note,
        })

    for i, line in enumerate(lines):
        m = BYTES_RE.search(line)
        if m and (i + 1) not in consumed_lines:
            leads.append({"function": fn["name"], "line": i + 1,
                          "call": m.group(1), "value": c_unescape(m.group(2))[:80]})
        m = BUILDVALUE_RE.search(line)
        if m:
            leads.append({"function": fn["name"], "line": i + 1,
                          "call": "Py_BuildValue", "format": m.group(1)})

    # alert mode: clustered small-int PyLong_FromLong not consumed by literals
    hits = []
    for i, line in enumerate(lines):
        if (i + 1) in consumed_lines:
            continue
        m = LONG_RE.search(line)
        if m:
            v = parse_int(m.group(1))
            if 0 <= v <= 255:
                hits.append((i + 1, v))
    clusters = []
    cur = []
    for ln, v in hits:
        if cur and ln - cur[-1][0] > CLUSTER_MAX_GAP:
            clusters.append(cur)
            cur = []
        cur.append((ln, v))
    if cur:
        clusters.append(cur)
    alerts = []
    for cl in clusters:
        if len(cl) >= min_cluster:
            alerts.append({
                "function": fn["name"], "kind": "byte_cluster",
                "count": len(cl), "values": [v for _, v in cl],
                "first_line": cl[0][0], "last_line": cl[-1][0],
            })
    return literals, leads, alerts


def main() -> int:
    ap = argparse.ArgumentParser(
        description="从 Cython 反编译 C 重建 Python 常量字面量（列表/元组/bytes），"
                    "并对疑似字节级常量表（填充表/S盒/置换表）告警")
    ap.add_argument("input", help="反编译 C 文本，或 decompile-all/decompile-function 的 @out JSON")
    ap.add_argument("--json", dest="json_out", default=None, help="把完整报告写入 JSON 文件")
    ap.add_argument("--min-cluster", type=int, default=8,
                    help="告警模式：同一聚集内 0..255 小整数 PyLong_FromLong 的最少个数（默认 8）")
    args = ap.parse_args()

    try:
        input_kind, funcs = load_functions(args.input)
    except OSError as e:
        print(f"[错误] 无法读取输入: {e}", file=sys.stderr)
        return 1

    all_literals, all_leads, all_alerts = [], [], []
    for fn in funcs:
        literals, leads, alerts = scan_function(fn, args.min_cluster)
        all_literals.extend(literals)
        all_leads.extend(leads)
        all_alerts.extend(alerts)

    report = {
        "input": args.input, "input_kind": input_kind,
        "functions_scanned": len(funcs),
        "literals": all_literals, "leads": all_leads, "alerts": all_alerts,
    }

    print(f"[const_scan] 输入: {args.input}（{input_kind}），扫描函数 {len(funcs)} 个")
    print()

    if all_literals:
        print(f"════ 重建出的常量字面量（{len(all_literals)} 处）════")
        for lit in all_literals:
            state = "完整" if lit["complete"] else f"部分（{lit['found_len']}/{lit['declared_len']}）"
            print(f"  · {lit['kind']} × {lit['declared_len']}  [{state}]  "
                  f"函数 {lit['function']} @ {lit['address']}，PyList/PyTuple_New 在第 {lit['line']} 行")
            print(f"    预览: {lit['preview']}")
            if lit["note"]:
                print(f"    注意: {lit['note']}")
        print()
    else:
        print("════ 未发现 PyList_New/PyTuple_New 常量构造点 ════")
        print()

    if all_alerts:
        print(f"════ 疑似字节级常量表告警（{len(all_alerts)} 处）════")
        print("  （填充表 / S盒 / 置换表特征：函数内聚集的小整数 PyLong_FromLong；")
        print("    Cython 会把列表常量炸成 int 对象，按字节模式搜 .so 必然搜不到）")
        for al in all_alerts:
            vals = ", ".join(str(v) for v in al["values"][:32])
            more = " ..." if al["count"] > 32 else ""
            print(f"  · 函数 {al['function']}：{al['count']} 个 0..255 常量"
                  f"（第 {al['first_line']}..{al['last_line']} 行）")
            print(f"    值: [{vals}{more}]")
        print()

    if all_leads:
        print(f"════ 其他常量线索（PyBytes_FromString / PyUnicode / Py_BuildValue，{len(all_leads)} 处）════")
        for lead in all_leads[:20]:
            extra = lead.get("value", lead.get("format", ""))
            print(f"  · {lead['call']}  函数 {lead['function']} 第 {lead['line']} 行: {extra!r}")
        if len(all_leads) > 20:
            print(f"  ... 其余 {len(all_leads) - 20} 条见 --json 报告")
        print()

    print(f"[结论] 字面量 {len(all_literals)} 处，告警 {len(all_alerts)} 处，线索 {len(all_leads)} 条。"
          "全量值在 --json 报告里。")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[const_scan] JSON 报告已写入: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
