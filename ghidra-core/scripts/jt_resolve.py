#!/usr/bin/env python
"""jt_resolve.py - 跳转表一键解析（happyVm 复盘 §9.6）。

Host-side tool (any Python 3.8+, stdlib only). 伪码只暴露部分表基址，
且两张表共用一个索引时「只解一张 = 解错一半」——本工具把函数内所有
候选表基址全部找出、全部解码、全部列出，不允许只报一张。

候选线索（三路并集，去重）:
  a) 反汇编 LEA Rxx,[0x........]，随后 10 条指令内出现 [Rxx + Ryy*0x4]
     索引读或 JMP Rxx；
  b) decompile 警告 "Could not recover jumptable at 0x........"（记入汇总，
     证明该函数确有未恢复表）；
  c) 伪码残留的 "&DAT_00xxxxxxxx + idx * 4" 渲染（基址直接可读）。

每个候选基址用 read-bytes 读 N 项（默认 32，且不越过下一个候选基址，
防止相邻表互相吞并），按 rel32（target = base + s32(entry)）与绝对地址
两种模式解码并择优；target 用 basic-blocks 块起始 + 函数地址范围交叉
验证：落块 / 落指令 / 落间隙（未反汇编的 case 体，符合预期）/ 越界，
连续 2 项越界 = 表结束信号。

Usage:
  python rpc_driver.py ensure <binary>          # daemon 未起时先 ensure
  python jt_resolve.py <binary> <func-addr> [--table-bits 32] [--json out]

Exit codes: 0 至少解析出一张表, 1 usage error, 2 无可解析表,
3 daemon 不可达（先 ensure）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

RPC_DRIVER = Path(__file__).resolve().parent / "rpc_driver.py"
PAGE = 1000  # disassemble --count 上限


class RpcError(Exception):
    def __init__(self, message, daemon=False):
        super().__init__(message)
        self.daemon = daemon


def rpc_call(binary, command, *args, timeout=300):
    """subprocess 调同目录 rpc_driver.py；@out 落临时文件再读 JSON
    （铁律 3：大输出必须落文件，不走 stdout 管道）。"""
    fd, out = tempfile.mkstemp(prefix="dsh_jt_", suffix=".json")
    os.close(fd)
    cmd = [sys.executable, str(RPC_DRIVER), "@" + out, command, str(binary)]
    cmd += [str(a) for a in args]
    proc = None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = Path(out).read_text(encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        raise RpcError("rpc_driver 调用超时（%ds），daemon 可能未就绪" % timeout, True)
    except OSError as e:
        raise RpcError("rpc_driver 调用失败: %s" % e, True)
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
    if not raw.strip():
        tail = (((proc.stderr or "") + (proc.stdout or "")).strip()[:400]
                if proc else "")
        raise RpcError("rpc_driver 无 JSON 输出。%s" % tail, True)
    try:
        data = json.loads(raw)
    except ValueError:
        raise RpcError("rpc_driver 输出不是 JSON: %s" % raw[:300], True)
    if not data.get("ok"):
        blob = json.dumps(data, ensure_ascii=False)
        daemon = any(k in blob for k in ("auto-ensure", "NotRunning", "daemon",
                                         "load failed", "binary not found"))
        raise RpcError("%s 失败: %s" % (command, data.get("message")
                                        or data.get("error")), daemon)
    return data.get("result") or {}


def fetch_function(binary, func):
    """basic-blocks 定函数范围 + 分页 disassemble（--count 上限 1000）。
    请求地址落入未反汇编间隙时 daemon 首行给 '; WARNING' 并自动前跳到
    下一条已定义指令，分页指针按实际返回推进，天然兼容该回退。"""
    bb = rpc_call(binary, "basic-blocks", func, "-l", "2000")
    blocks = bb.get("blocks") or []
    if not blocks:
        raise RpcError("函数没有基本块（地址有误或未完成分析）: %s" % func)
    ranges = sorted((int(b["start"], 16), int(b["end"], 16)) for b in blocks)
    lo, hi = ranges[0][0], ranges[-1][1]
    insns, addr = [], lo
    while addr <= hi:
        res = rpc_call(binary, "disassemble", "0x%x" % addr,
                       "-n", str(PAGE), "--with-instructions")
        page = res.get("instructions") or []
        if not page:
            break
        for ins in page:
            a = int(ins["address"], 16)
            if any(s <= a <= e for s, e in ranges):
                insns.append(ins)
        nxt = int(page[-1]["address"], 16) + int(page[-1].get("length") or 1)
        if nxt <= addr:
            break
        addr = nxt
        if len(page) < PAGE:
            break
    return bb, ranges, lo, hi, insns


LEA_RE = re.compile(r"^([A-Z][A-Z0-9]+),\[0x([0-9a-fA-F]+)\]$")
JT_WARN_RE = re.compile(r"Could not recover jumptable at (0x[0-9a-fA-F]+)")
PSEUDO_TABLE_RE = re.compile(r"&DAT_00([0-9a-fA-F]{6})\s*\+\s*\w+\s*\*\s*4")


def find_candidates(insns, c_code):
    """返回 {表基址: 线索描述}。"""
    cand = {}
    for i, ins in enumerate(insns):
        if ins.get("mnemonic") != "LEA":
            continue
        m = LEA_RE.match((ins.get("operands") or "").strip())
        if not m:
            continue
        reg, base = m.group(1), int(m.group(2), 16)
        for j in range(i + 1, min(i + 11, len(insns))):
            ops = insns[j].get("operands") or ""
            indexed = ("[%s + " % reg in ops) and ("*0x4]" in ops)
            jumped = insns[j].get("mnemonic") == "JMP" and reg in ops
            if indexed or jumped:
                cand.setdefault(base, "LEA@0x%x" % int(ins["address"], 16))
                break
    for m in PSEUDO_TABLE_RE.finditer(c_code or ""):
        cand.setdefault(int(m.group(1), 16), "伪码 &DAT_00%s *4 渲染" % m.group(1))
    return cand


def decode_table(binary, base, block_starts, insn_starts, lo, hi, limit):
    """读 limit 项，rel32/abs32 双模式择优。解析失败返回 None。"""
    try:
        res = rpc_call(binary, "read-bytes", "0x%x" % base, str(4 * limit))
    except RpcError:
        return None
    raw = bytes.fromhex(res.get("hex") or "")
    n = len(raw) // 4

    def rel32(e):
        v = int.from_bytes(e, "little")
        return base + (v - (1 << 32) if v >= 1 << 31 else v)

    best = None
    for mode, fn in (("rel32", rel32),
                     ("abs32", lambda e: int.from_bytes(e, "little"))):
        rows, miss = [], 0
        for i in range(n):
            t = fn(raw[i * 4:(i + 1) * 4])
            st = ("落块" if t in block_starts else
                  "落指令" if t in insn_starts else
                  "落间隙" if lo <= t <= hi else "越界")
            rows.append((i, t, st))
            miss = miss + 1 if st == "越界" else 0
            if miss >= 2:  # 连续 2 项越界 = 表结束信号
                rows = rows[:-2]
                break
        score = sum(1 for _, _, s in rows[:4] if s != "越界")
        if best is None or score > best[0]:
            best = (score, mode, rows)
    score, mode, rows = best
    if score < 2 or len(rows) < 2:
        return None
    return {"base": base, "mode": mode, "entries": rows}


def main():
    ap = argparse.ArgumentParser(
        description="跳转表一键解析：全部候选基址 + rel32 解码 + CFG 交叉验证")
    ap.add_argument("binary", help="样本路径（须经 rpc_driver.py ensure 加载）")
    ap.add_argument("func", help="函数地址（如 0x40aba0）或函数名")
    ap.add_argument("--table-bits", type=int, default=32,
                    help="表项位宽，目前仅 32（默认）")
    ap.add_argument("--max-entries", type=int, default=32, help="每表最多读项数")
    ap.add_argument("--json", help="JSON 报告输出路径")
    a = ap.parse_args()
    if a.table_bits != 32:
        print("[错误] 目前仅支持 32 位表项。", file=sys.stderr)
        return 1
    if not Path(a.binary).is_file():
        print("[错误] 样本文件不存在: %s" % a.binary, file=sys.stderr)
        return 1

    try:
        bb, ranges, lo, hi, insns = fetch_function(a.binary, a.func)
        dec = rpc_call(a.binary, "decompile", a.func)
    except RpcError as e:
        print("[错误] %s" % e, file=sys.stderr)
        if e.daemon:
            print("[提示] Ghidra daemon 不可达或样本未加载，先执行：", file=sys.stderr)
            print("  python %s ensure %s" % (RPC_DRIVER, a.binary), file=sys.stderr)
            return 3
        return 2

    c_code = dec.get("c_code") or ""
    warns = JT_WARN_RE.findall(c_code)
    block_starts = {int(b["start"], 16) for b in bb.get("blocks") or []}
    insn_starts = {int(i["address"], 16) for i in insns}
    cand = find_candidates(insns, c_code)

    fname = bb.get("name", a.func)
    print("=== 跳转表解析: %s @ %s ===" % (fname, bb.get("address", a.func)))
    print("指令 %d 条 | 基本块 %d 个 | 范围 0x%x..0x%x"
          % (len(insns), len(block_starts), lo, hi))
    print("[线索] 候选表基址 %d 个: %s"
          % (len(cand), ", ".join("0x%x(%s)" % (b, s) for b, s in sorted(cand.items())) or "无"))
    print("[线索] 伪码 jumptable 警告 %d 处: %s"
          % (len(warns), ", ".join(warns) or "无"))

    bases = sorted(cand)
    tables, failed = [], []
    for k, base in enumerate(bases):
        nxt = bases[k + 1] if k + 1 < len(bases) else None
        limit = a.max_entries if nxt is None else min(a.max_entries, (nxt - base) // 4)
        if limit < 2:
            failed.append((base, "与下一候选基址重叠"))
            continue
        t = decode_table(a.binary, base, block_starts, insn_starts, lo, hi, limit)
        if t:
            tables.append(t)
        else:
            failed.append((base, "解码后不足 2 项有效 target"))

    for n, t in enumerate(tables, 1):
        sts = [s for _, _, s in t["entries"]]
        gaps = sts.count("落间隙")
        verdict = ("全部落块（可信）" if all(s == "落块" for s in sts) else
                   "部分可疑（%d 项越界残留）" % sts.count("越界") if "越界" in sts else
                   "全部落函数范围（其中 %d 项落在未反汇编间隙 = 未恢复 case 体）" % gaps)
        print("\n表 #%d 基址 0x%x  模式 %s  项数 %d  验证: %s"
              % (n, t["base"], t["mode"], len(t["entries"]), verdict))
        for i, tgt, st in t["entries"]:
            note = "" if st == "落块" else "  <- %s" % st
            print("  [%2d] 0x%x%s" % (i, tgt, note))
    for base, why in failed:
        print("\n候选 0x%x 解析失败: %s" % (base, why))

    print("\n=== 汇总 ===")
    print("函数内疑似表 %d 张，已解析 %d 张（全部列出——只解一张 = 解错一半）。"
          % (len(cand), len(tables)))
    if a.json:
        json.dump({"function": fname, "warnings": warns,
                   "candidates": {"0x%x" % b: s for b, s in sorted(cand.items())},
                   "tables": [{"base": "0x%x" % t["base"], "mode": t["mode"],
                               "targets": ["0x%x" % x for _, x, _ in t["entries"]]}
                              for t in tables],
                   "failed": [{"base": "0x%x" % b, "reason": w} for b, w in failed]},
                  open(a.json, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print("JSON -> %s" % a.json)
    return 0 if tables else 2


if __name__ == "__main__":
    sys.exit(main())
