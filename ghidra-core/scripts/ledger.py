#!/usr/bin/env python
"""ledger.py - mechanical circuit breaker for Iron Rule 7 (evidence ledger).

Host-side tool (any Python 3.8+, stdlib only; NOT through driver.py exec).

Iron Rule 7 as text says "second visit to the same byte region = stop".
Text does not fire by itself, so this script is the GATE: every region-level
observation MUST be booked through `observe`. The second time a region is
observed, the entry is REJECTED (exit 2) unless `--delta` answers
"what is different from last time". No answer = escalate, do not retry.

Storage (per binary, keyed by path; sha256-16 recorded inside):
  <ws>/out/<name>.ledger.jsonl   machine truth, append-only
  <ws>/out/<name>.ledger.md      rendered view, auto-regenerated on writes

Commands:
  query    <binary> [--region R]                       look before you analyze
  observe  <binary> --region R --tool T --note N [--delta D]
  conclude <binary> --conclusion C --address A --evidence E \
           --source S --independent yes|no [--harness H] [--quote Q] [--id K] [--overturn] \
           [--kind finding|flag|model|negative] [--program-accept P] [--anchor A] [--proof P]
           （非地址型题目用 --locus region:/channel:/proto: 前缀代替 --address；
           --kind flag 必须 --program-accept 且禁止 --source self-script；
           --kind model 必须 --anchor "L2 左逆锚定：inv(fwd(已知答案))==已知答案
           的实测输出"——fwd(inv(B))==B 恒真，不算验证；
           --kind negative（可达性/存在类否定结论）必须 --proof
           "static-constraint: …" 或 "dynamic-forced: …"——观测缺失 ≠ 不存在，
           铁律 10⑦）
  anomaly  <binary> --region R --note N --consequence C
  resolve  <binary> --anomaly ID (--note N --evidence E | --waive W)
  hypothesis <binary> --text H --if-true P --if-false Q --test "<cmd>" [--id K]
  hypothesis <binary> --resolve-id K (--status confirmed|killed --evidence E | --status waived --waive W)
  plan     <binary> --axes "charset(95) x order(2)" --budget 570 [--note N]
  brute    <binary> --keyspace "2**31" --eta "25min @ 8线程" --why-no-smt R [--tool T]
           （铁律 13 约束系统路由闸：候选空间 ≥ 2^28 的自建枚举开跑前必须登记
           keyspace/预计耗时/SMT 不可行理由，gate_bruteforce 查此账）
  stuck    <binary> --at R --tried "A,B" --escalate TARGET [--ack "A1,A3"]
  status   <binary>
  render   <binary>

Anomaly discipline (Iron Rule 12): an observed inconsistency MUST be booked
as a testable hypothesis via `anomaly` (--consequence answers "if this holds,
what else must be false"), never downgraded to "noise / ambiguity to be
enumerated later". Anomalies stay `open` until a matching `resolve` entry
is appended; old lines are never rewritten. Reverse gate (mechanical):
`resolve --note` MUST also give `--evidence` (command/address/reading) —
a narrative explanation is not evidence and cannot close a constraint;
missing evidence = exit 2. Only objectively unverifiable anomalies (missing
tooling etc.) may take the `--waive` channel instead; the waive reason is
booked and `waived` renders separately from `resolved` in status/render.
While any anomaly is open, `stuck` is REFUSED (exit 2) unless --ack lists
every open anomaly id ("I know these are unchecked") — ack or waive
unblocks stuck, so missing tooling can never deadlock the loop.

Exit-code convention: 0 = success; 1 = usage/environment error (missing
file, malformed input); 2 = mechanical gate rejection (missing --delta,
missing --evidence, --note/--waive violation, unresolved anomalies).

Long-text args (--conclusion/--evidence/--quote) accept a file instead:
--conclusion-file F etc. (UTF-8). Use files from PowerShell 5.1 — embedded
quotes in inline args break parameter boundaries there.
--id accepts any string (C1, Q5-1, ...); omitted = next free integer.

Conclusion provenance (mandatory, Iron Rule 10): every conclusion must name
WHERE its reading came from (--source: read_views | self-script |
decompiler-render | runtime-gdb | runtime-oracle | manual) and whether a
second, independent source cross-confirms it (--independent yes|no).
self-script requires --harness <script path> (a harness that has not passed
its known-answer self-check is zero evidence). --quote attaches the verbatim
tool output the conclusion rests on. independent=no conclusions render as
UNVERIFIED and must not be delivered as-is.

Flag conclusions (Iron Rule 10⑤, mechanical): --kind flag MUST carry
--program-accept "feed command + verbatim success response of the UNMODIFIED
original program / platform" and MUST NOT use --source self-script — a
self-written probe equivalence is not the program's check (chal session
circular-verification incident). Flag entries render with 🏁; a flag entry
without program_accept renders ⚠缺程序接受证据.

Region syntax: 0x1000-0x1100 | 0x1000+0x40 | 0x1000 (point) | check_flag
(name) | name:literal (force name, for names that look like hex).
Exit codes: 0 ok, 1 usage/io error, 2 circuit breaker fired (read stdout).
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# dsh/Git Bash capture decodes stdout as UTF-8; a cp936 console would otherwise
# emit mojibake for the breaker block.
for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

HOME = Path(os.path.expanduser("~"))
WS_OUT = HOME / ".dsh" / "ghidra-workspace" / "out"

# Iron Rule 7: naked-eye hex reading is only for verifying tool output.
# The budget is mechanical: per region, per binary, the 3rd booking is refused.
NAKED_EYE = {"naked-eye", "raw-hex", "hex", "xxd", "hexdump", "hd", "肉眼"}
NAKED_EYE_BUDGET = 2

ESCALATION_MENU = """\
答不出 -> 禁止换第 3 种方式重试同一路径，必须升级其一：
  · 换工具层级: read-bytes -> disassemble -> decompile -> pcode / search-decompiled
  · 疑似 packed/加密 -> re-unpack（upx -d / upx_repair.py / unpacker）
  · 静态卡住 -> re-dynamic（跑起来看 / oracle.py / emulate-function）
  · 都不行 -> ledger.py stuck <binary> --at <区域> --tried "A,B" --escalate <去向>，然后问用户"""


def sha16(binary: Path) -> str:
    h = hashlib.sha256()
    with binary.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def ledger_paths(binary: Path) -> tuple[Path, Path]:
    WS_OUT.mkdir(parents=True, exist_ok=True)
    return (WS_OUT / (binary.name + ".ledger.jsonl"),
            WS_OUT / (binary.name + ".ledger.md"))


def load_entries(jsonl: Path) -> list[dict]:
    if not jsonl.is_file():
        return []
    out = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def append_entry(jsonl: Path, entry: dict) -> None:
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def anomaly_resolves(entries: list[dict]) -> dict:
    """anomaly_id -> 最新一条 anomaly-resolve（append-only，后者覆盖前者语义）。"""
    out = {}
    for e in entries:
        if e.get("type") == "anomaly-resolve":
            out[str(e.get("anomaly_id"))] = e
    return out


def open_anomalies(entries: list[dict]) -> list[dict]:
    """open 状态由回放计算：有 anomaly 且无对应 anomaly-resolve = open。"""
    resolved = anomaly_resolves(entries)
    return [e for e in entries if e.get("type") == "anomaly"
            and str(e.get("id")) not in resolved]


def next_anomaly_id(entries: list[dict]) -> str:
    """沿用 conclude 的「下一个空闲整数」风格，加 A 前缀避免与结论 id 混淆。"""
    n = 0
    for e in entries:
        if e.get("type") == "anomaly":
            m = re.match(r"^A(\d+)$", str(e.get("id", "")))
            if m:
                n = max(n, int(m.group(1)))
    return f"A{n + 1}"


def _anomaly_sort_key(aid: str):
    m = re.match(r"^A(\d+)$", str(aid))
    return (0, int(m.group(1))) if m else (1, str(aid))


def hypothesis_resolves(entries: list[dict]) -> dict:
    """hypothesis_id -> 最新一条 hypothesis-resolve（与 anomaly 同构的 append-only 回放）。"""
    out = {}
    for e in entries:
        if e.get("type") == "hypothesis-resolve":
            out[str(e.get("hypothesis_id"))] = e
    return out


def open_hypotheses(entries: list[dict]) -> list[dict]:
    resolved = hypothesis_resolves(entries)
    return [e for e in entries if e.get("type") == "hypothesis"
            and str(e.get("id")) not in resolved]


def next_hypothesis_id(entries: list[dict]) -> str:
    n = 0
    for e in entries:
        if e.get("type") == "hypothesis":
            m = re.match(r"^H(\d+)$", str(e.get("id", "")))
            if m:
                n = max(n, int(m.group(1)))
    return f"H{n + 1}"


def _hypothesis_sort_key(hid: str):
    m = re.match(r"^H(\d+)$", str(hid))
    return (0, int(m.group(1))) if m else (1, str(hid))


def parse_region(text: str):
    """-> ("range", start, end_inclusive) | ("name", str)"""
    t = text.strip()
    if t.lower().startswith("name:"):
        return ("name", t[5:])

    def hexint(s: str) -> int:
        s = s.strip().lower()
        return int(s[2:] if s.startswith("0x") else s, 16)

    low = t.lower()
    try:
        if "-" in low and not low.startswith("-"):
            a, b = low.split("-", 1)
            start, end = hexint(a), hexint(b)
            return ("range", min(start, end), max(start, end))
        if "+" in low:
            a, b = low.split("+", 1)
            start = hexint(a)
            return ("range", start, start + hexint(b) - 1)
        if low.startswith("0x") or (low and all(c in "0123456789abcdef" for c in low)):
            v = hexint(low)
            return ("range", v, v)
    except ValueError:
        pass
    return ("name", t)


def regions_hit(a, b) -> bool:
    if a[0] == "range" and b[0] == "range":
        return a[1] <= b[2] and b[1] <= a[2]
    if a[0] == "name" and b[0] == "name":
        return a[1] == b[1]
    return False


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_obs(i: int, e: dict) -> str:
    delta = f"  delta=\"{e['delta']}\"" if e.get("delta") else ""
    return f"[{i}] {e['ts']}  tool={e['tool']}  note=\"{e['note']}\"{delta}"


def breaker_block(region: str, priors: list[dict], reason: str) -> None:
    print(f"[断路器 · 铁律7] 区域 \"{region}\" 第 {len(priors) + 1} 次回访 —— {reason}")
    print("──── 已有观察 ────")
    for i, e in enumerate(priors, 1):
        print(fmt_obs(i, e))
    print("──── 强制问题 ────")
    print("这次观测和上次差在哪？")
    print("答得出 -> 重新执行本命令并加: --delta \"具体差异（区别于上面每一条）\"")
    print(ESCALATION_MENU)


def require_binary(args) -> Path:
    binary = Path(args.binary)
    if not binary.is_file():
        print(json.dumps({"ok": False, "error": f"binary not found: {binary}"},
                         ensure_ascii=False))
        sys.exit(1)
    return binary


def auto_render(binary: Path) -> None:
    try:
        render(binary)
    except Exception:
        pass  # never let rendering break a booking


def cmd_observe(args) -> int:
    binary = require_binary(args)
    jsonl, _ = ledger_paths(binary)
    entries = load_entries(jsonl)
    region = parse_region(args.region)
    priors = [e for e in entries if e.get("type") == "observe"
              and regions_hit(parse_region(e.get("region", "")), region)]
    tool = args.tool.strip()

    if tool.lower() in NAKED_EYE:
        naked = [e for e in priors if e["tool"].lower() in NAKED_EYE]
        if len(naked) >= NAKED_EYE_BUDGET:
            breaker_block(args.region, priors,
                          f"肉眼/裸 hex 预算已用完（{NAKED_EYE_BUDGET} 次/区域）——"
                          "字节只能通过工具解读，肉眼仅用于验证工具输出")
            return 2

    if priors:
        delta = (args.delta or "").strip()
        if not delta or delta == args.note.strip():
            breaker_block(args.region, priors,
                          "缺少 --delta" if not delta else "--delta 与 --note 相同，不是差异")
            return 2

    entry = {"type": "observe", "ts": now(), "sha16": sha16(binary),
             "region": args.region.strip(), "tool": tool,
             "note": args.note.strip(), "visit": len(priors) + 1}
    if args.delta:
        entry["delta"] = args.delta.strip()
    append_entry(jsonl, entry)
    auto_render(binary)

    out = {"ok": True, "booked": True, "visit": entry["visit"],
           "ledger": str(jsonl)}
    neg_kw = ("不可达", "不存在", "死代码", "无法到达", "从不命中", "从未被",
              "拿不到", "无法获得", "unreachable", "non-returning", "dead code")
    if any(k in entry["note"] for k in neg_kw):
        out["negative_hint"] = ("本条 observe 含可达性/存在类否定判词——观察只能记录"
                                "「未观测到」，证明不了「不存在」；若据此下否定结论，"
                                "必须 conclude --kind negative --proof "
                                "static-constraint|dynamic-forced（铁律 10⑦，"
                                "判例 4307cc95）")
    if entry["visit"] >= 3:
        out["warning"] = (f"该区域第 {entry['visit']} 次回访——若本条 delta "
                          "仍无实质增量，立即升级工具层级（见断路器菜单）")
    print(json.dumps(out, ensure_ascii=False))
    return 0


def cmd_query(args) -> int:
    binary = require_binary(args)
    jsonl, md = ledger_paths(binary)
    entries = load_entries(jsonl)
    result = {"ok": True, "ledger": str(jsonl), "md": str(md),
              "entries": len(entries), "observations": [], "conclusions": [],
              "stucks": [], "open_anomalies": open_anomalies(entries)}
    if args.region:
        region = parse_region(args.region)
        result["observations"] = [
            e for e in entries if e.get("type") == "observe"
            and regions_hit(parse_region(e.get("region", "")), region)]
        result["conclusions"] = [
            e for e in entries if e.get("type") == "conclude"
            and regions_hit(parse_region(e.get("region", "")), region)]
        if result["observations"] or result["conclusions"]:
            result["verdict"] = ("已踏勘——直接引用以上结论/观察；没有台账之外的"
                                 "新证据禁止重析（observe 会被断路器拦截）")
        else:
            result["verdict"] = "未踏勘——可以分析，观察结果用 observe 落账"
    else:
        result["observations"] = [e for e in entries if e.get("type") == "observe"]
        result["conclusions"] = [e for e in entries if e.get("type") == "conclude"]
        result["stucks"] = [e for e in entries if e.get("type") == "stuck"]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_conclude(args) -> int:
    binary = require_binary(args)

    def _resolve(value, fpath, name):
        if fpath:
            p = Path(fpath)
            if not p.is_file():
                print(json.dumps({"ok": False,
                                  "error": f"--{name}-file not found: {p}"},
                                 ensure_ascii=False))
                sys.exit(1)
            return p.read_text(encoding="utf-8").strip()
        return (value or "").strip()

    conclusion = _resolve(args.conclusion, args.conclusion_file, "conclusion")
    evidence = _resolve(args.evidence, args.evidence_file, "evidence")
    quote = _resolve(args.quote, args.quote_file, "quote")
    for name, val in (("conclusion", conclusion), ("evidence", evidence)):
        if not val:
            print(json.dumps({"ok": False,
                              "error": f"--{name} 或 --{name}-file 必须给其一"},
                             ensure_ascii=False))
            return 1
    locus = (args.locus or args.address or "").strip()
    if not locus:
        print(json.dumps({"ok": False,
                          "error": "--address 或 --locus 必填其一；非地址型题目"
                                   "（协议/算法/多方件）用 region: / channel: / proto: 前缀，"
                                   "如 --locus region:channel-model"},
                         ensure_ascii=False))
        return 1

    jsonl, _ = ledger_paths(binary)
    entries = load_entries(jsonl)
    conclusions = [e for e in entries if e.get("type") == "conclude"]

    cid = args.id
    if cid is None:
        cid = max([e.get("id") for e in conclusions
                   if isinstance(e.get("id"), int)], default=0) + 1
    old = next((e for e in conclusions
                if str(e.get("id")) == str(cid)), None)
    if old and not args.overturn:
        print(f"[写入即锁定] 结论 #{cid} 已存在：\"{old['conclusion']}\"")
        print("推翻它必须加 --overturn 并在 --evidence 里给出新证据（推翻留痕）。")
        return 2

    if args.source == "self-script" and not args.harness:
        print(json.dumps({"ok": False,
                          "error": "source=self-script 必须加 --harness <脚本路径>；"
                                   "未通过已知答案自检的 harness 输出是零证据（铁律 10）"},
                         ensure_ascii=False))
        return 1

    kind = getattr(args, "kind", "finding") or "finding"
    program_accept = _resolve(getattr(args, "program_accept", None),
                              getattr(args, "program_accept_file", None),
                              "program-accept")
    # 铁律 10⑤ 硬门（chal session 循环论证事故：agent 把自己写的探针等价式
    # 当成程序判定，交付错 flag 并标 --independent yes）。flag 类结论的唯一
    # 合法 VERIFIED 证据是「未修改的原程序/平台接受候选输入」本身。
    if kind == "flag":
        if not program_accept:
            print(json.dumps({"ok": False,
                              "error": "--kind flag 必须加 --program-accept "
                                       "\"投喂命令 + 未修改原程序/平台的成功响应原文\""
                                       "（长文本走 --program-accept-file）。"
                                       "自写探针的等价式不是程序判定——"
                                       "探针只能支撑 --kind finding"},
                             ensure_ascii=False))
            return 2
        if args.source == "self-script":
            print(json.dumps({"ok": False,
                              "error": "--kind flag 不允许 --source self-script："
                                       "flag 的权威来源是原程序/平台的接受行为，"
                                       "写 --source runtime-oracle 并把实测记录填进 "
                                       "--program-accept"},
                             ensure_ascii=False))
            return 2

    # 铁律 10⑥ 硬门（f862c151/92a0a107 双会话临门一脚事故：用恒真自检
    # fwd(inv(B))==B 确认了一个错的方程——任何逆函数实现都构造性满足它，
    # 零信息量）。宣布「模型/反演已闭合」的结论必须附 L2 左逆锚定证据：
    # inv(fwd(X_known))==X_known，其中 X_known 是已知的真实答案
    # （如 'A'*L 采样的 trace——反演结果前 L 字节必须是 0x41）。
    anchor = _resolve(getattr(args, "anchor", None),
                      getattr(args, "anchor_file", None), "anchor")
    if kind == "model":
        if not anchor:
            print(json.dumps({"ok": False,
                              "error": "--kind model（模型/反演闭合声明）必须加 "
                                       "--anchor \"L2 左逆锚定的实测输出\"："
                                       "inv(fwd(X_known))==X_known，X_known 取已知"
                                       "真实答案（长文本走 --anchor-file）。"
                                       "fwd(inv(B))==B 恒真，是 L1 零信息量自检，"
                                       "不能当锚；自检分级见铁律 10⑥"},
                             ensure_ascii=False))
            return 2

    # 铁律 10⑦ 硬门（4307cc95：watchpoint 未触发 + hbreak 不命中 +
    # Ghidra 无 xref 三条「未观测到」被写成「flag 路径不可达」并交付，实际是
    # UD2 的 SIGILL handler 推进保存的 RIP 使调用正常返回——观测缺失 ≠ 不存在）。
    # 可达性/存在类否定结论只有两种合法证据：static-constraint（给出入口到目标
    # 每条路径上不可满足的约束）或 dynamic-forced（patch 掉中间闸门强制到达后
    # 目标仍不执行）。
    proof = _resolve(getattr(args, "proof", None),
                     getattr(args, "proof_file", None), "proof")
    if kind == "negative":
        proof_low = proof.lower()
        if not (proof_low.startswith("static-constraint")
                or proof_low.startswith("dynamic-forced")):
            print(json.dumps({"ok": False,
                              "error": "--kind negative（可达性/存在类否定结论）必须加 "
                                       "--proof \"static-constraint: <每条路径上不可满足的"
                                       "约束>\" 或 \"dynamic-forced: <patch 强制到达后目标"
                                       "仍不执行的实测>\"（长文本走 --proof-file）。"
                                       "watchpoint 未触发 / hbreak 未命中 / 反编译器无 xref "
                                       "只是「未观测到」，证明不了「不存在」（铁律 10⑦，"
                                       "判例 4307cc95）"},
                             ensure_ascii=False))
            return 2

    entry = {"type": "conclude", "ts": now(), "sha16": sha16(binary),
             "id": cid, "conclusion": conclusion,
             "address": (args.address or "").strip(), "region": locus,
             "evidence": evidence,
             "source": args.source, "independent": args.independent}
    if kind != "finding":
        entry["kind"] = kind
    if program_accept:
        entry["program_accept"] = program_accept
    if anchor:
        entry["anchor"] = anchor
    if proof:
        entry["proof"] = proof
    if args.harness:
        entry["harness"] = args.harness.strip()
    if quote:
        entry["quote"] = quote
    if old:
        entry["overturns"] = {"conclusion": old["conclusion"],
                              "evidence": old["evidence"], "ts": old["ts"]}
    append_entry(jsonl, entry)
    auto_render(binary)
    out = {"ok": True, "id": cid, "locked": True, "overturned": bool(old)}
    if kind == "finding":
        neg_kw = ("不可达", "不存在", "死代码", "无法到达", "从不命中", "从未被",
                  "拿不到", "无法获得", "unreachable", "non-returning", "dead code")
        if any(k in conclusion for k in neg_kw):
            out["negative_hint"] = ("该结论含可达性/存在类否定判词——若这是此类结论，"
                                    "应使用 --kind negative --proof static-constraint|dynamic-forced "
                                    "重新落账（铁律 10⑦：观测缺失 ≠ 不存在）；"
                                    "非否定结论可忽略本提示")
    if args.independent == "no":
        out["warning"] = ("该结论无独立来源交叉印证——render 中标记 UNVERIFIED；"
                          "交付前必须补第二来源（静态常量 / 第二输入 / 已知明文）"
                          "或在交付物中显式声明「自我一致，未独立验证」")
    print(json.dumps(out, ensure_ascii=False))
    return 0


def cmd_anomaly(args) -> int:
    binary = require_binary(args)
    jsonl, _ = ledger_paths(binary)
    entries = load_entries(jsonl)
    aid = next_anomaly_id(entries)
    entry = {"type": "anomaly", "id": aid, "status": "open", "ts": now(),
             "sha16": sha16(binary), "region": args.region.strip(),
             "note": args.note.strip(),
             "consequence": args.consequence.strip()}
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "id": aid, "status": "open",
                      "ledger": str(jsonl)}, ensure_ascii=False))
    return 0


def cmd_resolve(args) -> int:
    binary = require_binary(args)
    note = (args.note or "").strip()
    waive = (args.waive or "").strip()
    if bool(note) == bool(waive):
        print(json.dumps({"ok": False,
                          "error": "--note 与 --waive 二选一，必须且只能给一个（机械门）"},
                         ensure_ascii=False))
        return 2
    evidence = (args.evidence or "").strip()
    if args.evidence_file:
        p = Path(args.evidence_file)
        if not p.is_file():
            print(json.dumps({"ok": False,
                              "error": f"--evidence-file not found: {p}"},
                             ensure_ascii=False))
            return 1
        evidence = p.read_text(encoding="utf-8").strip()
    # 反向门（铁律 12）：resolve 关闭异常必须给可检验证据；叙述性解释不算。
    # waive 通道豁免（豁免理由即 --waive 文本本身，已强制入账），
    # 但 status=waived 在 status/render 里单独可见，与 resolved 区分。
    if note and not evidence:
        print("[反向门 · 铁律12] resolve 关闭异常必须给可检验证据"
              "（命令/地址/读数），叙述性解释不算——")
        print("  重新执行并加: --evidence \"复核命令 + 关键读数\""
              "（长文本走 --evidence-file）")
        print("  客观不可查（工具缺失等）才走: --waive \"为何豁免\"")
        return 2
    jsonl, _ = ledger_paths(binary)
    entries = load_entries(jsonl)
    aid = str(args.anomaly).strip()
    target = next((e for e in entries if e.get("type") == "anomaly"
                   and str(e.get("id")) == aid), None)
    resolved = anomaly_resolves(entries)
    if target is None or aid in resolved:
        reason = "不存在" if target is None else f"已关闭（{resolved[aid]['status']}）"
        opens = [str(e["id"]) for e in open_anomalies(entries)]
        print(json.dumps({"ok": False,
                          "error": f"anomaly {aid} {reason}，无法 resolve",
                          "open_anomalies": opens}, ensure_ascii=False))
        return 2
    entry = {"type": "anomaly-resolve", "anomaly_id": aid,
             "status": "waived" if waive else "resolved",
             "note": waive or note, "ts": now()}
    if evidence:
        entry["evidence"] = evidence
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "anomaly": aid, "status": entry["status"]},
                     ensure_ascii=False))
    return 0


def cmd_hypothesis(args) -> int:
    binary = require_binary(args)
    jsonl, _ = ledger_paths(binary)
    entries = load_entries(jsonl)
    if args.resolve_id:
        # 关闭模式：与 resolve 反向门同构——confirmed/killed 都必须给可检验证据，
        # 叙述不是证据，缺 evidence exit 2。waived 通道（客观不可检验/已被后续
        # 结论取代）豁免 evidence，但豁免理由强制入账，waived 在 render 单列可见。
        hid = str(args.resolve_id).strip()
        if not args.status:
            print(json.dumps({"ok": False,
                              "error": "--resolve-id 关闭假设时必须给 "
                                       "--status confirmed|killed|waived"},
                             ensure_ascii=False))
            return 1
        waive = (getattr(args, "waive", None) or "").strip()
        evidence = (args.evidence or "").strip()
        if args.evidence_file:
            p = Path(args.evidence_file)
            if not p.is_file():
                print(json.dumps({"ok": False,
                                  "error": f"--evidence-file not found: {p}"},
                                 ensure_ascii=False))
                return 1
            evidence = p.read_text(encoding="utf-8").strip()
        if args.status == "waived":
            if not waive:
                print(json.dumps({"ok": False,
                                  "error": "--status waived 必须给 --waive "
                                           "\"为何豁免\"（豁免理由强制入账）"},
                                 ensure_ascii=False))
                return 2
            evidence = "waive: " + waive
        elif not evidence:
            print("[反向门 · 铁律4] hypothesis 关闭（confirmed/killed）必须给可检验证据"
                  "（检验命令的实际输出/读数），叙述不是证据——")
            print("  重新执行并加: --evidence \"跑 --test 命令的关键输出\""
                  "（长文本走 --evidence-file）；客观不可检验才走 "
                  "--status waived --waive \"为何豁免\"")
            return 2
        target = next((e for e in entries if e.get("type") == "hypothesis"
                       and str(e.get("id")) == hid), None)
        resolved = hypothesis_resolves(entries)
        if target is None or hid in resolved:
            reason = "不存在" if target is None \
                else f"已关闭（{resolved[hid]['status']}）"
            opens = [str(e["id"]) for e in open_hypotheses(entries)]
            print(json.dumps({"ok": False,
                              "error": f"hypothesis {hid} {reason}，无法关闭",
                              "open_hypotheses": opens}, ensure_ascii=False))
            return 2
        entry = {"type": "hypothesis-resolve", "hypothesis_id": hid,
                 "status": args.status, "evidence": evidence, "ts": now()}
        append_entry(jsonl, entry)
        auto_render(binary)
        print(json.dumps({"ok": True, "hypothesis": hid,
                          "status": args.status}, ensure_ascii=False))
        return 0
    # 创建模式
    fields = {"text": args.text, "if_true": args.if_true,
              "if_false": args.if_false, "test": args.test}
    missing = [f"--{k.replace('_', '-')}" for k, v in fields.items()
               if not (v or "").strip()]
    if missing:
        print(json.dumps({"ok": False,
                          "error": f"创建假设必填: {' '.join(missing)}"
                                   "（--if-true/--if-false 回答「若为真/若为假，"
                                   "下一步分别做什么」，--test 给出判定命令）"},
                         ensure_ascii=False))
        return 1
    hid = args.id or next_hypothesis_id(entries)
    entry = {"type": "hypothesis", "id": hid, "status": "open", "ts": now(),
             "sha16": sha16(binary),
             "text": args.text.strip(), "if_true": args.if_true.strip(),
             "if_false": args.if_false.strip(), "test": args.test.strip()}
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "id": hid, "status": "open",
                      "ledger": str(jsonl)}, ensure_ascii=False))
    return 0


def cmd_plan(args) -> int:
    binary = require_binary(args)
    jsonl, _ = ledger_paths(binary)
    entry = {"type": "plan", "ts": now(), "sha16": sha16(binary),
             "axes": args.axes.strip(), "budget": args.budget,
             "note": (args.note or "").strip()}
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "budget": args.budget,
                      "ledger": str(jsonl)}, ensure_ascii=False))
    return 0


def parse_keyspace(text: str) -> int:
    """安全解析 keyspace 表达式：整数/0x 十六进制/2**31/1e6/95*8*3 组合。

    只允许数字与 + - * ** << >> 运算符（^ 按 ** 理解），ast 白名单求值，
    不碰 eval 全功能。
    """
    import ast
    import operator
    ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
           ast.Pow: operator.pow, ast.LShift: operator.lshift,
           ast.RShift: operator.rshift}
    expr = text.strip().replace("^", "**")
    tree = ast.parse(expr, mode="eval")

    def ev(node) -> int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return int(node.value)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        if isinstance(node, ast.BinOp) and type(node.op) in ops:
            return ops[type(node.op)](ev(node.left), ev(node.right))
        raise ValueError(f"不允许的表达式片段: {ast.dump(node)}")

    value = ev(tree)
    if value <= 0:
        raise ValueError("keyspace 必须为正")
    return value


def cmd_brute(args) -> int:
    """铁律 13 约束系统路由闸的登记口：大枚举开跑前的账本。

    判例 285db822：BV32 约束系统（ror/add/mul）z3 毫秒出唯一解，agent 全程
    z3 零调用、连写 4 个 OpenMP C 枚举器烧 20+ min——失败触发的断路器拦不住
    「永远有产出」的枚举器，所以枚举本身必须先过账。gate_bruteforce.py 对
    未登记的自建大枚举器（≥2^28）机械阻断。
    """
    binary = require_binary(args)
    try:
        ks = parse_keyspace(args.keyspace)
    except (ValueError, SyntaxError) as ex:
        print(json.dumps({"ok": False,
                          "error": f"--keyspace 无法解析: {args.keyspace!r}（{ex}）；"
                                   "支持整数 / 0x 十六进制 / 2**31 / 1e6 / 95*8*3"},
                         ensure_ascii=False))
        return 1
    jsonl, _ = ledger_paths(binary)
    entry = {"type": "brute", "ts": now(), "sha16": sha16(binary),
             "keyspace": ks, "eta": args.eta.strip(),
             "why_no_smt": args.why_no_smt.strip(),
             "tool": (args.tool or "").strip()}
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "keyspace": ks,
                      "ledger": str(jsonl)}, ensure_ascii=False))
    return 0


_TECHNIQUE_CLASSES = {
    "z3/SMT": ("z3", "smt", "solver", "约束求解", "求解器"),
    "peel/cone剥离": ("peel_inverse", "peel_solve", "cone_invert", "剥离", "锥形"),
    "gdb动态": ("gdb", "watchpoint", "hwatch", "断点", "单步", " layer_dump"),
    "仿真": ("emulate", "unicorn", "仿真"),
    "伪码": ("decompile", "伪码", "反编译"),
    "汇编/字节直读": ("disassemble", "objdump", "反汇编", "xxd", "hexdump",
                      "肉眼", "字节"),
    "枚举/爆破": ("爆破", "枚举", "brute", "穷举", "遍历"),
    "patch改跑": ("patch", "改字节"),
    "结构/元数据": ("frame_map", "const_scan", "readelf", "栈帧", "元数据"),
    "差分对比": ("model_diff", "diff", "差分", "对比实验"),
    "符号执行": ("angr", "符号执行"),
    "trace/hook": ("strace", "ltrace", "trace", "frida", "hook"),
    "strings/xref": ("strings", "xref", "交叉引用"),
}


def _technique_classes(text):
    """提取文本命中的技术类集合（stuck 换路校验用）。"""
    low = text.lower()
    return {cls for cls, kws in _TECHNIQUE_CLASSES.items()
            if any(k in low for k in kws)}


def cmd_stuck(args) -> int:
    binary = require_binary(args)
    jsonl, _ = ledger_paths(binary)
    entries = load_entries(jsonl)
    opens = open_anomalies(entries)
    acknowledged = []
    if opens:
        need = sorted((str(e["id"]) for e in opens), key=_anomaly_sort_key)
        ack = (args.ack or "").strip()
        acked = {x.strip() for x in ack.split(",") if x.strip()}
        if acked != set(need):
            print(f"[异常未收口 · 铁律12] 该二进制有 {len(need)} 个 open anomaly，"
                  "stuck 入账前必须全部确认：")
            for e in opens:
                print(f"  {e['id']} [{e['region']}] {e['note']}"
                      f" —— 若成立则必须为假：{e['consequence']}")
            print("二选一：")
            print(f"  · 明知未查也要留卡点 -> 重新执行并加: --ack \"{','.join(need)}\""
                  "（语义：我知道这些没查）")
            print("  · 工具缺失等客观不可查 -> 先豁免，不许硬卡："
                  "ledger.py resolve <binary> --anomaly <id> --waive \"为何豁免\"")
            return 2
        acknowledged = need
    # ── 否定结论矛盾检查（判例 a0f3be66：T16 运行期派生的 negative 落账后
    # 136 秒，escalate 仍写「离线 z3/angr 求解」——正是该否定已杀死的路线类，
    # 35 分钟空转）。活跃 negative conclude 在场时，stuck 必须显式声明
    # 升级路径为何不被这些否定覆盖。──────
    latest_conc: dict = {}
    for e in entries:
        if e.get("type") == "conclude":
            latest_conc[str(e.get("id"))] = e
    negs = [e for e in latest_conc.values() if e.get("kind") == "negative"]
    neg_ack = (getattr(args, "ack_negatives", None) or "").strip()
    if negs and len(neg_ack) < 20:
        print(f"[否定结论在场 · 升级路径矛盾检查] 该二进制有 {len(negs)} 条活跃 "
              "negative conclude（已被推翻的除外）：")
        for e in negs:
            print(f"  #{e.get('id')} [{e.get('region') or e.get('address') or ''}] "
                  f"{e.get('conclusion')}")
        print("每条 negative 都杀死了一整类路线。--escalate 若仍落在被杀死的类里"
              "（判例 a0f3be66：「不存在固定输入/运行期相关」落账后仍升级离线"
              "符号求解 → 35 分钟空转），就是重复事故。二选一：")
        print("  · 升级路径不被上述否定覆盖 → 加 --ack-negatives "
              "\"逐条说明为何不被覆盖\"（≥20 字）")
        print("  · 确实被覆盖 → 换升级路径；被否定杀死的类不许再作为 escalate")
        return 2
    # ── 换路校验（gate_stuck 下游：落账不能只是补账，必须包含换路）──────
    # 失效模式：被 gate_stuck 拦 → 补一条 tried/escalate 与上次雷同的 stuck →
    # 继续原路径（门教会的是应付检查，不是换路）。两条机械判据，仅约束本样本
    # 已有 stuck 落账的后续 stuck；同类不同法的正当重试加 --note 说明差异点放行。
    prev_stucks = [e for e in entries if e.get("type") == "stuck"]
    if prev_stucks and not (getattr(args, "note", None) or "").strip():
        new_tried = args.tried.strip()
        new_esc = args.escalate.strip()
        last = prev_stucks[-1]
        combo_new = f"{new_tried}|{new_esc}".lower()
        combo_old = (str(last.get("tried") or "") + "|"
                     + str(last.get("escalate") or "")).lower()
        ratio = difflib.SequenceMatcher(None, combo_new, combo_old).ratio()
        if ratio > 0.8:
            print(f"[stuck 换路校验] 本次 tried/escalate 与上一次 stuck 雷同"
                  f"（相似度 {ratio:.2f}>0.8）——落账不是补账，必须包含换路。\n"
                  f"上一次：tried={last.get('tried')!r} escalate={last.get('escalate')!r}\n"
                  "正当的同类重试（如换模型/换常量再跑同一技术）：加 "
                  "--note \"与上次的差异点\" 说明后放行。")
            return 2
        esc_classes = _technique_classes(new_esc)
        if esc_classes:
            seen = _technique_classes(new_tried)
            for e in prev_stucks:
                seen |= _technique_classes(str(e.get("tried") or ""))
                seen |= _technique_classes(str(e.get("escalate") or ""))
            if esc_classes <= seen:
                print(f"[stuck 换路校验] --escalate 的技术类 {sorted(esc_classes)} "
                      "全部落在已试/已升级过的清单里——「升级到已试过的路」不是升级。\n"
                      f"已见技术类：{sorted(seen)}\n"
                      "三选一：① escalate 换到清单外的技术类；② 同类不同法的正当"
                      "重试加 --note \"差异点\"；③ 台账外技术类词汇误伤时同样用 "
                      "--note 说明。")
                return 2
    entry = {"type": "stuck", "ts": now(), "sha16": sha16(binary),
             "at": args.at.strip(), "tried": args.tried.strip(),
             "escalate": args.escalate.strip()}
    note = (getattr(args, "note", None) or "").strip()
    if note:
        entry["note"] = note
    if acknowledged:
        entry["acknowledged_anomalies"] = acknowledged
    if neg_ack:
        entry["ack_negatives"] = neg_ack
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "recorded": True,
                      "next": entry["escalate"]}, ensure_ascii=False))
    return 0


def cmd_status(args) -> int:
    binary = require_binary(args)
    jsonl, md = ledger_paths(binary)
    entries = load_entries(jsonl)
    obs = [e for e in entries if e.get("type") == "observe"]
    anoms = [e for e in entries if e.get("type") == "anomaly"]
    hot = {}
    for e in obs:
        hot[e["region"]] = hot.get(e["region"], 0) + 1
    out = {
        "ok": True, "ledger": str(jsonl), "md": str(md),
        "observations": len(obs),
        "conclusions": len([e for e in entries if e.get("type") == "conclude"]),
        "anomalies": len(anoms),
        "hypotheses": len([e for e in entries if e.get("type") == "hypothesis"]),
        "open_hypotheses": open_hypotheses(entries),
        "plans": len([e for e in entries if e.get("type") == "plan"]),
        "stucks": [e for e in entries if e.get("type") == "stuck"],
        "open_anomalies": open_anomalies(entries),
        "revisit_hotspots": {r: n for r, n in sorted(hot.items(),
                             key=lambda kv: -kv[1]) if n >= 2},
    }
    if len(obs) >= 5 and not anoms:
        out["hint"] = (f"已入账 {len(obs)} 次观察但 0 条 anomaly。若期间遇到过任何不一致"
                       "（工具误报/读数异常/假设冲突/harness 异常），按铁律 12 用 "
                       "ledger.py anomaly --consequence 落账，禁止降级为噪声")
    workdir = getattr(args, "workdir", None)
    if workdir:
        wd = Path(workdir)
        if wd.is_dir():
            scripts = [p for p in wd.rglob("*.py") if p.is_file()]
            ratio = len(scripts) / max(len(entries), 1)
            out["workdir_scripts"] = len(scripts)
            if len(scripts) >= 5 and ratio > 5:
                out["churn_hint"] = (
                    f"work 目录 {len(scripts)} 个脚本 vs 台账 {len(entries)} 条目"
                    f"（比值 {ratio:.1f} > 5）——典型的「记账死掉 + 同路径换措辞重试」"
                    "信号（判例D·R3：36 脚本 vs 11 条目）。立即审视："
                    "这些脚本是否各写各的 region 绕开了 observe 断路器？"
                    "未入账的观测补 observe，卡住先 stuck")
        else:
            out["workdir_warning"] = f"--workdir 不存在: {wd}"
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def render(binary: Path) -> Path:
    jsonl, md = ledger_paths(binary)
    entries = load_entries(jsonl)
    sha = next((e["sha16"] for e in reversed(entries) if "sha16" in e),
               sha16(binary))

    latest: dict[str, dict] = {}
    for e in entries:
        if e.get("type") == "conclude":
            latest[str(e["id"])] = e
    obs = [e for e in entries if e.get("type") == "observe"]
    stucks = [e for e in entries if e.get("type") == "stuck"]

    by_region: dict[str, list] = {}
    for e in obs:
        by_region.setdefault(e["region"], []).append(e)

    lines = [
        f"# Ledger: {binary.name}（sha256 前 16: {sha}）",
        "",
        "<!-- 由 ledger.py render 自动生成，手工改动会被覆盖；入账走 ledger.py -->",
        "",
        "## 权威结论（写入即锁定；⚠UNVERIFIED = 无独立来源，禁止原样交付）",
        "| # | 结论 | 位置 | 证据（命令/输出要点） | 来源 | 独立验证 | 时间 |",
        "|---|------|------|----------------------|------|---------|------|",
    ]
    for cid in sorted(latest, key=lambda k: (0, int(k)) if str(k).isdigit()
                      else (1, str(k))):
        e = latest[cid]
        concl = e["conclusion"].replace("\n", " ⏎ ")
        if "overturns" in e:
            concl += f"（推翻：{e['overturns']['conclusion']}）"
        source = e.get("source", "—")
        if e.get("harness"):
            source += f"({e['harness']})"
        indep = e.get("independent", "—")
        evidence_cell = e['evidence'].replace(chr(10), ' ⏎ ')
        if e.get("kind") == "flag":
            concl = "🏁 " + concl
            if e.get("program_accept"):
                evidence_cell += (" ｜程序接受: "
                                  + e["program_accept"].replace(chr(10), ' ⏎ '))
            else:
                concl = "⚠缺程序接受证据 " + concl
        if e.get("kind") == "model":
            concl = "⚓ " + concl
            if e.get("anchor"):
                evidence_cell += (" ｜左逆锚定: "
                                  + e["anchor"].replace(chr(10), ' ⏎ '))
            else:
                concl = "⚠缺左逆锚定 " + concl
        if indep == "no":
            concl = "⚠UNVERIFIED " + concl
        lines.append(f"| {cid} | {concl} | {e.get('address') or e.get('region', '—')} | {evidence_cell} "
                     f"| {source} | {indep} | {e['ts']} |")
    lines += ["", "## 已踏勘区域",
              "| 区域 | 回访次数 | 工具 | 最近观察 | 差异链 |",
              "|------|---------|------|----------|--------|"]
    for region, es in by_region.items():
        tools = ", ".join(dict.fromkeys(e["tool"] for e in es))
        deltas = " → ".join(e.get("delta", "（首访）") for e in es)
        lines.append(f"| {region} | {len(es)} | {tools} | {es[-1]['note']} | {deltas} |")
    lines += ["", "## 卡点记录",
              "| 卡点 | 已试路径 | 升级去向 | 时间 |",
              "|------|---------|----------|------|"]
    for e in stucks:
        ack = f"（ack: {','.join(e['acknowledged_anomalies'])}）" \
            if e.get("acknowledged_anomalies") else ""
        lines.append(f"| {e['at']} | {e['tried']} | {e['escalate']}{ack} | {e['ts']} |")
    resolves = anomaly_resolves(entries)
    anoms = [e for e in entries if e.get("type") == "anomaly"]
    lines += ["", "## 异常（anomaly）",
              "| id | 状态 | 区域 | 观测到的不一致 | 若成立则必须为假 | 解决/豁免 | 时间 |",
              "|----|------|------|---------------|-----------------|---------|------|"]
    for e in sorted(anoms, key=lambda x: _anomaly_sort_key(x.get("id"))):
        r = resolves.get(str(e.get("id")))
        status = r["status"] if r else "open"
        how = r["note"].replace("\n", " ⏎ ") if r else "—"
        if r and r.get("evidence"):
            how += f"｜证据: {r['evidence'].replace(chr(10), ' ⏎ ')}"
        lines.append(f"| {e['id']} | {status} | {e['region']} "
                     f"| {e['note'].replace(chr(10), ' ⏎ ')} "
                     f"| {e['consequence'].replace(chr(10), ' ⏎ ')} "
                     f"| {how} | {e['ts']} |")
    hyps = [e for e in entries if e.get("type") == "hypothesis"]
    hres = hypothesis_resolves(entries)
    lines += ["", "## 假设（hypothesis，open 在前）",
              "| id | 状态 | 假设 | 若为真则 | 若为假则 | 判定命令 | 关闭证据 | 时间 |",
              "|----|------|------|---------|---------|----------|---------|------|"]
    for e in sorted(hyps, key=lambda x: (str(x.get("id")) in hres,
                                         _hypothesis_sort_key(x.get("id")))):
        r = hres.get(str(e.get("id")))
        status = r["status"] if r else "open"
        ev = r["evidence"].replace("\n", " ⏎ ") if r else "—"
        lines.append(f"| {e['id']} | {status} | {e['text'].replace(chr(10), ' ⏎ ')} "
                     f"| {e['if_true'].replace(chr(10), ' ⏎ ')} "
                     f"| {e['if_false'].replace(chr(10), ' ⏎ ')} "
                     f"| {e['test'].replace(chr(10), ' ⏎ ')} "
                     f"| {ev} | {e['ts']} |")
    plans = [e for e in entries if e.get("type") == "plan"]
    lines += ["", "## 枚举计划（plan，铁律 13 轴矩阵+候选预算）",
              "| 时间 | 轴矩阵 | 候选预算 | 备注 |",
              "|------|--------|---------|------|"]
    for e in plans:
        lines.append(f"| {e['ts']} | {e['axes'].replace(chr(10), ' ⏎ ')} "
                     f"| {e['budget']} | {e.get('note', '').replace(chr(10), ' ⏎ ')} |")
    lines.append("")
    md.write_text("\n".join(lines), encoding="utf-8")
    return md


def cmd_render(args) -> int:
    binary = require_binary(args)
    md = render(binary)
    print(json.dumps({"ok": True, "md": str(md)}, ensure_ascii=False))
    return 0


_SCHEMA = {
    "observe": ({"type", "ts", "sha16", "region", "tool", "note", "visit"}, {}),
    "conclude": ({"type", "ts", "sha16", "id", "conclusion", "address",
                  "evidence", "source", "independent"},
                 {"source": {"read_views", "self-script", "decompiler-render",
                             "runtime-gdb", "runtime-oracle", "manual"},
                  "independent": {"yes", "no"},
                  "kind": {"finding", "flag", "model", "negative"}}),
    "anomaly": ({"type", "id", "status", "ts", "sha16", "region", "note",
                 "consequence"}, {"status": {"open"}}),
    "anomaly-resolve": ({"type", "anomaly_id", "status", "note", "ts"},
                        {"status": {"resolved", "waived"}}),
    "hypothesis": ({"type", "id", "status", "ts", "sha16", "text",
                    "if_true", "if_false", "test"}, {"status": {"open"}}),
    "hypothesis-resolve": ({"type", "hypothesis_id", "status", "evidence",
                            "ts"}, {"status": {"confirmed", "killed", "waived"}}),
    "plan": ({"type", "ts", "sha16", "axes", "budget", "note"}, {}),
    "brute": ({"type", "ts", "sha16", "keyspace", "eta", "why_no_smt"}, {}),
    "stuck": ({"type", "ts", "sha16", "at", "tried", "escalate"}, {}),
}


def cmd_validate(args) -> int:
    """机器校验台账条目的最小 schema（CI 回归/判据自动化的前提）。"""
    binary = require_binary(args)
    jsonl, _ = ledger_paths(binary)
    violations = []
    total = 0
    if jsonl.exists():
        for lineno, line in enumerate(jsonl.read_text(
                encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            total += 1
            try:
                e = json.loads(line)
            except json.JSONDecodeError as ex:
                violations.append(f"line {lineno}: JSON 解析失败 {ex}")
                continue
            t = e.get("type")
            if t not in _SCHEMA:
                violations.append(f"line {lineno}: 未知 type {t!r}")
                continue
            required, enums = _SCHEMA[t]
            missing = required - set(e)
            if missing:
                violations.append(
                    f"line {lineno}: type={t} 缺字段 {sorted(missing)}")
            for field, allowed in enums.items():
                if field in e and e[field] not in allowed:
                    violations.append(
                        f"line {lineno}: type={t} {field}={e[field]!r} "
                        f"不在取值域 {sorted(allowed)}")
            # 反向门只约束新条目：旧 resolve 无 evidence 字段不判违规；
            # 但新条目一旦写了 evidence 就必须非空（机械门在 resolve 写入侧）
            if t == "anomaly-resolve" and "evidence" in e \
                    and not str(e["evidence"]).strip():
                violations.append(
                    f"line {lineno}: type=anomaly-resolve evidence 为空字符串")
    out = {"ok": not violations, "ledger": str(jsonl), "entries": total,
           "violations": violations}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if not violations else 2


def main() -> int:
    ap = argparse.ArgumentParser(description="Iron Rule 7 mechanical circuit breaker")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("query", help="先查后析：分析前查台账")
    p.add_argument("binary")
    p.add_argument("--region")
    p.set_defaults(fn=cmd_query)

    p = sub.add_parser("observe", help="观察落账（同区回访强制 --delta）")
    p.add_argument("binary")
    p.add_argument("--region", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--note", required=True)
    p.add_argument("--delta")
    p.set_defaults(fn=cmd_observe)

    p = sub.add_parser("conclude", help="权威结论（写入即锁定；必须标注来源与独立性）")
    p.add_argument("binary")
    p.add_argument("--conclusion")
    p.add_argument("--conclusion-file", help="长文本走文件（UTF-8），绕开 shell 引号")
    p.add_argument("--address", help="地址型题目的结论位置（0x…）")
    p.add_argument("--locus", help="非地址型题目的结论位置：region: / channel: / proto: 前缀；与 --address 二选一")
    p.add_argument("--evidence")
    p.add_argument("--evidence-file", help="长文本走文件（UTF-8）")
    p.add_argument("--source", required=True,
                   choices=["read_views", "self-script", "decompiler-render",
                            "runtime-gdb", "runtime-oracle", "manual"],
                   help="读数来源；self-script 必须同时给 --harness")
    p.add_argument("--independent", required=True, choices=["yes", "no"],
                   help="是否有第二独立来源交叉印证；no → render 标 UNVERIFIED")
    p.add_argument("--harness", help="source=self-script 时必填：脚本路径+版本")
    p.add_argument("--quote", help="结论所依据的工具输出原文（verbatim）")
    p.add_argument("--quote-file", help="quote 长文本走文件（UTF-8）")
    p.add_argument("--id", help="字符串/整数均可（C1、Q5-1…）；缺省 = 下一个空闲整数")
    p.add_argument("--overturn", action="store_true")
    p.add_argument("--kind", choices=["finding", "flag", "model", "negative"], default="finding",
                   help="flag=flag/答案类结论：必须配 --program-accept（铁律 10⑤ 硬门），"
                        "且不允许 --source self-script；"
                        "model=模型/反演闭合声明：必须配 --anchor（铁律 10⑥ 硬门："
                        "L2 左逆锚定 inv(fwd(已知答案))==已知答案 的实测输出）；"
                        "negative=可达性/存在类否定结论：必须配 --proof "
                        "static-constraint|dynamic-forced（铁律 10⑦ 硬门："
                        "观测缺失 ≠ 不存在）")
    p.add_argument("--proof",
                   help="kind=negative 必填：\"static-constraint: <每条路径不可满足的约束>\" "
                        "或 \"dynamic-forced: <patch 强制到达后目标仍不执行的实测>\"")
    p.add_argument("--proof-file", help="proof 长文本走文件（UTF-8）")
    p.add_argument("--program-accept",
                   help="kind=flag 必填：未修改原程序/平台接受候选输入的实测记录"
                        "（投喂命令 + 成功响应原文）")
    p.add_argument("--program-accept-file", help="program-accept 长文本走文件（UTF-8）")
    p.add_argument("--anchor",
                   help="kind=model 必填：L2 左逆锚定证据（inv(fwd(X_known))==X_known "
                        "的断言+实测输出）；fwd(inv(B))==B 恒真不算")
    p.add_argument("--anchor-file", help="anchor 长文本走文件（UTF-8）")
    p.set_defaults(fn=cmd_conclude)

    p = sub.add_parser("anomaly", help="异常落账（铁律 12：不一致必须转成可检验假设，--consequence 必填）")
    p.add_argument("binary")
    p.add_argument("--region", required=True)
    p.add_argument("--note", required=True, help="观测到的不一致")
    p.add_argument("--consequence", required=True,
                   help="若该不一致成立，什么必须为假（可检验的推论）")
    p.set_defaults(fn=cmd_anomaly)

    p = sub.add_parser("resolve", help="关闭异常：--note 如何解决 + --evidence 可检验证据（机械门，缺证据 exit 2）/ --waive 为何豁免（二选一）")
    p.add_argument("binary")
    p.add_argument("--anomaly", required=True, help="anomaly id（A1、A2…）")
    p.add_argument("--note", help="如何解决的")
    p.add_argument("--evidence", help="可检验证据（命令/地址/读数）；--note 关闭时必填（反向门）")
    p.add_argument("--evidence-file", help="evidence 长文本走文件（UTF-8）")
    p.add_argument("--waive", help="为何豁免（工具缺失等客观不可查）")
    p.set_defaults(fn=cmd_resolve)

    p = sub.add_parser("hypothesis", help="可检验假设落账（铁律 4：不一致必须转成可检验假设）；"
                                          "--resolve-id 关闭时必须 --evidence（反向门，缺证据 exit 2）")
    p.add_argument("binary")
    p.add_argument("--text", help="假设内容（H）")
    p.add_argument("--if-true", help="若为真，下一步做什么（P）")
    p.add_argument("--if-false", help="若为假，下一步做什么（Q）")
    p.add_argument("--test", help="判定命令（可复现）")
    p.add_argument("--id", help="缺省 = 下一个空闲 H<int>")
    p.add_argument("--resolve-id", help="关闭模式：要关闭的 hypothesis id（H1、H2…）")
    p.add_argument("--status", choices=["confirmed", "killed", "waived"],
                   help="关闭模式必填：证实 / 证伪 / 豁免（客观不可检验或已被后续结论取代）")
    p.add_argument("--evidence", help="confirmed/killed 必填：检验命令的实际输出/读数（反向门）")
    p.add_argument("--evidence-file", help="evidence 长文本走文件（UTF-8）")
    p.add_argument("--waive", help="status=waived 必填：豁免理由（强制入账，render 单列可见）")
    p.set_defaults(fn=cmd_hypothesis)

    p = sub.add_parser("plan", help="枚举计划落账（铁律 13：轴矩阵+候选预算，禁止只写在聊天里）")
    p.add_argument("binary")
    p.add_argument("--axes", required=True,
                   help="轴矩阵原文，如 \"charset(95) x order(2) x pack(3)\"")
    p.add_argument("--budget", required=True, type=int, help="候选预算（总数）")
    p.add_argument("--note", help="剪轴理由/备注")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("brute", help="爆破登记（铁律 13 约束系统路由闸：候选空间 ≥ 2^28 的"
                                     "自建枚举开跑前必须登记，gate_bruteforce 查此账）")
    p.add_argument("binary")
    p.add_argument("--keyspace", required=True,
                   help="候选空间大小，支持 2**31 / 0x80000000 / 1e6 / 95*8*3 形式")
    p.add_argument("--eta", required=True, help="预计耗时（如 \"25min @ 8 线程\"）")
    p.add_argument("--why-no-smt", required=True,
                   help="为何不走 z3/SMT：①密码学黑盒比对（KDF/加解密输出比对）"
                        "或 ②SMT 已证不可行（unsat/超时证据）")
    p.add_argument("--tool", help="爆破载体（自写 C/OpenMP、hashcat 模式等）")
    p.set_defaults(fn=cmd_brute)

    p = sub.add_parser("stuck", help="卡点必记（存在 open anomaly 时必须 --ack 全部列出；"
                                     "本样本已有 stuck 时，tried/escalate 与上次雷同或"
                                     "escalate 技术类落在已试清单内 → 拒收，正当同类"
                                     "重试加 --note 说明差异点）")
    p.add_argument("binary")
    p.add_argument("--at", required=True)
    p.add_argument("--tried", required=True)
    p.add_argument("--escalate", required=True)
    p.add_argument("--ack", help="逗号分隔的全部 open anomaly id（\"A1,A3\"），"
                                 "语义：我知道这些没查")
    p.add_argument("--note", help="换路校验的豁免说明：与上次 stuck 的差异点"
                                  "（同类不同法的正当重试必填）")
    p.add_argument("--ack-negatives", dest="ack_negatives",
                   help="存在活跃 negative conclude 时必填：逐条说明升级路径"
                        "为何不被这些否定覆盖（≥20 字）")
    p.set_defaults(fn=cmd_stuck)

    p = sub.add_parser("status", help="台账总览 + 回访热点 + （可选）脚本 churn 覆盖度信号")
    p.add_argument("binary")
    p.add_argument("--workdir", help="题目工作目录：统计 *.py 脚本数 ÷ 台账条目数，>5 打印 churn 警告")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("render", help="重建 .ledger.md 人读视图")
    p.add_argument("binary")
    p.set_defaults(fn=cmd_render)

    p = sub.add_parser("validate", help="机器校验台账条目最小 schema（CI 判据用）")
    p.add_argument("binary")
    p.set_defaults(fn=cmd_validate)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
