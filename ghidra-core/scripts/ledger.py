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
           --source S --independent yes|no [--harness H] [--quote Q] [--id K] [--overturn]
  anomaly  <binary> --region R --note N --consequence C
  resolve  <binary> --anomaly ID (--note N | --waive W)
  stuck    <binary> --at R --tried "A,B" --escalate TARGET [--ack "A1,A3"]
  status   <binary>
  render   <binary>

Anomaly discipline (Iron Rule 12): an observed inconsistency MUST be booked
as a testable hypothesis via `anomaly` (--consequence answers "if this holds,
what else must be false"), never downgraded to "noise / ambiguity to be
enumerated later". Anomalies stay `open` until a matching `resolve` entry
(--note how it was resolved, or --waive why it is objectively unverifiable,
e.g. missing tooling) is appended; old lines are never rewritten. While any
anomaly is open, `stuck` is REFUSED (exit 2) unless --ack lists every open
anomaly id ("I know these are unchecked") — ack or waive unblocks stuck, so
missing tooling can never deadlock the loop.

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

Region syntax: 0x1000-0x1100 | 0x1000+0x40 | 0x1000 (point) | check_flag
(name) | name:literal (force name, for names that look like hex).
Exit codes: 0 ok, 1 usage/io error, 2 circuit breaker fired (read stdout).
"""
from __future__ import annotations

import argparse
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
    if not (args.address or "").strip():
        print(json.dumps({"ok": False, "error": "--address 必填"},
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

    entry = {"type": "conclude", "ts": now(), "sha16": sha16(binary),
             "id": cid, "conclusion": conclusion,
             "address": args.address.strip(), "region": args.address.strip(),
             "evidence": evidence,
             "source": args.source, "independent": args.independent}
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
                          "error": "--note 与 --waive 二选一，必须且只能给一个"},
                         ensure_ascii=False))
        return 1
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
    append_entry(jsonl, entry)
    auto_render(binary)
    print(json.dumps({"ok": True, "anomaly": aid, "status": entry["status"]},
                     ensure_ascii=False))
    return 0


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
    entry = {"type": "stuck", "ts": now(), "sha16": sha16(binary),
             "at": args.at.strip(), "tried": args.tried.strip(),
             "escalate": args.escalate.strip()}
    if acknowledged:
        entry["acknowledged_anomalies"] = acknowledged
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
        "stucks": [e for e in entries if e.get("type") == "stuck"],
        "open_anomalies": open_anomalies(entries),
        "revisit_hotspots": {r: n for r, n in sorted(hot.items(),
                             key=lambda kv: -kv[1]) if n >= 2},
    }
    if len(obs) >= 5 and not anoms:
        out["hint"] = (f"已入账 {len(obs)} 次观察但 0 条 anomaly。若期间遇到过任何不一致"
                       "（工具误报/读数异常/假设冲突/harness 异常），按铁律 12 用 "
                       "ledger.py anomaly --consequence 落账，禁止降级为噪声")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def render(binary: Path) -> Path:
    jsonl, md = ledger_paths(binary)
    entries = load_entries(jsonl)
    sha = next((e["sha16"] for e in reversed(entries) if "sha16" in e),
               sha16(binary))

    latest: dict[int, dict] = {}
    for e in entries:
        if e.get("type") == "conclude":
            latest[e["id"]] = e
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
        "| # | 结论 | 地址 | 证据（命令/输出要点） | 来源 | 独立验证 | 时间 |",
        "|---|------|------|----------------------|------|---------|------|",
    ]
    for cid in sorted(latest, key=lambda k: (0, k) if isinstance(k, int)
                      else (1, str(k))):
        e = latest[cid]
        concl = e["conclusion"].replace("\n", " ⏎ ")
        if "overturns" in e:
            concl += f"（推翻：{e['overturns']['conclusion']}）"
        source = e.get("source", "—")
        if e.get("harness"):
            source += f"({e['harness']})"
        indep = e.get("independent", "—")
        if indep == "no":
            concl = "⚠UNVERIFIED " + concl
        lines.append(f"| {cid} | {concl} | {e['address']} | {e['evidence'].replace(chr(10), ' ⏎ ')} "
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
        lines.append(f"| {e['id']} | {status} | {e['region']} "
                     f"| {e['note'].replace(chr(10), ' ⏎ ')} "
                     f"| {e['consequence'].replace(chr(10), ' ⏎ ')} "
                     f"| {how} | {e['ts']} |")
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
                  "independent": {"yes", "no"}}),
    "anomaly": ({"type", "id", "status", "ts", "sha16", "region", "note",
                 "consequence"}, {"status": {"open"}}),
    "anomaly-resolve": ({"type", "anomaly_id", "status", "note", "ts"},
                        {"status": {"resolved", "waived"}}),
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
    p.add_argument("--address", required=True)
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
    p.set_defaults(fn=cmd_conclude)

    p = sub.add_parser("anomaly", help="异常落账（铁律 12：不一致必须转成可检验假设，--consequence 必填）")
    p.add_argument("binary")
    p.add_argument("--region", required=True)
    p.add_argument("--note", required=True, help="观测到的不一致")
    p.add_argument("--consequence", required=True,
                   help="若该不一致成立，什么必须为假（可检验的推论）")
    p.set_defaults(fn=cmd_anomaly)

    p = sub.add_parser("resolve", help="关闭异常：--note 如何解决 / --waive 为何豁免（二选一）")
    p.add_argument("binary")
    p.add_argument("--anomaly", required=True, help="anomaly id（A1、A2…）")
    p.add_argument("--note", help="如何解决的")
    p.add_argument("--waive", help="为何豁免（工具缺失等客观不可查）")
    p.set_defaults(fn=cmd_resolve)

    p = sub.add_parser("stuck", help="卡点必记（存在 open anomaly 时必须 --ack 全部列出）")
    p.add_argument("binary")
    p.add_argument("--at", required=True)
    p.add_argument("--tried", required=True)
    p.add_argument("--escalate", required=True)
    p.add_argument("--ack", help="逗号分隔的全部 open anomaly id（\"A1,A3\"），"
                                 "语义：我知道这些没查")
    p.set_defaults(fn=cmd_stuck)

    p = sub.add_parser("status", help="台账总览 + 回访热点")
    p.add_argument("binary")
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
