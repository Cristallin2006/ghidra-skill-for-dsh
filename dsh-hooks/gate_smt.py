#!/usr/bin/env python
"""gate_smt.py - PreToolUse SMT 前置闸：z3 之前必须先过剥离路由（铁律 6/13 机械版）。

判例 be20d7dc（跳过 peel 直接 z3，40 min 全 unknown 丢 flag）与 47246ce9
（peel 检出递推段后直奔 z3，模型连修 4 次未收敛，47 min 无 flag）共同的
前置事实：「手上有直线程序时，任何求逆/SMT 之前 MUST 先跑 peel_inverse.py」
是纯文字纪律，执行率靠自觉。本闸把它变成机械门——与 gate_bruteforce 对称：
那扇门拦「绕过 SMT 去爆破」，这扇门拦「绕过剥离去 SMT」。

判定（全部满足才 exit 2 阻断）：
  1. bash 命令文本（含 heredoc 脚本体）或 Write 的文件内容命中 z3 指纹
     （import z3 / from z3 / z3. 调用）——z3 是唯一 SMT 通道指纹；
  2. 存在 12h 内活跃台账（否则不是逆向任务语境，开发会话的 z3 不拦）；
  3. 活跃台账全文无 peel/cone 痕迹——剥离路由从未对本样本运行过，
     也没有「peel 不适用」的结论落账。

出口（全部低成本，速度坎不是墙）：
  · 手上有 ssa_reconstruct/直线程序 -> 先跑 peel_inverse.py（检出段则
    --emit-solver 生成骨架逐层反解，无干净结构转 cone_invert.py）；
  · peel 结构性不适用 -> ledger.py conclude 落账一句「peel 不适用 + 理由」
    （含 "peel" 字样即满足痕迹检查）；
  · z3 用于验证而非求逆（peel 已跑过）-> 台账已有 peel 痕迹，天然放行。

豁免：ledger.py/doctor.py 等台账命令、skill 自带脚本（/scripts/ 路径）、
peel_inverse/cone_invert 自身。任何内部异常 -> 放行（exit 0）。
"""
import json
import re
import sys
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OUT = Path.home() / ".dsh" / "ghidra-workspace" / "out"
LEDGER_ACTIVE_SEC = 12 * 3600

Z3 = re.compile(r"(?:import\s+z3|from\s+z3|\bz3\s*\.)", re.IGNORECASE)
EXEMPT = re.compile(
    r"ledger\.py|doctor\.py|peel_inverse|cone_invert|peel_solve|"
    r"/\.dsh/skills/|site-packages", re.IGNORECASE)
PEEL_TRACE = ("peel", "cone_invert", "剥离", "锥形反推")


def active_ledgers():
    if not OUT.is_dir():
        return []
    now = time.time()
    res = []
    for j in OUT.glob("*.ledger.jsonl"):
        try:
            if now - j.stat().st_mtime <= LEDGER_ACTIVE_SEC:
                res.append(j)
        except OSError:
            continue
    return res


def has_peel_trace(ledgers) -> bool:
    for j in ledgers:
        try:
            text = j.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if any(k in text for k in PEEL_TRACE):
            return True
    return False


def block(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 2


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    # bash 侧看 command（含 heredoc 脚本体），Write 侧看 file_path+content
    text = str(ti.get("command") or ti.get("cmd") or "")
    target = str(ti.get("file_path") or ti.get("path") or "")
    content = str(ti.get("content") or "")
    blob = text + "\n" + content
    if not blob.strip() or not Z3.search(blob):
        return 0
    if EXEMPT.search(blob) or EXEMPT.search(target):
        return 0
    ledgers = active_ledgers()
    if not ledgers:
        return 0
    if has_peel_trace(ledgers):
        return 0
    return block(
        "[gate_smt · 铁律6/13 剥离前置闸] 检测到 z3/SMT 调用，但活跃台账全程"
        "无 peel/cone 痕迹——「手上有直线程序时，任何求逆/SMT 之前先跑 "
        "peel_inverse.py」此前是纯文字纪律（执行率靠自觉），本闸是它的机械版。\n"
        "判例：be20d7dc 跳过剥离直接 z3，40 min 全 unknown 丢 flag；"
        "47246ce9 检出递推段后直奔 z3，模型连修 4 次未收敛，47 min 无 flag。\n"
        "三选一（皆为低成本出口）：\n"
        "  ① 手上有 ssa_reconstruct/直线程序 -> 先跑 "
        "python3 ~/.dsh/skills/ghidra-core/scripts/peel_inverse.py <recon>"
        "（检出段 -> --emit-solver 骨架逐层反解；无干净结构 -> cone_invert.py）\n"
        "  ② peel 结构性不适用 -> ledger.py conclude <样本> 落账一句"
        "「peel 不适用 + 理由」（是否定性结论，按铁律 10 带证据）\n"
        "  ③ z3 是验证而非求逆且 peel 已跑过 -> 台账已有痕迹，不会拦你"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_smt hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
