#!/usr/bin/env python
"""gate_churn.py - PreToolUse 拟合熔断门：脚本堆积 + 零 stuck 落账 = 阻断。

matcher "Write|write"。chal session 事故：agent 在 /tmp 下连写 26 个一次性
拟合/解析脚本（wiring.py → wiring2.py → fitwiring.py → …），同一思路换措辞
重试 5 次，台账 stucks 恒为 0——铁律 6/7 的文字纪律完全没有触发。

判定逻辑（全部满足才 exit 2 阻断）：
  1. 写入目标是 .py 文件
  2. 不在豁免根下（~/.dsh、site-packages、node_modules、.git、venv）
  3. 目标目录下近 24h 内改动的 .py 已达 CHURN_LIMIT 个（本次是第 N+1 个）
  4. 存在活跃台账（out/*.ledger.jsonl 12h 内有改动）且其 stuck 条目为 0
     —— 落过 stuck 说明已按铁律 6 走升级流程，放行

定位：速度坎，逼一次台账接触，不防蓄意绕过（heredoc 写文件不经 Write）。
任何内部异常 -> 放行（exit 0）。
"""
import json
import sys
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CHURN_LIMIT = 8            # 目录内近 24h .py 达到此数后，下一个触发熔断
RECENT_SEC = 24 * 3600     # 脚本新鲜度窗口
LEDGER_ACTIVE_SEC = 12 * 3600

EXEMPT_PARTS = {".dsh", ".git", "node_modules", "site-packages",
                "__pycache__", ".venv", "venv"}


def exempt(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return bool(parts & EXEMPT_PARTS)


def active_ledger_has_stuck() -> bool | None:
    """有活跃台账时返回其 stuck 条目数>0；无活跃台账返回 None。"""
    out = Path.home() / ".dsh" / "ghidra-workspace" / "out"
    if not out.is_dir():
        return None
    now = time.time()
    ledgers = []
    for j in out.glob("*.ledger.jsonl"):
        try:
            if now - j.stat().st_mtime <= LEDGER_ACTIVE_SEC:
                ledgers.append(j)
        except OSError:
            continue
    if not ledgers:
        return None
    for j in ledgers:
        try:
            for line in j.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and json.loads(line).get("type") == "stuck":
                    return True
        except Exception:
            continue
    return False


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    target = ti.get("file_path") or ti.get("path") or ""
    if not isinstance(target, str) or not target.strip():
        return 0
    p = Path(target.strip())
    if p.suffix.lower() != ".py" or exempt(p):
        return 0
    parent = p.parent
    try:
        if not parent.is_dir():
            return 0
        now = time.time()
        recent = [f for f in parent.glob("*.py")
                  if f.is_file() and now - f.stat().st_mtime <= RECENT_SEC]
    except OSError:
        return 0
    if len(recent) < CHURN_LIMIT:
        return 0
    stuck_ok = active_ledger_has_stuck()
    if stuck_ok is None or stuck_ok:
        return 0
    msg = (
        f"[gate_churn · 铁律6 拟合熔断] 目录 {parent} 近 24h 已有 "
        f"{len(recent)} 个 .py 脚本，且活跃台账 stuck 条目为 0。\n"
        "脚本堆积 + 零卡点落账 = 「同一思路换措辞重试」的机械签名"
        "（chal session：26 脚本 / stucks=0）。\n"
        "继续写脚本前先做其一：\n"
        "  ① python ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本> "
        "--at <卡点> --tried <已试路径> --escalate <升级去向>\n"
        "  ② 拟合/接线连错 2 次的强制升级：z3/SMT 求解，或 "
        "emulate_blob / emulate-function 仿真取数——禁止写第 3 个手写拟合脚本"
    )
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_churn hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
