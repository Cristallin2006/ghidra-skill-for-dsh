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

可重触发（判例 116cdc04：stuck 落账一次后前置条件永久解除，
之后又堆 20+ 脚本零拦截）：stuck 存在时，统计「最近一次台账接触
（任一条目落账）之后」目录内新增的 .py 数，再满 CHURN_LIMIT 个则重新
熔断——一次台账接触换一批脚本额度，额度用尽需要新的落账续期。
条目时间戳不可解析时安全回退为放行。

定位：速度坎，逼一次台账接触，不防蓄意绕过（heredoc 写文件不经 Write）。
任何内部异常 -> 放行（exit 0）。
"""
import json
import sys
import time
from datetime import datetime
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


def active_ledger_stuck_info() -> tuple[bool, float | None] | None:
    """无活跃台账返回 None；否则返回 (有无 stuck, 最近任一条目落账 epoch 或 None)。

    额度锚点用「任一类型条目的最近 ts」而非仅 stuck：stuck 之后的
    observe/conclude/resolve 同样是台账接触，接触即续额度。
    """
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
    has_stuck = False
    latest: float | None = None
    for j in ledgers:
        try:
            for line in j.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                if e.get("type") == "stuck":
                    has_stuck = True
                try:
                    t = datetime.strptime(e.get("ts", ""),
                                          "%Y-%m-%d %H:%M:%S").timestamp()
                    latest = t if latest is None else max(latest, t)
                except ValueError:
                    continue
        except Exception:
            continue
    return has_stuck, latest


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
    info = active_ledger_stuck_info()
    if info is None:
        return 0
    has_stuck, latest_touch = info
    if has_stuck:
        if latest_touch is None:
            return 0  # 条目时间戳不可解析，安全回退
        after = [f for f in recent if f.stat().st_mtime > latest_touch]
        if len(after) < CHURN_LIMIT:
            return 0  # 上次台账接触换来的脚本额度未用尽，放行
        msg = (
            f"[gate_churn · 铁律6 拟合熔断·再触发] 目录 {parent} 自最近一次 "
            f"台账落账后又新增 {len(after)} 个 .py 脚本。\n"
            "上次卡点落账换来的脚本额度已用尽（判例 116cdc04：stuck 落账一次后"
            "熔断永久解除，之后又堆 20+ 脚本零拦截）。\n"
            "继续写脚本前先把升级流程走闭环：\n"
            "  ① 上一卡点的升级去向执行完了吗？结果用 ledger.py conclude/"
            "resolve 落账；\n"
            "  ② 又卡住了就落新的 stuck：python ~/.dsh/skills/ghidra-core/"
            "scripts/ledger.py stuck <样本> --at <卡点> --tried <已试路径> "
            "--escalate <升级去向>\n"
            "  ③ 若新脚本与卡点无关（正当推进），在台账用 observe/conclude "
            "说明进展即可续额度。"
        )
        print(msg, file=sys.stderr)
        return 2
    msg = (
        f"[gate_churn · 铁律6 拟合熔断] 目录 {parent} 近 24h 已有 "
        f"{len(recent)} 个 .py 脚本，且活跃台账 stuck 条目为 0。\n"
        "脚本堆积 + 零卡点落账 = 「同一思路换措辞重试」的机械签名"
        "（chal session：26 脚本 / stucks=0）。\n"
        "继续写脚本前先做其一：\n"
        "  ① python ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本> "
        "--at <卡点> --tried <已试路径> --escalate <升级去向>\n"
        "  ② 拟合/接线连错 2 次的强制升级：z3/SMT 求解，或 "
        "emulate_blob / emulate-function 仿真取数——禁止写第 3 个手写拟合脚本。"
        "升级前先查依赖图：存在可剥离递推/可逆算子时优先手工剥离"
        "（Reverse-chal：掩码二阶递推逐层反解，z3 60s 超时反而没用上）"
    )
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_churn hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
