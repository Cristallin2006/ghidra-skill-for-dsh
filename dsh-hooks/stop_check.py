#!/usr/bin/env python
"""stop_check.py - Stop 收尾检查（默认停用，见 README.md §L4）。

Stop 事件时：若 ~/.dsh/ghidra-workspace/out/ 下存在「有 observe 但零
conclude 零 stuck」的台账，deny 强制继续并提示核对。

风险：无法区分台账是本会话还是历史会话留下的（payload 不含会话起点），
对非逆向目录可能误判。所以默认不挂进 hooks.json——L1-L3 验证稳定后
再决定启用。

启用方法：hooks.json 加：
  "Stop": [{"hooks": [{"type": "command",
    "command": "python \"${CLAUDE_PLUGIN_ROOT}/stop_check.py\"", "timeout": 10}]}]
"""
import json
import sys
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main() -> int:
    sys.stdin.read()
    out = Path.home() / ".dsh" / "ghidra-workspace" / "out"
    if not out.is_dir():
        return 0
    open_ended = []
    for j in sorted(out.glob("*.ledger.jsonl"), key=lambda p: p.stat().st_mtime,
                    reverse=True)[:5]:
        types = set()
        try:
            for line in j.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    types.add(json.loads(line).get("type"))
        except Exception:
            continue
        if "observe" in types and not ({"conclude", "stuck"} & types):
            open_ended.append(j.name)
    if not open_ended:
        return 0
    msg = (f"[stop_check] 台账有观察但无结论/卡点记录：{', '.join(open_ended)}。"
           f"交付前 python ledger.py status <样本> 核对：结论是否落账？"
           f"未解决的异常是否 anomaly 记录？确认无遗漏再收尾。")
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"stop_check hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
