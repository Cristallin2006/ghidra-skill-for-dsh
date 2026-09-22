#!/usr/bin/env python
"""session_start.py - dsh SessionStart/SubagentStart 纪律注入（hooks-claude-code 桥）。

会话/子代理创建时把压缩版逆向纪律卡注入上下文（additionalContext ->
agent.inject user message）。不依赖 agent 自觉读 SKILL.md——catalog 里只有
description，铁律全文在 ghidra-core §1，这张卡是常驻上下文的最低保障。

输入：stdin 的 hook payload JSON（含 hook_event_name）。
输出：stdout 一行 JSON {"hookSpecificOutput": {...}}。任何异常都静默 exit 0
（注入失败不许影响会话创建）。
"""
import json
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CARD = """\
[逆向纪律卡 · ghidra-skill-for-dsh，铁律全文见 ghidra-core/SKILL.md §1]
1. 逆向/流量/脱壳/漏洞任务：动手前先用 skill 工具加载对应 SKILL.md 全文；拿到样本先 re-triage 分诊，不凭扩展名猜。
2. 一切区域级观察走 ledger.py observe、结论走 conclude --source --independent；分析任何区域前先 ledger.py query。
3. 同区回访必须带 --delta（答"这次和上次差在哪"）；肉眼 hex 同区最多 2 次，第 3 次机械拒绝。
4. 观测到不一致（重复键冲突/两次读数不同）必须 ledger.py anomaly --consequence 落账，禁止降级为"噪声/待枚举"。
5. 枚举类解码先出轴矩阵+候选预算；无 oracle（hash/一致性/校验位）不跑全交叉。
6. 卡住先 ledger.py stuck（有 open anomaly 须 --ack 或 resolve --waive）再升级工具层级，禁止换措辞重试同一路径。"""


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = "SessionStart"
        if raw.strip():
            event = json.loads(raw).get("hook_event_name", event)
        json.dump({"hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": CARD,
        }}, sys.stdout, ensure_ascii=False)
    except Exception as e:
        print(f"session_start hook warning: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
