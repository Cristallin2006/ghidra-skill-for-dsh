#!/usr/bin/env python
"""stop_check.py - Stop 收尾检查（2026-09-26 起默认挂载，见 README.md §L4）。

Stop 事件时对最近活跃的台账做两类收尾核对，命中即 deny（exit 2）强制继续：

1. 烂尾台账：有 observe 但零 conclude 零 stuck（看了没记账）。
2. 铁律 10⑤：最新（未被同 id 推翻）的 kind=flag 结论缺 program_accept
   ——flag 的唯一合法 VERIFIED 证据是「未修改原程序/平台接受候选输入」，
   自写探针等价式不算（chal session 循环论证事故）。

只检查 mtime 在最近 RECENCY_SEC 内的台账，避免把历史会话的台账算进
本次收尾（旧版无时间窗，误报源）。hook 自身异常一律放行（exit 0）。
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

RECENCY_SEC = 12 * 3600  # 只收尾 12h 内活跃过的台账


def main() -> int:
    sys.stdin.read()
    out = Path.home() / ".dsh" / "ghidra-workspace" / "out"
    if not out.is_dir():
        return 0
    now = time.time()
    open_ended = []
    bad_flag = []
    for j in sorted(out.glob("*.ledger.jsonl"), key=lambda p: p.stat().st_mtime,
                    reverse=True)[:5]:
        try:
            if now - j.stat().st_mtime > RECENCY_SEC:
                continue
        except OSError:
            continue
        types = set()
        conclusions = []
        try:
            for line in j.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                types.add(e.get("type"))
                if e.get("type") == "conclude":
                    conclusions.append(e)
        except Exception:
            continue
        if "observe" in types and not ({"conclude", "stuck"} & types):
            open_ended.append(j.name)
        latest = {}
        for e in conclusions:
            latest[e.get("id")] = e
        for e in latest.values():
            if e.get("kind") == "flag" and not str(
                    e.get("program_accept") or "").strip():
                bad_flag.append(f"{j.name} 结论#{e.get('id')}")
    msgs = []
    if open_ended:
        msgs.append(
            f"台账有观察但无结论/卡点记录：{', '.join(open_ended)}。"
            "交付前 python ledger.py status <样本> 核对：结论是否落账？"
            "未解决的异常是否 anomaly 记录？")
    if bad_flag:
        msgs.append(
            f"flag 结论缺「程序接受」证据（铁律 10⑤）：{', '.join(bad_flag)}。"
            "flag 的唯一合法验证 = 未修改原程序/平台接受候选输入；"
            "补 ledger.py conclude --kind flag --program-accept \"投喂命令+成功响应\""
            " 或 --overturn 作废它。自写探针的等价式不是程序判定。")
    if not msgs:
        return 0
    print("[stop_check] " + "\n".join(msgs) + " 确认无遗漏再收尾。",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"stop_check hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
