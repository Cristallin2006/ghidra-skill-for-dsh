#!/usr/bin/env python
"""gate_longrun.py - PreToolUse 长任务落盘门：timeout 长任务必须走 guarded_run。

matcher "Pwsh|pwsh|Bash|bash"。chal session 事故：bf_block0 爆破用
`nohup timeout 1200 python3 bf.py > log 2>&1 &` 跑——python 块缓冲 +
timeout 到点 SIGTERM，20 分钟计算结果一个字节都没落盘。

判定逻辑（全部满足才 exit 2 阻断）：
  1. 命令含 `timeout <秒>` 且秒数 >= LONG_SEC
  2. 命令用 python/python3 跑 .py 脚本（长计算的特征）
  3. 未走 guarded_run.py（它自带 tee 落盘 + 无缓冲 + 杀前保全）

短 timeout（<LONG_SEC）的探测命令不受影响。任何异常 -> 放行（exit 0）。
"""
import json
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

LONG_SEC = 300
TIMEOUT_RE = re.compile(r"\btimeout\s+(?:-[a-zA-Z]+\s+)*(\d+)\b")
PY_SCRIPT_RE = re.compile(r"\bpython3?(?:\.\d+)?(?:\.exe)?\b[^|;&]*\.py\b")


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ti.get("cmd") or ""
    if not isinstance(cmd, str) or not cmd.strip():
        return 0
    if "guarded_run" in cmd:
        return 0
    m = TIMEOUT_RE.search(cmd)
    if not m or int(m.group(1)) < LONG_SEC:
        return 0
    if not PY_SCRIPT_RE.search(cmd):
        return 0
    msg = (
        "[gate_longrun · 长任务落盘门] 检测到 timeout 长任务直接跑 python 脚本。\n"
        "裸 `timeout N python3 x.py > log` 的双重陷阱：python 块缓冲 + 到点 "
        "SIGTERM = 部分结果一个字节都不落盘（chal session bf_block0："
        "20 分钟爆破日志 0 字节）。\n"
        "改用 guarded_run.py（tee 落盘 + 无缓冲转发 + 杀前保全 + 心跳）：\n"
        "  python3 ~/.dsh/skills/ghidra-core/scripts/guarded_run.py \\\n"
        "    --timeout 1200 --log out/job.log -- python3 -u x.py [args]\n"
        "若确属一次性短探测（误伤）：把 timeout 降到 300 秒以内即不触发。"
    )
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_longrun hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
