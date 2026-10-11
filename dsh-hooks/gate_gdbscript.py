#!/usr/bin/env python
"""gate_gdbscript.py - PreToolUse gdb 手写脚本计数门：第二个 .gdb 起禁抄样板。

修的是 51bb491d 暴露的 gdbkit 不可达：agent 全程手写 8 个 gdb 脚本
（g_meas/g_kdf/g_s3/g_flag/g_mask/g_try0/g_force/g_gate），样板互相抄、
漂移出错（SIGTRAP 不能 pass 这类坑每个脚本各踩一遍），而
re-dynamic/scripts/gdbkit.py（日志/容错读写/断点类/Force/ucontext/trace
全封装）零使用——规则写在 re-dynamic SKILL.md 里，但该 skill 没被加载，
规则不可见。skill 加载由 gate_sample 的加载门管；本门管「加载之后仍
惯性手写」的计数熔断，与 re-dynamic 的 gdb 阶梯同规：第一个手写脚本
放行（快速探针合理），第二个起 exit 2。

判定：命令含对 *.gdb 文件的重定向写入（cat > x.gdb <<EOF / > x.gdb /
tee x.gdb）。逃生门：脚本内容或命令里带 "gdbkit-gap:" 注释（声明
gdbkit 不覆盖的能力）则放行并留痕——防死锁，也顺便收集 gdbkit 缺口。

计数按 session_id 存 OUT/.gdb-writes.json（24h TTL）。读取/执行已有
.gdb 不计（gdb -x old.gdb 不含重定向写入）。任何内部异常 -> 放行。

输入：stdin PreToolUse payload {"tool_input": {"command": ...},
"session_id": ...}。输出：放行 = exit 0；阻断 = exit 2 + stderr。
"""
import json
import os
import re
import sys
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OUT = Path(os.environ.get("DSH_HOME") or str(Path.home() / ".dsh")) \
    / "ghidra-workspace" / "out"
MARKER = OUT / ".gdb-writes.json"
TTL = 24 * 3600

# 对 .gdb 文件的重定向写入 / tee 写入；'.' 即词边界，\bgdb\b 够不着文件名
# 里的 "gdb"，这里显式匹配扩展名。
GDB_WRITE = re.compile(
    r"(?:>>?\s*|(?:\btee\b)[^\n|;]*?\s)([^\s;|\"']+\.gdb)\b")
ESCAPE = re.compile(r"gdbkit-gap:")


def load_marker():
    try:
        return json.loads(MARKER.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_marker(m):
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        now = time.time()
        m = {k: v for k, v in m.items()
             if now - float((v or {}).get("t") or 0) < TTL}
        MARKER.write_text(json.dumps(m), encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ti.get("cmd") or ""
    if not isinstance(cmd, str):
        cmd = ""
    # Bash 重定向写入 或 Write 工具直写 .gdb（防换工具绕行）
    fp = ti.get("file_path") or ""
    is_write_tool = isinstance(fp, str) and fp.strip("\"'").endswith(".gdb")
    content = ti.get("content") or ""
    if not GDB_WRITE.search(cmd) and not is_write_tool:
        return 0
    if ESCAPE.search(cmd) or ESCAPE.search(str(content)):
        return 0  # 逃生门：声明了 gdbkit 缺口，放行留痕（内容本身即痕）

    session_id = str(payload.get("session_id") or "unknown")
    marker = load_marker()
    ent = marker.get(session_id) or {}
    n = int(ent.get("n") or 0) + 1
    marker[session_id] = {"n": n, "t": time.time()}
    save_marker(marker)

    if n == 1:
        return 0  # 第一个手写脚本放行（快速探针合理）；警告由 inject_rules R4 给
    msg = (
        f"[gate_gdbscript · re-dynamic gdb 阶梯] 本会话第 {n} 个手写 .gdb "
        f"脚本——第二个起禁止抄样板（51bb491d：手写 8 个，SIGTRAP 类坑逐个踩）。\n"
        f"改用 gdbkit 封装（日志/容错 rd-wr/断点类/Force 写值/ucontext 读写/"
        f"sig_pass/trace_pcs/dump_ranges 全是现成的）：\n"
        f"  python3 ~/.dsh/skills/re-dynamic/scripts/gdbkit.py --help\n"
        f"gdbkit 确实不覆盖本次能力时：在命令里加注释 # gdbkit-gap: <缺什么> "
        f"后重试，本门放行。"
    )
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_gdbscript hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
