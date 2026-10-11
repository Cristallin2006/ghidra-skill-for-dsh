#!/usr/bin/env python
"""inject_rules.py - PostToolUse 即时规则注入：规则在它被需要的那一秒出现。

修的是纪律卡的结构性失效（四根因诊断之 3）：t=0 一次性注入的长卡片在
长会话里注意力归零，且「规则」与「触发它的证据」在时间上分离——
「UD2 时 non-returning 不可信」该出现的时刻是 triage 输出 selfmod_signal
命中的那一秒，不是会话开头。本 hook 扫 PostToolUse 的 tool_response，
命中特征就把对应的那一条规则（含修复工具指针）单独注入上下文。

触发表（每条每会话只注入一次，dedupe marker 按 session_id+rule）：
  R1 selfmod_signal hit=true  -> 铁律 10⑦：non-returning/死代码判定不可信，
     修复用 noreturn_fix.py；dump 层重载用 rpc import-raw
  R2 "Could not recover jumptable" -> jt_resolve.py 一键解所有表基址
     （只解一张 = 解错一半），fatal 函数禁读伪码
  R3 triage lang_hints python_ext=true -> Cython 前置：先 §12 元数据 +
     frame_map 帧槽位真值，再建模（f862c151：无真值建模 128 变体盲搜）
  R4 命令写 *.gdb 脚本（重定向/tee/Write 工具）-> gdb 阶梯指针：第二个
     手写脚本起必须 gdbkit.py（51bb491d：手写 8 个脚本逐个踩坑）
  R5 命令含 set $pc/$rip/$eip/$eflags 跳分支 -> force compare 反模式 +
     runtime-dependent-verifier.md 配方指针（51bb491d/be6391dc：force
     gate 后派生值全错，仍 "下游校验仍失败"）
  R6 Write/命令里用 gdbkit Force( 且会话日志已有跨 run 不一致实锤 ->
     塌缩点前置指针（13ee6b0f：读了 runtime 配方却跳过 ①，force 过门
     20min 零产出；selector=runtime[0]&31 枚举 32 种即离线化）

R1-R3 扫 tool_response（证据在输出里），R4/R5 扫 tool_input.command
（证据在动作本身），R6 扫 command+Write content 并以会话日志为条件。
每条每会话只注入一次，dedupe marker 按 session_id+rule。

只注入指针级一句话（细节在 skill 里，agent 可按需加载）——注入本体也要
遵守低密度原则。失效方向（有意如此）：读不到/解析失败 -> 不注入；
matcher 仅 bash 系（rpc/脚本输出都经 bash）；不防蓄意绕过，目标是接住
「证据已在屏幕上但 t=0 卡片想不起来」的惯性。任何异常 -> 静默 exit 0。
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
MARKER = OUT / ".inject-rules.json"
MARKER_TTL = 24 * 3600  # marker 里每条的寿命：跨天的长会话允许重注入一次

RULES = [
    ("R1_selfmod",
     lambda t: '"selfmod_signal"' in t and '"hit": true' in t.replace("'", '"'),
     "[即时规则 · 铁律10⑦] triage 的 selfmod_signal 命中：本样本带自定义信号"
     "处理器/裸 UD2，反编译器的 non-returning、死代码、调用图截断判定一律"
     "不可信——handler 可改写保存的 RIP 让「非法指令」正常返回。下任何可达性"
     "结论前必须先答「handler 是否推进了保存的 RIP」并落 ledger.py hypothesis。"
     "修复工具：python3 ~/.dsh/skills/ghidra-core/scripts/noreturn_fix.py <bin>"
     "（体检 NoReturn+流切断点，--fix 清标志，--flow 补 fall-through）；"
     "解密层需 xref/反编译时：rpc_driver.py import-raw <原样本> <dump> "
     "--base 0xVA。否定结论走 conclude --kind negative --proof 硬门。"),
    ("R2_jumptable",
     lambda t: "Could not recover jumptable" in t,
     "[即时规则 · decompiler-pitfalls §3④] 检测到未恢复跳转表：禁止只解一张"
     "（多表共用索引时只解一张 = 解错一半）。一键解所有基址：python3 "
     "~/.dsh/skills/ghidra-core/scripts/jt_resolve.py <bin> <func-addr>；"
     "fatal 清单内函数禁读伪码，走 L1 汇编/L2 P-code。"),
    ("R3_python_ext",
     lambda t: '"python_ext": true' in t or '"python_ext":true' in t,
     "[即时规则 · re-triage Cython 前置] triage 报 python_ext=true：先用 §12 "
     "元数据（co_varnames 角色语义）+ frame_map.py 帧槽位真值钉变量角色，"
     "再建模——无真值建模 = 结构变体盲搜（f862c151：128 个手写变体零产出）。"
     "深挖前确认已加载 ghidra-static 全文（铁律 1）。"),
]

# 命令触发型（扫 tool_input.command，证据在动作本身而非输出）
CMD_RULES = [
    ("R4_gdbscript",
     lambda c: re.search(r">\s*[^\s;|]+\.gdb\b|\btee\s+\S+\.gdb\b", c),
     "[即时规则 · re-dynamic gdb 阶梯] 检测到手写 .gdb 脚本：第一个可以当"
     "快速探针，第二个起必须改用 gdbkit.py（51bb491d：手写 8 个脚本，"
     "SIGTRAP 类坑逐个踩）——python3 "
     "~/.dsh/skills/re-dynamic/scripts/gdbkit.py --help；"
     "未加载 re-dynamic 全文先加载。"),
    ("R5_forcecmp",
     lambda c: re.search(r"set\s+\$(?:pc|rip|eip|eflags|flags)\b", c),
     "[即时规则 · force compare 反模式] 检测到 set $pc/$eflags 跳过比较"
     "分支：这只是骗过程序，后续派生值全错（51bb491d/be6391dc：force gate "
     "后仍「下游校验仍失败」）。若卡点涉及运行时熵（PID/ASLR/时间戳/"
     "栈地址），正确路线见 ghidra-static references/"
     "runtime-dependent-verifier.md：找熵塌缩点 → 小空间枚举 → 活进程现读"
     " → 本 run 组装。"),
]

# R6：gdbkit Force( × 跨 run 不一致实锤 → 塌缩点前置。
# Force( 是 gdbkit 的 force compare API（R5 的 set $pc 正则盖不住，且常写
# 在 Write 的 .py 里）；单独 force 是合法控制流探索，不拦——只有会话日志
# 已出现 runtime 随机性证据时才注入，指向配方 ①。
# 证据只认 assistant/message 行（agent 自己的观测结论）；tool/result 里的
# skill 文档也含「跨 run」字样（ghidra-static 加载即入日志），不算证据。
FORCE_RE = re.compile(r"\bForce\(")
RT_EVIDENCE_RE = re.compile(
    r"per[- ]run|between runs|across runs|every run|each run|"
    r"跨 ?run|每 ?run|逐 ?run|每次运行|每轮运行", re.I)
R6_TEXT = (
    "[即时规则 · 塌缩点前置] 检测到 gdbkit Force( 且本会话已有跨 run 不一致"
    "实锤：runtime 依赖已确认，force compare 只能探控制流、产不出验证数据"
    "（13ee6b0f：force 过比较门后下游 AEAD 仍失败，20min 零产出）。强制下一步"
    " = ghidra-static references/runtime-dependent-verifier.md ① 塌缩点搜索："
    "把每个 runtime 依赖字节列出来，逐问「它有几个可能取值」——selector 常是"
    " hash 的单字节参数 / & 掩码 / 表索引，枚举空间 ≤2^16 即离线化。塌缩点未"
    "落账（ledger observe）前，force 不是主路。")


def _session_text(session_id: str):
    """本会话持久日志全文；不可判定返回 None。与 gate_stuck 同通道。"""
    if not session_id:
        return None
    try:
        import stop_check
        return stop_check.session_log_text(session_id)
    except Exception:
        return None


def load_marker():
    try:
        return json.loads(MARKER.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_marker(m):
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        now = time.time()
        m = {k: v for k, v in m.items() if now - float(v) < 7 * 24 * 3600}
        MARKER.write_text(json.dumps(m), encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    resp = payload.get("tool_response")
    if not isinstance(resp, str):
        resp = ""
    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ""
    if not isinstance(cmd, str):
        cmd = ""
    content = ti.get("content") or ""
    if not isinstance(content, str):
        content = ""
    if not resp and not cmd and not content:
        return 0
    session_id = str(payload.get("session_id") or "unknown")

    marker = load_marker()
    now = time.time()
    fired = []
    for rule_id, pred, text in RULES:
        key = f"{session_id}:{rule_id}"
        if now - float(marker.get(key) or 0) < MARKER_TTL:
            continue
        if resp and pred(resp):
            fired.append((key, text))
    for rule_id, pred, text in CMD_RULES:
        key = f"{session_id}:{rule_id}"
        if now - float(marker.get(key) or 0) < MARKER_TTL:
            continue
        if cmd and pred(cmd):
            fired.append((key, text))
    # R6：先过便宜的 Force( 触发，再付会话日志扫描的代价
    key = f"{session_id}:R6_force_runtime"
    if now - float(marker.get(key) or 0) >= MARKER_TTL:
        blob = cmd or content
        if blob and FORCE_RE.search(blob):
            log_text = _session_text(session_id)
            if log_text and any(
                    RT_EVIDENCE_RE.search(ln)
                    for ln in log_text.splitlines()
                    if '"assistant/message"' in ln):
                fired.append((key, R6_TEXT))
    if not fired:
        return 0
    for key, _ in fired:
        marker[key] = now
    save_marker(marker)

    json.dump({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "\n\n".join(t for _, t in fired),
    }}, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"inject_rules hook warning (静默放行): {e}", file=sys.stderr)
        sys.exit(0)
