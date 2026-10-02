#!/usr/bin/env python
"""stop_check.py - Stop 收尾检查（v3：未收敛投降闸，修 29bf99c0）。

Stop 事件时对**本会话自己写过的**台账做五类收尾核对，命中即 deny（exit 2）强制继续：

1. 烂尾台账：有 observe 但零 conclude 零 stuck（看了没记账）。
2. 铁律 10⑤：最新（未被同 id 推翻）的 kind=flag 结论缺 program_accept
   ——flag 的唯一合法 VERIFIED 证据是「未修改原程序/平台接受候选输入」，
   自写探针等价式不算（chal session 循环论证事故）。
3. 铁律 4：存在未闭环的 open hypothesis（92a0a107 临门一脚事故：
   H1 精确写出真因却没跑，带着它交卷）。出口：confirmed/killed --evidence
   或 --status waived --waive 理由。
4. 带路径投降：台账**末条**是 stuck 且 --escalate 写的路径未出现在 --tried 里
   （4ccec36c：escalate 写出能力范围内的可执行路径——peel 式逐语句反推——
   0 次执行直接交卷，121 min 无 flag）。stuck 是升级起点不是终点：
   出口 = 执行 escalate 后 conclude / 把该路径并入 --tried 重新 stuck /
   escalate 改写为「问用户/需安装 X」（用户向关键词豁免）。
5. 未收敛投降：stuck 的 escalate 执行过一次、后续条目自己落账「未收敛/未拿到」，
   却没有新 stuck、没问用户就交卷（29bf99c0：binv.py 一轮 +38 未收敛后
   以「上下文将尽」为由 19 min 交卷，实测 1M 窗口占用不足三成）。
   未收敛 ≠ 穷尽。出口 = 改进规则重跑 / 重新 stuck 新路径 /
   ask_user_question（用户在 stuck 之后发过话即视为已问，放行）/
   重新 stuck 把已试路径并入 --tried（转闸 4 判定）。

--- v2 修的是什么（2026-09-26 实证） ---
v1 对 out/ 下 mtime 最新的 5 份台账做**全局**核对，没有会话维度。并发会话下必然误报：
session-f862c151 收尾时抓到 session-92a0a107 正在写的 rev-chal.so.ledger.jsonl
（4 observe / 0 conclude，但那个会话当时还在跑第 89 步），把它 deny 了。
v1 的 12h 时间窗只治了「历史会话」，治不了「并发会话」。

--- v2 的归属判定 ---
Stop payload 里唯一可用的身份是 session_id（transcript_path 在本桥里恒为空串，
见 dsh-hooks-claude-code 的 base()）。所以从会话自己的日志反推归属：

  解码 <DSH_HOME>/sessions/*/<session_id>/session.v3.jsonl.zstd（追加式的**多帧**
  zstd，Python 3.12 无 stdlib zstd，走 ctypes 调 libzstd 的流式 decodeStream，
  天然支持帧拼接；同时兼容未压缩的 session.v3.jsonl 导出格式），
  取所有 tool/call 的 arguments.command，逐条 shell 语句判定：

    语句内出现 ledger.py + **写子命令**（observe/conclude/anomaly/resolve/
    hypothesis/plan/stuck/render）+ 该台账的样本 stem（词边界匹配）=> 认定归属。

  两点必要性（都有实证）：
    * 只读子命令不算归属——本会话本轮跑过 `ledger.py status .../rev-chal.so`，
      若把 status 算作归属，修完照样误报自己。
    * 必须做 shell 变量展开——实际写法是 `B=/path/x.so` 一行、
      `ledger.py observe "$B"` 另一行，不展开就认不出自己写的台账（漏判）。

--- 失效方向（有意如此） ---
* 会话日志读不到 / 解不开 / session_id 为空 => 退回 v1 全局核对（保守，不放松原意）。
* 解析漏判 => 该会话逃过收尾核对。这是有意选的方向：v1 那种「误伤无辜会话」的代价
  高于「个别会话漏检」，且纪律卡本身仍是第二道约束。本闸门定位是速度坎，不防蓄意绕过。
* 闸 5 的「已问用户」豁免看 user/message 时间戳——系统注入消息也算 user 角色，
  可能假性豁免（保守方向，可接受）。
"""
import ctypes
import ctypes.util
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

RECENCY_SEC = 12 * 3600  # 只收尾 12h 内活跃过的台账
SCAN_TOP = 5             # v1 起就只看 mtime 最新的 5 份，保留
MAX_LOG_BYTES = 256 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024 * 1024

# 会改动台账的 ledger.py 子命令；query/status/validate/--help 是只读，不算归属
WRITE_SUBCMDS = {"observe", "conclude", "anomaly", "resolve",
                 "hypothesis", "plan", "stuck", "render"}

LEDGER_CALL_RE = re.compile(r"""(?:^|[\s/"'$({])ledger\.py["']?\s+([A-Za-z][\w-]*)""")
ASSIGN_RE = re.compile(
    r"""(?:^|[\s;])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|[^\s;&|]+)""")
VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
STMT_SPLIT_RE = re.compile(r"[;\n]|&&|\|\||\|")


def dsh_home() -> Path:
    env = os.environ.get("DSH_HOME")
    return Path(env) if env else Path.home() / ".dsh"


# ---------------------------------------------------------------- zstd (ctypes)

class _In(ctypes.Structure):
    _fields_ = [("src", ctypes.c_void_p), ("size", ctypes.c_size_t),
                ("pos", ctypes.c_size_t)]


class _Out(ctypes.Structure):
    _fields_ = [("dst", ctypes.c_void_p), ("size", ctypes.c_size_t),
                ("pos", ctypes.c_size_t)]


_ZSTD = None
_ZSTD_TRIED = False


def _zstd():
    """惰性加载 libzstd；不可用返回 None（上层回退 v1 全局核对）。"""
    global _ZSTD, _ZSTD_TRIED
    if _ZSTD_TRIED:
        return _ZSTD
    _ZSTD_TRIED = True
    lib = None
    for name in ("libzstd.so.1", "libzstd.so", "libzstd.1.dylib", "libzstd.dylib", "zstd.dll"):
        try:
            lib = ctypes.CDLL(name)
            break
        except OSError:
            continue
    if lib is None:
        try:
            found = ctypes.util.find_library("zstd")
            lib = ctypes.CDLL(found) if found else None
        except OSError:
            lib = None
    if lib is None:
        return None
    try:
        lib.ZSTD_createDCtx.restype = ctypes.c_void_p
        lib.ZSTD_freeDCtx.argtypes = [ctypes.c_void_p]
        lib.ZSTD_freeDCtx.restype = ctypes.c_size_t
        lib.ZSTD_decompressStream.argtypes = [ctypes.c_void_p,
                                              ctypes.POINTER(_Out),
                                              ctypes.POINTER(_In)]
        lib.ZSTD_decompressStream.restype = ctypes.c_size_t
        lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
        lib.ZSTD_isError.restype = ctypes.c_uint
        lib.ZSTD_DStreamOutSize.restype = ctypes.c_size_t
    except AttributeError:
        return None
    _ZSTD = lib
    return lib


def decode_zstd_frames(data: bytes):
    """流式解多帧 zstd。返回 bytes（允许因尾帧未写完而截断），彻底失败返回 None。"""
    lib = _zstd()
    if lib is None or not data:
        return None
    dctx = lib.ZSTD_createDCtx()
    if not dctx:
        return None
    try:
        src = ctypes.create_string_buffer(data, len(data))
        inb = _In(ctypes.cast(src, ctypes.c_void_p), len(data), 0)
        cap = max(int(lib.ZSTD_DStreamOutSize()), 65536)
        dst = ctypes.create_string_buffer(cap)
        outb = _Out(ctypes.cast(dst, ctypes.c_void_p), cap, 0)
        chunks = []
        total = 0
        while inb.pos < inb.size and total < MAX_TEXT_BYTES:
            outb.pos = 0
            before = inb.pos
            ret = lib.ZSTD_decompressStream(dctx, ctypes.byref(outb), ctypes.byref(inb))
            if lib.ZSTD_isError(ret):
                break  # 半帧/损坏：保留已解出的部分
            if outb.pos:
                chunks.append(dst.raw[:outb.pos])
                total += outb.pos
            if outb.pos == 0 and inb.pos == before:
                break
        return b"".join(chunks) if chunks else None
    finally:
        lib.ZSTD_freeDCtx(dctx)


# ---------------------------------------------------------------- ownership

def session_log(session_id: str):
    """定位本会话的持久日志（.zstd 优先，兼容未压缩的导出格式）；找不到返回 None。"""
    if not session_id:
        return None
    sessions = dsh_home() / "sessions"
    if not sessions.is_dir():
        return None
    try:
        for name in ("session.v3.jsonl.zstd", "session.v3.jsonl"):
            for p in sessions.glob("*/" + session_id + "/" + name):
                if p.is_file():
                    return p
    except OSError:
        return None
    return None


_LOG_TEXT_CACHE = {}


def session_log_text(session_id: str):
    """读并（必要时）解压会话日志全文；失败返回 None。同会话只解一次。"""
    if session_id in _LOG_TEXT_CACHE:
        return _LOG_TEXT_CACHE[session_id]
    text = None
    log = session_log(session_id)
    if log is not None:
        try:
            if log.stat().st_size <= MAX_LOG_BYTES:
                raw = log.read_bytes()
                if log.suffix == ".zstd":
                    raw = decode_zstd_frames(raw)
                if raw is not None:
                    text = raw.decode("utf-8", "replace")
        except OSError:
            text = None
    _LOG_TEXT_CACHE[session_id] = text
    return text


def tool_commands(session_id: str):
    """会话日志里所有 bash tool/call 的 command；不可判定返回 None（回退 v1）。"""
    text = session_log_text(session_id)
    if text is None:
        return None
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or '"tool/call"' not in line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("type") != "tool/call":
            continue
        args = (ev.get("data") or {}).get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                continue
        cmd = args.get("command") if isinstance(args, dict) else None
        if isinstance(cmd, str) and cmd:
            out.append(cmd)
    return out


def user_message_times(session_id: str):
    """会话日志里 user/message 记录的时间（epoch 秒）；不可判定返回 None。"""
    text = session_log_text(session_id)
    if text is None:
        return None
    out = []
    for line in text.splitlines():
        if '"user/message"' not in line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("type") != "user/message":
            continue
        t = ev.get("time")
        if isinstance(t, (int, float)):
            out.append(t / 1000.0)
    return out


def _expand(stmt: str, env: dict) -> str:
    return VAR_RE.sub(lambda m: env.get(m.group(1), m.group(0)), stmt)


def owns(commands, stem: str) -> bool:
    """本会话是否用写子命令写过 stem 对应的台账。"""
    stem_re = re.compile(r"(?<![\w.\-])" + re.escape(stem) + r"(?![\w.\-])")
    for raw in commands:
        env = {}
        text = raw.replace("\\\r\n", " ").replace("\\\n", " ")
        for stmt in STMT_SPLIT_RE.split(text):
            if not stmt.strip():
                continue
            # 先收集变量赋值（样本路径常写成 B=/path/x.so 独立一行）
            for m in ASSIGN_RE.finditer(stmt):
                val = m.group(3)
                if val is None:
                    val = m.group(4)
                if val is None:
                    val = m.group(2)
                env[m.group(1)] = val
            expanded = _expand(stmt, env)
            if "ledger.py" not in expanded or not stem_re.search(expanded):
                continue
            for m in LEDGER_CALL_RE.finditer(expanded):
                if m.group(1) in WRITE_SUBCMDS:
                    return True
    return False


# ---------------------------------------------------------------- checks

# 第 4 类检查（带路径投降）用的关键词：escalate 指向 agent 自己可执行的路径。
# 命中其一且该词不在 tried 里 ⇒ 路径写了没跑 ⇒ deny。失效方向有意保守：
# escalate 含用户向关键词（问用户/需安装/缺工具…）即豁免——本闸是速度坎，不防蓄意绕过。
STUCK_EXEC_HINTS = ("peel", "剥离", "反解", "逐语句", "逐层", "cone_invert",
                    "emulate", "oracle", "model_diff", "gdb", "frida", "qiling",
                    "angr", "z3", "smt", "爆破", ".py")
STUCK_USER_HINTS = ("问用户", "用户", "需安装", "安装", "pip", "apt",
                    "不可用", "缺工具", "缺少", "权限")

# 第 5 类检查（未收敛投降）用的关键词：stuck 之后的条目自己承认升级路径没跑通。
# 收紧到「明确承认无结果」的措辞，正常进展记录不会命中。
UNCONV_HINTS = ("未收敛", "未拿到", "不收敛", "未解出", "no flag")


def main() -> int:
    raw = sys.stdin.read()
    session_id = ""
    try:
        payload = json.loads(raw) if raw.strip() else {}
        if isinstance(payload, dict):
            session_id = str(payload.get("session_id") or "")
    except Exception:
        session_id = ""

    out = dsh_home() / "ghidra-workspace" / "out"
    if not out.is_dir():
        return 0
    now = time.time()
    recent = []
    for j in sorted(out.glob("*.ledger.jsonl"),
                    key=lambda p: p.stat().st_mtime, reverse=True)[:SCAN_TOP]:
        try:
            if now - j.stat().st_mtime > RECENCY_SEC:
                continue
        except OSError:
            continue
        recent.append(j)

    # 判定归属；commands is None => 无法判定，退回 v1 的全局核对
    commands = tool_commands(session_id)
    if commands is None:
        scoped = recent
    else:
        scoped = [j for j in recent
                  if owns(commands, j.name[:-len(".ledger.jsonl")])]

    if os.environ.get("DSH_STOP_CHECK_DEBUG"):
        print(f"[stop_check] session={session_id or '(empty)'} "
              f"recent={[j.name for j in recent]} "
              f"scoped={[j.name for j in scoped]}", file=sys.stderr)

    open_ended = []
    bad_flag = []
    open_hyp = []
    tail_stuck = []
    unconverged = []
    user_times = user_message_times(session_id)
    for j in scoped:
        types = set()
        conclusions = []
        hyps = set()
        hres = set()
        entries = []
        try:
            for line in j.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                entries.append(e)
                types.add(e.get("type"))
                if e.get("type") == "conclude":
                    conclusions.append(e)
                elif e.get("type") == "hypothesis":
                    hyps.add(str(e.get("id")))
                elif e.get("type") == "hypothesis-resolve":
                    hres.add(str(e.get("hypothesis_id")))
        except Exception:
            continue
        last = entries[-1] if entries else None
        if "observe" in types and not ({"conclude", "stuck"} & types):
            open_ended.append(j.name)
        latest = {}
        for e in conclusions:
            latest[e.get("id")] = e
        for e in latest.values():
            if e.get("kind") == "flag" and not str(
                    e.get("program_accept") or "").strip():
                bad_flag.append(f"{j.name} 结论#{e.get('id')}")
        # 第三类检查（92a0a107 临门一脚事故：H1 精确写出真因却没跑，
        # 带着 open hypothesis 交卷）。出口：跑掉（confirmed/killed --evidence）
        # 或豁免（--status waived --waive 理由）。
        opens = sorted(hyps - hres)
        if opens:
            open_hyp.append(f"{j.name} 假设#{','.join(opens)}")
        # 第四类检查（4ccec36c 带路径投降：末条 stuck 的 escalate 写了能力范围内
        # 的可执行路径却 0 次执行直接交卷）。判定：escalate 的执行类关键词与 tried
        # 零交集 ⇒ 路径写了没跑 ⇒ deny。失效方向有意保守：任一关键词重叠即视为
        # 已尝试（同路径换措辞不误伤）；escalate 含用户向关键词即豁免。
        if last and last.get("type") == "stuck":
            esc = str(last.get("escalate") or "").lower()
            tried = str(last.get("tried") or "").lower()
            if not any(h in esc for h in STUCK_USER_HINTS):
                exechits = [h for h in STUCK_EXEC_HINTS if h in esc]
                if exechits and not any(h in tried for h in exechits):
                    tail_stuck.append(
                        f"{j.name}（escalate 未执行路径：{'/'.join(exechits[:3])}）")
        # 第五类检查（29bf99c0 未收敛投降：stuck 的 escalate 执行过一次、
        # 后续条目自己落账「未收敛/未拿到」，随后不写新 stuck、不问用户直接交卷，
        # 还以「上下文将尽」为借口——实测 1M 窗口占用不足三成）。未收敛 ≠ 穷尽。
        # 出口：改进规则重跑 / 重新 stuck 新路径 / ask_user_question（用户在
        # stuck 之后发过话即视为已问，放行）/ 重新 stuck 并入 tried 走闸 4。
        stuck_idx = -1
        for idx, e in enumerate(entries):
            if e.get("type") == "stuck":
                stuck_idx = idx
        if stuck_idx >= 0:
            s = entries[stuck_idx]
            esc5 = str(s.get("escalate") or "")
            after = entries[stuck_idx + 1:]
            flag_after = any(e.get("type") == "conclude" and e.get("kind") == "flag"
                             for e in after)
            hit_unconv = any(
                any(h in json.dumps(e, ensure_ascii=False) for h in UNCONV_HINTS)
                for e in after)
            if (after and hit_unconv and not flag_after
                    and (not last or last.get("type") != "stuck")
                    and not any(h in esc5 for h in STUCK_USER_HINTS)):
                asked = False
                if user_times:
                    try:
                        sts = time.mktime(time.strptime(str(s.get("ts") or ""),
                                                        "%Y-%m-%d %H:%M:%S"))
                        asked = any(t > sts for t in user_times)
                    except (ValueError, OverflowError):
                        asked = False
                if not asked:
                    unconverged.append(f"{j.name}（{s.get('at')}）")

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
    if open_hyp:
        msgs.append(
            f"存在未闭环假设（铁律 4）：{', '.join(open_hyp)}。"
            "假设写下就必须有下文——收尾前跑掉它：ledger.py hypothesis <样本> "
            "--resolve-id <H#> --status confirmed|killed --evidence \"实测输出\"；"
            "客观不可检验才走 --status waived --waive \"为何豁免\"。")
    if tail_stuck:
        msgs.append(
            f"台账末条是 stuck 但 escalate 路径未执行（tried 里没有它）：{', '.join(tail_stuck)}。"
            "stuck 是升级的起点不是终点（铁律 7）——escalate 写的路径在能力范围内"
            "（机械步骤/已有部分验证）必须先执行：执行成功 → conclude 落账；"
            "执行失败 → 重新 stuck 并把该路径并入 --tried（任一路径词重叠即视为已尝试）；"
            "确实需要用户/缺工具 → 重新 stuck 把 --escalate 写成「问用户/需安装 X」。"
            "直接交卷 = 4ccec36c 事故（121 min 无 flag）。")
    if unconverged:
        msgs.append(
            f"stuck 的升级已执行但自己落账未收敛：{', '.join(unconverged)}。"
            "未收敛 ≠ 穷尽，禁止默默交卷（29bf99c0：binv.py 一轮 +38 未收敛后"
            "以「上下文将尽」交卷，实测 1M 窗口占用不足三成）："
            "① 规则不足就补规则重跑（弃路径要 conclude 理由）；"
            "② 换全新路径：ledger.py stuck 重写 --escalate；"
            "③ 客观卡死 → ask_user_question 报告卡点由用户定夺；"
            "④ 路径真穷尽 → 重新 stuck 把已试路径并入 --tried（闸 4 放行）。"
            "「上下文将尽」不是出口——上下文压力的正确响应是窗口化读取继续推进。")
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
