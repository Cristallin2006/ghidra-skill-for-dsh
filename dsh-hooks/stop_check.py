#!/usr/bin/env python
"""stop_check.py - Stop 收尾检查（v2：会话归属，修跨会话误报）。

Stop 事件时对**本会话自己写过的**台账做三类收尾核对，命中即 deny（exit 2）强制继续：

1. 烂尾台账：有 observe 但零 conclude 零 stuck（看了没记账）。
2. 铁律 10⑤：最新（未被同 id 推翻）的 kind=flag 结论缺 program_accept
   ——flag 的唯一合法 VERIFIED 证据是「未修改原程序/平台接受候选输入」，
   自写探针等价式不算（chal session 循环论证事故）。
3. 铁律 4：存在未闭环的 open hypothesis（92a0a107 临门一脚事故：
   H1 精确写出真因却没跑，带着它交卷）。出口：confirmed/killed --evidence
   或 --status waived --waive 理由。

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
  天然支持帧拼接），取所有 tool/call 的 arguments.command，逐条 shell 语句判定：

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
    """定位本会话的持久日志；找不到返回 None。"""
    if not session_id:
        return None
    sessions = dsh_home() / "sessions"
    if not sessions.is_dir():
        return None
    try:
        for p in sessions.glob("*/" + session_id + "/session.v3.jsonl.zstd"):
            if p.is_file():
                return p
    except OSError:
        return None
    return None


def tool_commands(session_id: str):
    """会话日志里所有 bash tool/call 的 command；不可判定返回 None（回退 v1）。"""
    log = session_log(session_id)
    if log is None:
        return None
    try:
        if log.stat().st_size > MAX_LOG_BYTES:
            return None
        text = decode_zstd_frames(log.read_bytes())
    except OSError:
        return None
    if text is None:
        return None
    out = []
    for line in text.decode("utf-8", "replace").splitlines():
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
    for j in scoped:
        types = set()
        conclusions = []
        hyps = set()
        hres = set()
        try:
            for line in j.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                types.add(e.get("type"))
                if e.get("type") == "conclude":
                    conclusions.append(e)
                elif e.get("type") == "hypothesis":
                    hyps.add(str(e.get("id")))
                elif e.get("type") == "hypothesis-resolve":
                    hres.add(str(e.get("hypothesis_id")))
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
        # 第三类检查（92a0a107 临门一脚事故：H1 精确写出真因却没跑，
        # 带着 open hypothesis 交卷）。出口：跑掉（confirmed/killed --evidence）
        # 或豁免（--status waived --waive 理由）。
        opens = sorted(hyps - hres)
        if opens:
            open_hyp.append(f"{j.name} 假设#{','.join(opens)}")

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
