#!/usr/bin/env python
"""gate_sample.py - PreToolUse 首接触门禁：对无台账样本的惯性直读说不。

matcher "Pwsh|pwsh|Bash|bash"（dsh-hook-protocol 的字面量 matcher 是
**大小写敏感**精确匹配：CLAUDE_LITERAL 模式走 split("|").includes()——
只写 "Bash" 在 WSL 的 "bash" 工具上静默失效，chal session 即因此零拦截）。
每次 shell 调用前触发。判定逻辑：
  1. 命令含 ledger.py / doctor.py（台账/工具链自身操作）-> 放行
  2. 命令含分析动词（xxd/hexdump/strings/objdump/readelf/...）或
     rpc_driver 深挖子命令（decompile/exec-code/emulate/patch…，路由看门：
     没分诊就不许深挖），且作用于存在的二进制样本文件（扩展名或 magic
     判定；pcap/pcapng 豁免——triage 修头是合法开局）-> 进入台账检查
  3. ~/.dsh/ghidra-workspace/out/<样本名>.ledger.jsonl 存在 -> 放行
     （之后的同区回访由 ledger 自己的断路器管）；不存在 -> exit 2 阻断，
     stderr 指引先 re-triage 分诊 + ledger query，深挖另须先加载
     ghidra-static 全文。
  4. Cython 前置（f862c151）：有台账但 triage 报 lang_hints.python_ext=true
     且台账无 const_scan/frame_map 证据时，rpc 深挖同样 exit 2——
     先取 §12 元数据 + 帧槽位真值再建模。

定位：防"惯性直读"，不防蓄意绕过（命令写进脚本文件再执行即可绕过）。
绕过会在台账缺失上留痕。任何内部异常 -> 放行（exit 0），门禁故障不许
阻塞正常工作。

输入：stdin PreToolUse payload {"tool_input": {"command": ...}, "cwd": ...}。
输出：放行 = exit 0 无输出；阻断 = exit 2 + stderr 原因（喂给模型）。
"""
import json
import os
import re
import sys
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 分析动词：命中其一才进入样本判定
VERBS = re.compile(
    r"\b(xxd|hexdump|hd|od|strings|objdump|readelf|nm|rabin2|r2|radare2|gdb|"
    r"llvm-objdump|dumpbin|windbg|cdb)\b", re.IGNORECASE)

# 台账/工具链自身操作一律放行（rpc_driver 不再整体豁免——深挖子命令走路由门）
ALLOW = re.compile(r"ledger\.py|doctor\.py|triage_scan\.py|driver\.py")

# 路由看门（chal session：re-triage 之后一次都没加载 ghidra-static 就深挖）。
# rpc_driver 的深挖子命令与裸分析动词同等待遇：无台账 = 没分诊 = 阻断。
# ensure/status/stop/triage/只读元数据（imports/exports/functions/strings…）
# 仍放行——它们是分诊动作本身。
RPC = re.compile(r"rpc_driver\.py")
RPC_DEEP = re.compile(
    r"\b(decompile(?:-all)?|search-decompiled|exec-code|disassemble|assemble|"
    r"write-bytes|patch|emulate-(?:function|program)|version-track)\b")

SAMPLE_EXT = {".exe", ".dll", ".so", ".bin", ".elf", ".dex", ".apk",
              ".class", ".sys", ".com", ".scr", ".ocx", ".dylib", ".o", ".a"}
EXEMPT_EXT = {".pcap", ".pcapng", ".txt", ".md", ".json", ".jsonl", ".py",
              ".c", ".cpp", ".h", ".log", ".hex", ".xml", ".yml", ".yaml"}

MAGICS = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe",
          b"\xca\xfe\xba\xbe", b"dex\n", b"\xde\xc0\x17\x0b")  # 最后: .class


def is_sample(token: str, cwd: Path) -> Path | None:
    """token 是存在的二进制样本文件则返回其 Path，否则 None。"""
    t = token.strip("\"'")
    if not t or t.startswith("-"):
        return None
    p = Path(t)
    if not p.is_absolute():
        p = cwd / p
    try:
        if not p.is_file():
            return None
    except OSError:
        return None
    ext = p.suffix.lower()
    if ext in EXEMPT_EXT:
        return None
    if ext in SAMPLE_EXT:
        return p
    # 无扩展名/未知扩展名：读 magic
    try:
        with p.open("rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if any(head.startswith(m) for m in MAGICS):
        return p
    return None


def ledger_exists(sample: Path) -> bool:
    out = Path.home() / ".dsh" / "ghidra-workspace" / "out"
    return (out / (sample.name + ".ledger.jsonl")).is_file()


CYTHON_EVIDENCE = re.compile(r"const_scan|frame_map")


def python_ext_unprimed(sample: Path) -> bool:
    """triage 报 python_ext=true 且台账无 const_scan/frame_map 证据 -> True。

    f862c151 session：跳过 §12 元数据与帧槽位直建轮函数模型，
    手写 95 项 datmap + 128 变体盲搜——Cython 样本的两类真值是强制前置。
    """
    out = Path.home() / ".dsh" / "ghidra-workspace" / "out"
    triage = out / (sample.name + ".triage.json")
    if not triage.is_file():
        return False
    try:
        hints = json.loads(triage.read_text(
            encoding="utf-8", errors="replace")).get("lang_hints") or {}
    except Exception:
        return False
    if not hints.get("python_ext"):
        return False
    ledger = out / (sample.name + ".ledger.jsonl")
    if ledger.is_file():
        try:
            if CYTHON_EVIDENCE.search(
                    ledger.read_text(encoding="utf-8", errors="replace")):
                return False
        except OSError:
            pass
    return True


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ti.get("cmd") or ""
    if not isinstance(cmd, str) or not cmd.strip():
        return 0
    # 先判 rpc_driver：深挖子命令走路由门，其余（ensure/triage/只读元数据）放行。
    # 注意不能靠 ALLOW 里的 driver\.py 豁免 rpc_driver——"driver\.py" 是
    # "rpc_driver.py" 的子串，会整体漏闸。
    if RPC.search(cmd):
        if not RPC_DEEP.search(cmd):
            return 0
        deep_rpc = True
    elif ALLOW.search(cmd):
        return 0
    else:
        deep_rpc = False
    if not VERBS.search(cmd) and not deep_rpc:
        return 0

    cwd = Path(payload.get("cwd") or os.getcwd())
    # shell 分词（双/单引号成组），逐 token 找样本文件
    tokens = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', cmd)
    for tok in tokens:
        sample = is_sample(tok, cwd)
        if sample is None:
            continue
        if ledger_exists(sample):
            if deep_rpc and python_ext_unprimed(sample):
                msg = (
                    f"[gate_sample · Cython 前置] {sample.name} 的 triage 判定 "
                    f"lang_hints.python_ext=true，但台账没有 const_scan / "
                    f"frame_map 证据。\n"
                    f"Cython/CPython 扩展深挖轮函数之前必须先取两类真值"
                    f"（f862c151：跳过本步 → 手写 95 项 datmap + 128 变体盲搜）：\n"
                    f"  ① python ~/.dsh/skills/ghidra-core/scripts/const_scan.py "
                    f"--binary <样本>（ctf-patterns §12 元数据常量重建）\n"
                    f"  ② python ~/.dsh/skills/ghidra-core/scripts/frame_map.py "
                    f"<函数地址>（栈帧槽位归属——伪码 local_XXXX 不可信）\n"
                    f"落账（observe）后本门放行。"
                )
                print(msg, file=sys.stderr)
                return 2
            return 0
        trigger = "rpc 深挖（decompile/exec-code/emulate 等）" if deep_rpc \
            else "分析类直读"
        msg = (
            f"[gate_sample · 铁律7 先查后析] 检测到对样本 {sample.name} 的{trigger}，"
            f"但该样本还没有台账。\n"
            f"先走流程，再动手：\n"
            f"  ① 用 skill 工具加载 re-triage 完成分诊（确认类型/加壳/语言）\n"
            f"  ② python ~/.dsh/skills/ghidra-core/scripts/ledger.py query <样本路径> 查重\n"
            f"  ③ 首个观察用 ledger.py observe 落账（台账文件此时建立，本门禁随之放行）\n"
            f"深挖（反编译/exec-code/仿真/patch）前还必须用 skill 工具加载 "
            f"ghidra-static 全文——chal session 事故：全程未加载就深挖。\n"
            f"若本次是非分析用途（误伤）：把样本加入台账（任一 observe）后即不再拦截。"
        )
        print(msg, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_sample hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
