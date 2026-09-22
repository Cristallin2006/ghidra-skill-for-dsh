#!/usr/bin/env python
"""gate_sample.py - PreToolUse 首接触门禁：对无台账样本的惯性直读说不。

matcher "Pwsh|Bash"，每次 shell 调用前触发。判定逻辑：
  1. 命令含 ledger.py / doctor.py（台账/工具链自身操作）-> 放行
  2. 命令含分析动词（xxd/hexdump/strings/objdump/readelf/...）且作用于
     存在的二进制样本文件（扩展名或 magic 判定；pcap/pcapng 豁免——
     triage 修头是合法开局）-> 进入台账检查
  3. ~/.dsh/ghidra-workspace/out/<样本名>.ledger.jsonl 存在 -> 放行
     （之后的同区回访由 ledger 自己的断路器管）；不存在 -> exit 2 阻断，
     stderr 指引先 re-triage 分诊 + ledger query。

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

# 台账/工具链自身操作一律放行
ALLOW = re.compile(r"ledger\.py|doctor\.py|triage_scan\.py|rpc_driver\.py|driver\.py")

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


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ti.get("cmd") or ""
    if not isinstance(cmd, str) or not cmd.strip():
        return 0
    if ALLOW.search(cmd):
        return 0
    if not VERBS.search(cmd):
        return 0

    cwd = Path(payload.get("cwd") or os.getcwd())
    # shell 分词（双/单引号成组），逐 token 找样本文件
    tokens = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', cmd)
    for tok in tokens:
        sample = is_sample(tok, cwd)
        if sample is None:
            continue
        if ledger_exists(sample):
            return 0
        msg = (
            f"[gate_sample · 铁律7 先查后析] 检测到对样本 {sample.name} 的分析类直读，"
            f"但该样本还没有台账。\n"
            f"先走流程，再动手：\n"
            f"  ① 用 skill 工具加载 re-triage 完成分诊（确认类型/加壳/语言）\n"
            f"  ② python ~/.dsh/skills/ghidra-core/scripts/ledger.py query <样本路径> 查重\n"
            f"  ③ 首个观察用 ledger.py observe 落账（台账文件此时建立，本门禁随之放行）\n"
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
