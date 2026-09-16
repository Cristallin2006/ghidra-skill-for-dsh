#!/usr/bin/env python
"""oracle.py - function-level oracle + breakpoint memory dump.

Host usage (Windows, any Python 3):
  python oracle.py <binary> <func_addr> [args...] [options] [@out.json]

  <func_addr>  address as shown in the Ghidra listing (0x... or hex)
  args         integer args (dec or 0x...) and string args (prefix str:)
               x86-64: first 6 int args (SysV) / first 4 (Win64) in regs;
               i386:   args are pushed on the stack (cdecl layout)

Options:
  --timeout SEC        emulation timeout (default 30; qiling uses us internally)
  --init-until <addr>  run normal startup up to <addr> (ghidra addr, e.g.
                       main) before the call - needed when the target
                       function calls libc (dynamic binaries)
  --break <addr>       ghidra address of a breakpoint; at each hit, evaluate
                       every --dump expression, then continue
  --dump <expr:len>    memory dump at break. expr forms:
                         ebp-0x8c:28      register-relative
                         esp+0x10:16
                         0x804a020:32     absolute (ghidra addr, auto-rebased)
                         eax              bare register -> value only
                       repeatable
  --max-hits N         stop dumping after N breakpoint hits (default 1)

The real work happens in WSL Ubuntu qiling (/root/re-pwn-venv) — the host
side only translates paths and shuttles a JSON spec/result.

Examples:
  python oracle.py ./sample 0x101064 1 0x20 str:test
  python oracle.py ./check 0x1020a0 str:flag{guess} @out.json
  python oracle.py ./encode 0x804887c --init-until 0x804887c \
      --break 0x8048a10 --dump ebp-0x8c:28 --dump esp:16
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

WSL_DISTRO = "Ubuntu"
WSL_PYTHON = "/root/re-pwn-venv/bin/python"
ROOTFS = {("elf", 64): "/root/qiling-rootfs/x8664_linux",
          ("elf", 32): "/root/qiling-rootfs/x86_linux",
          ("pe", 64): "/root/qiling-rootfs/x8664_windows",
          ("pe", 32): "/root/qiling-rootfs/x86_windows"}
SENTINEL = 0xDEAD0000  # fake return address; ql.run(end=...) stops here

WORKER = r'''
import json, re, sys
from qiling import Qiling
from qiling.const import QL_VERBOSE

spec = json.load(open(sys.argv[2]))
binary, func = spec["binary"], spec["func"]
args, timeout = spec["args"], spec.get("timeout", 30)
kind, bits = spec["kind"], spec["bits"]
rootfs = spec["rootfs"]
break_at = spec.get("break_at")
dump_exprs = spec.get("dumps", [])
max_hits = spec.get("max_hits", 1)

# qiling's path layer assumes the emulated binary lives INSIDE rootfs
# (readlinkat("/proc/self/exe") crashes otherwise) — stage it there.
import os, shutil
if not binary.startswith(rootfs + "/"):
    work = os.path.join(rootfs, "tmp", "oracle_work")
    os.makedirs(work, exist_ok=True)
    dst = os.path.join(work, os.path.basename(binary))
    shutil.copyfile(binary, dst)
    binary = dst

ql = Qiling([binary], rootfs, verbose=QL_VERBOSE.OFF)

# --- resolve runtime address -------------------------------------------
def to_rt(addr):
    if kind == "elf":
        return img.base + (addr - ghidra_base)
    return addr  # PE32+ loads at preferred image base, same as Ghidra

img = None
ghidra_base = 0
if kind == "elf":
    from pwn import ELF
    e = ELF(binary, checksec=False)
    ghidra_base = 0x100000 if e.pie else e.address
    img = next(im for im in ql.loader.images if im.path == binary)
func_rt = to_rt(func)

# Dynamic binaries: libc/PLT/GOT only work after the CRT + dynamic linker
# have run. --init-until <ghidra addr of main> runs the normal startup
# first, so functions that call libc can be oracled too.
init_until = spec.get("init_until")
if init_until is not None:
    ql.run(end=to_rt(init_until), timeout=timeout * 1000000)

# --- breakpoint memory dump (T2/T3: mid-pipeline forensics) -------------
hits = {"n": 0}
dumps_out = []

def eval_dump(expr):
    target, ln = (expr.rsplit(":", 1) + [None])[:2] if ":" in expr \
        else (expr, None)
    ln = int(ln, 0) if ln is not None else None
    target = target.strip()
    m = re.fullmatch(r"([a-z]{2,3})(?:([+-])(0x[0-9a-fA-F]+|\d+))?", target)
    if m and hasattr(ql.arch.regs, m.group(1)):
        v = getattr(ql.arch.regs, m.group(1))
        if m.group(2):
            off = int(m.group(3), 0)
            v = v + off if m.group(2) == "+" else v - off
    else:
        v = to_rt(int(target, 0))
    if ln is None:
        return {"expr": expr, "hit": hits["n"], "value": hex(v)}
    data = bytes(ql.mem.read(v, ln))
    return {"expr": expr, "hit": hits["n"], "addr": hex(v), "len": ln,
            "hex": data.hex(),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data)}

if break_at is not None:
    break_rt = to_rt(break_at)
    def on_code(ql, address, size):
        if address == break_rt and hits["n"] < max_hits:
            hits["n"] += 1
            for expr in dump_exprs:
                try:
                    dumps_out.append(eval_dump(expr))
                except Exception as exc:
                    dumps_out.append({"expr": expr, "hit": hits["n"],
                                      "error": str(exc)})
    ql.hook_code(on_code)

# --- marshal args -------------------------------------------------------
scratch = 0x50000000
ql.mem.map(scratch, 0x10000)
ptr = scratch

def write_str(s):
    global ptr
    ql.mem.write(ptr, s.encode() + b"\x00")
    p = ptr
    ptr += len(s) + 8
    return p

argvals = [write_str(a) if isinstance(a, str) else int(a) for a in args]

if bits == 64:
    regs = (["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if kind == "elf"
            else ["rcx", "rdx", "r8", "r9"])
    for reg, v in zip(regs, argvals):
        setattr(ql.arch.regs, reg, v)
    ql.arch.regs.rsp = (ql.arch.regs.rsp - 0x28) & ~0xF
    ql.stack_write(0, SENTINEL)
else:
    # i386 cdecl: align FIRST, then args right-to-left, return address on top
    ql.arch.regs.esp = ql.arch.regs.esp & ~0xF
    for v in reversed(argvals):
        ql.stack_push(v)
    ql.stack_push(SENTINEL)

captured = []
if kind == "elf":
    from qiling.const import QL_INTERCEPT
    def hook_write(ql, fd, buf, count, *rest):
        if fd in (1, 2):
            captured.append(bytes(ql.mem.read(buf, count)).decode("latin1"))
    ql.os.set_syscall("write", hook_write, QL_INTERCEPT.CALL)

stop = "end"
try:
    ql.run(begin=func_rt, end=SENTINEL, timeout=timeout * 1000000)
except Exception as exc:
    stop = f"{type(exc).__name__}: {exc}"

out_regs = ("rax", "rbx", "rdx", "rsi", "rdi") if bits == 64 \
    else ("eax", "ebx", "edx", "esi", "edi", "ebp", "esp")
result = {"ok": stop == "end",
          "retval": getattr(ql.arch.regs, out_regs[0]),
          "stop_reason": stop,
          "stdout": "".join(captured), "func_runtime": hex(func_rt),
          "break_hits": hits["n"], "dumps": dumps_out,
          "regs": {r: getattr(ql.arch.regs, r) for r in out_regs}}
json.dump(result, open(sys.argv[3], "w"))
'''


def win_to_wsl(p: Path) -> str:
    s = str(p.resolve()).replace("\\", "/")
    return f"/mnt/{s[0].lower()}{s[2:]}" if len(s) > 2 and s[1] == ":" else s


def sniff(binary: Path) -> tuple[str, int]:
    with binary.open("rb") as f:
        head = f.read(0x40)
        if head[:4] == b"\x7fELF":
            return "elf", (32 if head[4] == 1 else 64)
        f.seek(0x3C)
        pe_off = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_off + 24)
        magic = struct.unpack("<H", f.read(2))[0]
    return "pe", (64 if magic == 0x20B else 32)


def main(argv: list[str]) -> int:
    args = list(argv)
    out_path = None
    for a in list(args):
        if a.startswith("@"):
            out_path = a[1:]
            args.remove(a)
    timeout = 30
    if "--timeout" in args:
        i = args.index("--timeout")
        timeout = int(args[i + 1])
        del args[i:i + 2]
    init_until = None
    if "--init-until" in args:
        i = args.index("--init-until")
        init_until = int(args[i + 1], 0)
        del args[i:i + 2]
    break_at = None
    if "--break" in args:
        i = args.index("--break")
        break_at = int(args[i + 1], 0)
        del args[i:i + 2]
    dump_exprs = []
    while "--dump" in args:
        i = args.index("--dump")
        dump_exprs.append(args[i + 1])
        del args[i:i + 2]
    max_hits = 1
    if "--max-hits" in args:
        i = args.index("--max-hits")
        max_hits = int(args[i + 1])
        del args[i:i + 2]
    if len(args) < 2:
        print(__doc__)
        return 2

    binary = Path(args[0]).resolve()
    func = int(args[1], 0) if args[1].lower().startswith("0x") \
        else int(args[1], 16)
    call_args = [a[4:] if a.startswith("str:") else
                 int(a, 0) if a.lower().startswith("0x") else int(a)
                 for a in args[2:]]
    kind, bits = sniff(binary)

    spec = {"binary": win_to_wsl(binary), "func": func, "args": call_args,
            "timeout": timeout, "kind": kind, "bits": bits,
            "rootfs": ROOTFS[(kind, bits)], "init_until": init_until,
            "break_at": break_at, "dumps": dump_exprs, "max_hits": max_hits}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as sf:
        json.dump(spec, sf)
        spec_path = Path(sf.name)
    result_path = spec_path.with_suffix(".result.json")

    worker_path = Path(__file__).resolve()
    cmd = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", WSL_PYTHON,
           win_to_wsl(worker_path), "--worker",
           win_to_wsl(spec_path), win_to_wsl(result_path)]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 120, env=env)
    try:
        result = json.loads(result_path.read_text())
    except (OSError, json.JSONDecodeError):
        result = {"ok": False, "error": "worker failed",
                  "stderr": (proc.stderr or "")[-2000:],
                  "stdout": (proc.stdout or "")[-2000:]}
    finally:
        spec_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)

    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        exec(WORKER)
    else:
        sys.exit(main(sys.argv[1:]))
