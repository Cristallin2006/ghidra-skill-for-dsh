#!/usr/bin/env python
"""oracle.py - function-level oracle: call ONE function with real inputs,
observe return value / stdout / stop reason.

Host usage (Windows, any Python 3):
  python oracle.py <binary> <func_addr> [args...] [--timeout SEC] [@out.json]

  <func_addr>  address as shown in the Ghidra listing (0x... or hex)
  args         integer args (dec or 0x...) and string args (prefix str:)
               x86-64 only: first 6 int args (SysV) / first 4 (Win64)

The real work happens in WSL Ubuntu qiling (/root/re-pwn-venv) — the host
side only translates paths and shuttles a JSON spec/result.

Examples:
  python oracle.py ./sample 0x101064 1 0x20 str:test
  python oracle.py ./check 0x1020a0 str:flag{guess} @out.json
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

WSL_DISTRO = "Ubuntu"
WSL_PYTHON = "/root/re-pwn-venv/bin/python"
ROOTFS = {"elf": "/root/qiling-rootfs/x8664_linux",
          "pe": "/root/qiling-rootfs/x8664_windows"}
SENTINEL = 0xDEAD0000  # fake return address; ql.run(end=...) stops here

WORKER = r'''
import json, sys
from qiling import Qiling
from qiling.const import QL_VERBOSE

spec = json.load(open(sys.argv[2]))
binary, func = spec["binary"], spec["func"]
args, timeout = spec["args"], spec.get("timeout", 30)
kind = spec["kind"]  # "elf" | "pe"
rootfs = spec["rootfs"]

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
if kind == "elf":
    from pwn import ELF
    e = ELF(binary, checksec=False)
    ghidra_base = 0x100000 if e.pie else e.address
    img = next(im for im in ql.loader.images if im.path == binary)
    func_rt = img.base + (func - ghidra_base)
else:
    func_rt = func  # PE32+ loads at preferred image base, same as Ghidra

# Dynamic binaries: libc/PLT/GOT only work after the CRT + dynamic linker
# have run. --init-until <ghidra addr of main> runs the normal startup
# first, so functions that call libc can be oracled too.
init_until = spec.get("init_until")
if init_until is not None:
    init_rt = (img.base + (init_until - ghidra_base)) if kind == "elf" \
        else init_until
    ql.run(end=init_rt, timeout=timeout * 1000000)

# --- marshal args -------------------------------------------------------
scratch = 0x50000000
ql.mem.map(scratch, 0x10000)
ptr = scratch
regs = (["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if kind == "elf"
        else ["rcx", "rdx", "r8", "r9"])
for reg, a in zip(regs, args):
    if isinstance(a, str):
        ql.mem.write(ptr, a.encode() + b"\x00")
        setattr(ql.arch.regs, reg, ptr)
        ptr += len(a) + 8
    else:
        setattr(ql.arch.regs, reg, int(a))

# --- call frame ---------------------------------------------------------
ql.arch.regs.rsp = (ql.arch.regs.rsp - 0x28) & ~0xF
ql.stack_write(0, SENTINEL)

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

result = {"ok": stop == "end", "retval": ql.arch.regs.rax,
          "stop_reason": stop,
          "stdout": "".join(captured), "func_runtime": hex(func_rt),
          "regs": {r: getattr(ql.arch.regs, r) for r in
                   ("rax", "rbx", "rdx", "rsi", "rdi")}}
json.dump(result, open(sys.argv[3], "w"))
'''


def win_to_wsl(p: Path) -> str:
    s = str(p.resolve()).replace("\\", "/")
    return f"/mnt/{s[0].lower()}{s[2:]}" if len(s) > 2 and s[1] == ":" else s


def sniff_kind(binary: Path) -> str:
    magic = binary.open("rb").read(4)
    return "elf" if magic == b"\x7fELF" else "pe"


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
    if len(args) < 2:
        print(__doc__)
        return 2

    binary = Path(args[0]).resolve()
    func = int(args[1], 0) if args[1].lower().startswith("0x") \
        else int(args[1], 16)
    call_args = [a[4:] if a.startswith("str:") else
                 int(a, 0) if a.lower().startswith("0x") else int(a)
                 for a in args[2:]]
    kind = sniff_kind(binary)

    spec = {"binary": win_to_wsl(binary), "func": func, "args": call_args,
            "timeout": timeout, "kind": kind, "rootfs": ROOTFS[kind],
            "init_until": init_until}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as sf:
        json.dump(spec, sf)
        spec_path = Path(sf.name)
    result_path = spec_path.with_suffix(".result.json")

    worker_path = Path(__file__).resolve()
    cmd = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", WSL_PYTHON,
           win_to_wsl(worker_path), "--worker",
           win_to_wsl(spec_path), win_to_wsl(result_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 120)
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
