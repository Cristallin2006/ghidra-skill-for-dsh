#!/usr/bin/env python3
"""layer_dump.py — 分层运行时解密样本的「gdb 断点 dump → objdump → strings」一条龙。

判例 c50c8812（07CTF Glitched）：同一模式（loader 返回断点 → dump 解密页 →
objdump -D 线性反汇编 → strings）被手写 heredoc 重复 4 次（g9/g12/g13/g17.gdb）。
本脚本把它固化成一次调用。

典型用法（在「本层解密完成、下一层尚未执行」的断点处取层，如 loader 返回点）：

    python3 layer_dump.py ./glitch --break 0x40115d \\
        --dump 0x405000:0x1000:s2.bin --dump 0x406000:0x1000:s3.bin \\
        --input in_s1.txt --pass-signals --disasm --strings

- --break 只在第一次命中时 dump 并退出（dump 完即 quit，程序不继续跑）。
- --pass-signals：SIGILL/SIGSEGV/SIGBUS nostop noprint pass——自定义信号
  handler 是正常执行路径的样本（UD2 磁带/页故障合成）在断点前会被信号停住时加。
  **不含 SIGTRAP**：gdb 的断点/单步内部复用 SIGTRAP，pass 掉会让程序直接死
  （本脚本实测：pass SIGTRAP 后 Program terminated with signal SIGTRAP）。
- --disasm 产物 = OUT.dis（objdump -D 线性反汇编，--adjust-vma 对齐到 VA）。
  线性反汇编会从密文/数据里解出垃圾指令，读 .dis 时以地址为锚，别信 CFG。
- 不含解密层「重载分析器」能力（dump → 以基址 import 成 raw binary → 反编译
  拿 xref）；需要时手工 import，本脚本只管取层。

exit: 0 成功 / 2 用法错 / 3 gdb 或 objdump 缺失 / 4 断点未命中（零 dump 产出）
stdlib only，不经 daemon。
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

_SIGNALS = ("SIGILL", "SIGSEGV", "SIGBUS")  # 不含 SIGTRAP：gdb 内部复用，pass 即程序死（实测）


def _parse_dump(spec):
    """VA:LEN:OUT -> (va, length, out)。VA 必须 0x 十六进制，LEN 支持 0x。"""
    parts = spec.split(":")
    if len(parts) != 3:
        raise ValueError(f"--dump 格式必须是 VA:LEN:OUT，收到 {spec!r}")
    va_s, len_s, out = parts
    va = int(va_s, 16)
    length = int(len_s, 16) if len_s.lower().startswith("0x") else int(len_s)
    if length <= 0:
        raise ValueError(f"--dump 长度必须为正：{spec!r}")
    if not out:
        raise ValueError(f"--dump 输出路径为空：{spec!r}")
    return va, length, out


def _build_gdb_script(args, dumps):
    lines = ["set pagination off", "set confirm off"]
    if args.pass_signals:
        for sig in _SIGNALS:
            lines.append(f"handle {sig} nostop noprint pass")
    lines.append(f"break *{args.breakpoint}")
    lines.append("commands")
    lines.append("silent")
    lines.append(f'printf ">>> layer_dump: hit {args.breakpoint}\\n"')
    for va, length, out in dumps:
        lines.append(f'dump binary memory {out} {va:#x} {va + length:#x}')
        lines.append(f'printf ">>> dumped {out} ({length} bytes @ {va:#x})\\n"')
    lines.append("quit")
    lines.append("end")
    run = "run"
    if args.input:
        run += f" < {args.input}"
    else:
        run += " < /dev/null"
    lines.append(run)
    return "\n".join(lines) + "\n"


def _strings(path, va, min_len=5):
    data = open(path, "rb").read()
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(f"{va + m.start():#x}  {m.group().decode('ascii')}")
    return out


def main():
    ap = argparse.ArgumentParser(
        description="gdb 断点 dump 解密层 + objdump + strings 一条龙（见 docstring）")
    ap.add_argument("binary", help="目标二进制")
    ap.add_argument("--break", "-b", dest="breakpoint", required=True,
                    help="取层断点地址（0x…，如 loader 返回点）")
    ap.add_argument("--dump", action="append", required=True, metavar="VA:LEN:OUT",
                    help="可重复。VA 十六进制，LEN 支持 0x，OUT 输出文件")
    ap.add_argument("--input", help="stdin 输入文件（run < FILE）；缺省 </dev/null")
    ap.add_argument("--pass-signals", action="store_true",
                    help="SIGILL/SIGSEGV/SIGBUS/SIGTRAP nostop noprint pass")
    ap.add_argument("--disasm", action="store_true",
                    help="对每个 dump 跑 objdump -D（x86-64，--adjust-vma=VA）→ OUT.dis")
    ap.add_argument("--strings", action="store_true",
                    help="对每个 dump 提取可打印串（≥5，带 VA 偏移）")
    ap.add_argument("--timeout", type=int, default=120, help="gdb 运行超时秒数")
    ap.add_argument("--keep-gdb", action="store_true", help="保留生成的 gdb 脚本")
    args = ap.parse_args()

    if not os.path.isfile(args.binary):
        print(f"FATAL: binary 不存在：{args.binary}", file=sys.stderr)
        return 2
    try:
        dumps = [_parse_dump(s) for s in args.dump]
    except (ValueError, IndexError) as e:
        print(f"FATAL: {e}", file=sys.stderr)
        return 2

    gdb = shutil.which("gdb")
    if not gdb:
        print("FATAL: gdb 不在 PATH", file=sys.stderr)
        return 3
    if args.disasm and not shutil.which("objdump"):
        print("FATAL: --disasm 需要 objdump 在 PATH", file=sys.stderr)
        return 3

    script = _build_gdb_script(args, dumps)
    fd, script_path = tempfile.mkstemp(suffix=".gdb", prefix="layer_dump_")
    with os.fdopen(fd, "w") as f:
        f.write(script)

    try:
        proc = subprocess.run(
            [gdb, "-nx", "-q", "-batch", "-x", script_path, args.binary],
            capture_output=True, text=True, timeout=args.timeout)
        gdb_out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        print(f"FATAL: gdb 超时（{args.timeout}s）——断点未命中或程序卡住",
              file=sys.stderr)
        return 4
    finally:
        if not args.keep_gdb:
            try:
                os.unlink(script_path)
            except OSError:
                pass
        else:
            print(f"gdb script: {script_path}")

    produced = []
    for va, length, out in dumps:
        if os.path.isfile(out) and os.path.getsize(out) == length:
            sha = hashlib.sha256(open(out, "rb").read()).hexdigest()
            produced.append((va, length, out))
            print(f"OK {out}  {length} bytes @ {va:#x}  sha256={sha[:16]}…")
        else:
            size = os.path.getsize(out) if os.path.isfile(out) else -1
            print(f"MISS {out}（期望 {length} 字节，实得 {size}）", file=sys.stderr)

    if not produced:
        print("FATAL: 零 dump 产出——断点未命中或 run 失败。gdb 输出尾部：",
              file=sys.stderr)
        print("\n".join(gdb_out.splitlines()[-15:]), file=sys.stderr)
        return 4

    for va, length, out in produced:
        if args.disasm:
            dis = out + ".dis"
            with open(dis, "w") as f:
                subprocess.run(
                    ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                     f"--adjust-vma={va:#x}", out],
                    stdout=f, check=False)
            print(f"DIS {dis}")
        if args.strings:
            print(f"--- strings {out} ---")
            for line in _strings(out, va):
                print(line)

    print("next: 逐层读 .dis 建模 → 约束系统第一工具 z3（铁律 13 路由闸）；"
          "区域观察记得 ledger.py observe 落账")
    return 0


if __name__ == "__main__":
    sys.exit(main())
