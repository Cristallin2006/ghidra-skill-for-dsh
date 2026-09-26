#!/usr/bin/env python
"""oracle_family.py - 打桩 oracle 家族：单因子隔离（铁律 14 判定性实验的批量形态）。

Host-side tool (any Python 3.8+, stdlib only; 纯本地子进程工具，不经 daemon)。

binary + 函数地址 + 一组打桩返回常量 -> 批量产出 patched 副本 + 逐个运行
+ 差分表。把黑盒输出分解成可命名因子：钉 A 因子为常量看输出变不变——
变 = 该因子参与计算；任意常量下都不变 = 无关通道（DEFCON26 复盘：这是
推翻"参数角色读反"错模型的决定性实验，手搓 /tmp/chall_A、chall_h 的脚本化）。

用法:
  oracle_family.py <binary> --stub 0x13d74=0x00 --stub 0x13d74=0xff [--stub ...] \
      [--addr-is va|offset] [--rax] [--run-args "程序参数"] [--stdin-file F] \
      [--timeout 10] [--json] [--keep]

patch 方式（x86-64，函数开头覆写）:
  默认:  mov eax, imm32 ; ret   -> B8 <imm32> C3      （6 字节，val ≤ 0xffffffff）
  --rax: mov rax, imm64 ; ret   -> 48 B8 <imm64> C3   （10 字节）
其它架构（含 ELF e_machine != 0x3e、PE machine != 0x8664）未支持，exit 3。

地址换算（--addr-is，默认 va）:
  va:     ELF 按 program header（PT_LOAD）把虚拟地址换算成文件偏移；
          PE 暂只支持 offset（VA->文件偏移需按节表换算，未实现），给 va 会 exit 3。
  offset: 直接当文件偏移用。
Ghidra listing 里的地址对 PIE ELF 是 vaddr（通常 0x100000+ 基址），用 va；
对 objdump/nm 看到的非 PIE 地址同样是 vaddr，用 va。

exit: 0 全部副本成功运行并完成差分; 2 有副本运行失败（超时/非零退出，
      差分表仍给出，失败行单列）; 3 用法/文件/架构/地址换算错误。
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys

for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

EM_X86_64 = 0x3E
PE_X86_64 = 0x8664


def die(msg: str) -> None:
    print(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))
    raise SystemExit(3)


def parse_stub(spec: str) -> tuple[int, int]:
    if "=" not in spec:
        die(f"--stub 格式应为 <addr>=<val>，收到: {spec!r}")
    a, v = spec.split("=", 1)

    def _int(s: str) -> int:
        s = s.strip()
        try:
            return int(s, 0)
        except ValueError:
            return int(s, 16)

    try:
        addr, val = _int(a), _int(v)
    except ValueError:
        die(f"--stub 地址/值无法解析: {spec!r}")
    if addr < 0 or val < 0:
        die(f"--stub 地址/值必须非负: {spec!r}")
    return addr, val


def detect_format(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        if data[4] != 2:
            die("仅支持 ELF64（32 位 ELF 未支持）")
        machine = struct.unpack_from("<H", data, 0x12)[0]
        if machine != EM_X86_64:
            die(f"未支持的架构: ELF e_machine=0x{machine:x}（仅 x86-64=0x3e）。"
                "foreign-arch ELF 的先 import 进 Ghidra 用对应 processor，"
                "打桩需手工按该架构指令编码")
        return "elf"
    if data[:2] == b"MZ":
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            die("MZ 头但 PE 签名缺失，文件损坏或非常规格式")
        machine = struct.unpack_from("<H", data, pe_off + 4)[0]
        if machine != PE_X86_64:
            die(f"未支持的架构: PE machine=0x{machine:x}（仅 x86-64=0x8664）")
        return "pe"
    die("无法识别文件格式（仅支持 ELF64 / PE x86-64）")


def elf_va_to_offset(data: bytes, va: int) -> int:
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack_from(
            "<QQQQ", data, off + 8)
        if p_vaddr <= va < p_vaddr + p_filesz:
            return va - p_vaddr + p_offset
    die(f"va 0x{va:x} 不在任何 PT_LOAD 段内（确认 --addr-is；"
        "文件偏移请用 --addr-is offset）")


def make_stub(val: int, wide: bool) -> bytes:
    if wide:
        return b"\x48\xB8" + struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF) + b"\xC3"
    if val > 0xFFFFFFFF:
        die(f"打桩值 0x{val:x} 超过 imm32，加 --rax 用 mov rax, imm64")
    return b"\xB8" + struct.pack("<I", val) + b"\xC3"


def run_one(path: str, run_args: list[str], stdin_data: bytes | None,
            timeout: int) -> dict:
    try:
        p = subprocess.run([path] + run_args, input=stdin_data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
        return {"status": "ok", "exit_code": p.returncode,
                "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "exit_code": None,
                "stdout": b"", "stderr": b""}
    except OSError as ex:
        return {"status": "spawn-error", "exit_code": None,
                "stdout": b"", "stderr": str(ex).encode()}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="打桩 oracle 家族：钉单因子为常量，看输出变不变（铁律 14）")
    ap.add_argument("binary", help="x86-64 ELF/PE")
    ap.add_argument("--stub", action="append", required=True, metavar="ADDR=VAL",
                    help="打桩点=返回常量（hex），可重复；同地址多个值即一个家族")
    ap.add_argument("--addr-is", choices=["va", "offset"], default="va",
                    help="stub 地址是虚拟地址还是文件偏移（默认 va；PE 暂只支持 offset）")
    ap.add_argument("--rax", action="store_true",
                    help="用 mov rax, imm64; ret（10 字节）代替 mov eax, imm32; ret")
    ap.add_argument("--run-args", default="",
                    help="传给程序的参数（一个字符串，内部 shlex 拆分）")
    ap.add_argument("--stdin-file", help="喂给 stdin 的文件")
    ap.add_argument("--timeout", type=int, default=10, help="每次运行超时秒数")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--keep", action="store_true",
                    help="保留 patched 副本（默认跑完删除）")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        die(f"binary not found: {binary}")
    data = open(binary, "rb").read()
    fmt = detect_format(data)
    if fmt == "pe" and args.addr_is == "va":
        die("PE 暂只支持 --addr-is offset（VA->文件偏移需按节表换算，未实现）")

    stdin_data = None
    if args.stdin_file:
        if not os.path.isfile(args.stdin_file):
            die(f"--stdin-file not found: {args.stdin_file}")
        stdin_data = open(args.stdin_file, "rb").read()
    run_args = shlex.split(args.run_args)

    stubs = [parse_stub(s) for s in args.stub]
    jobs = []
    for addr, val in stubs:
        offset = addr if args.addr_is == "offset" else elf_va_to_offset(data, addr)
        patch = make_stub(val, args.rax)
        if offset + len(patch) > len(data):
            die(f"打桩偏移 0x{offset:x} 越出文件末尾")
        jobs.append({"addr": addr, "val": val, "offset": offset, "patch": patch})

    base = os.path.basename(binary)
    stem, suffix = os.path.splitext(base)
    made = []
    rc = 0
    try:
        baseline = run_one(binary, run_args, stdin_data, args.timeout)
        runs = []
        for j in jobs:
            name = f"{stem}.stub_{j['addr']:x}_{j['val']:x}{suffix}"
            copy_path = os.path.join(os.path.dirname(binary), name)
            with open(binary, "rb") as fsrc, open(copy_path, "wb") as fdst:
                buf = bytearray(fsrc.read())
                buf[j["offset"]:j["offset"] + len(j["patch"])] = j["patch"]
                fdst.write(buf)
            shutil.copymode(binary, copy_path)
            made.append(copy_path)
            r = run_one(copy_path, run_args, stdin_data, args.timeout)
            changed = (r["status"] == "ok" and baseline["status"] == "ok"
                       and (r["stdout"] != baseline["stdout"]
                            or r["exit_code"] != baseline["exit_code"]))
            runs.append({**j, "copy": copy_path, "status": r["status"],
                         "exit_code": r["exit_code"],
                         "stdout_hex": r["stdout"].hex(),
                         "stderr": r["stderr"][:200].decode("utf-8", "replace"),
                         "changed": changed})
            if r["status"] != "ok":
                rc = 2

        # 按地址聚合成判词
        verdicts = []
        by_addr: dict[int, list] = {}
        for r in runs:
            by_addr.setdefault(r["addr"], []).append(r)
        for addr, rs in by_addr.items():
            ok_runs = [r for r in rs if r["status"] == "ok"]
            any_changed = any(r["changed"] for r in ok_runs)
            if any_changed:
                verdict = "该因子参与计算（打桩返回值改变了输出）"
            elif len(ok_runs) >= 2:
                verdict = ("任意常量下输出均不变 ⇒ 该因子不参与，"
                           "疑为无关通道（可停止在它上面读码）")
            else:
                verdict = ("该常量下输出不变（只有 1 个值，建议 ≥2 个常量确认后"
                           "再判无关通道）")
            verdicts.append({"addr": addr, "values": [r["val"] for r in rs],
                             "verdict": verdict})

        result = {"ok": rc == 0, "binary": binary, "format": fmt,
                  "addr_is": args.addr_is,
                  "baseline": {"status": baseline["status"],
                               "exit_code": baseline["exit_code"],
                               "stdout_hex": baseline["stdout"].hex()},
                  "runs": [{k: v for k, v in r.items() if k != "patch"}
                           for r in runs],
                  "verdicts": verdicts}
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"[oracle_family] {base} ({fmt}, addr-is {args.addr_is})")
            bl = result["baseline"]
            print(f"基线（未 patch）: status={bl['status']} "
                  f"exit={bl['exit_code']} stdout={bl['stdout_hex']!r}")
            print("| 打桩点 | 值 | 文件偏移 | 运行 | exit | 输出变? |")
            print("|--------|----|----------|------|------|---------|")
            for r in runs:
                ch = ("变" if r["changed"] else "不变") if r["status"] == "ok" \
                    else f"运行失败({r['status']})"
                print(f"| 0x{r['addr']:x} | 0x{r['val']:x} | 0x{r['offset']:x} "
                      f"| {r['status']} | {r['exit_code']} | {ch} |")
            for v in verdicts:
                vals = ", ".join(f"0x{x:x}" for x in v["values"])
                print(f"判词 0x{v['addr']:x}（值 {vals}）: {v['verdict']}")
            if not args.keep:
                print("（patched 副本已删除；--keep 保留）")
        return rc
    finally:
        if not args.keep:
            for p in made:
                try:
                    os.unlink(p)
                except OSError:
                    pass


if __name__ == "__main__":
    sys.exit(main())
