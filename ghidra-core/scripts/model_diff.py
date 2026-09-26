#!/usr/bin/env python
"""model_diff.py - 模型实现 vs 真实 oracle 随机对拍（铁律 10② 分歧指纹产出工具）。

Host-side tool (any Python 3.8+, stdlib only; 纯本地子进程工具，不经 daemon)。

用法:
  model_diff.py --model "<cmd 模板>" --oracle "<cmd 模板>" \
      --input-gen hex:32 | dec[:min:max] | ascii:16 [--n 200] [--seed 1] [--json]

两条命令各为一个进程；每组输入经 stdin 喂入（hex 生裸字节，dec/ascii 追加
换行），stdout 逐字节比对。首个分歧给出输入 + 双方输出（hex 对照）+ 分歧
模式指纹 + 判词。

分歧指纹（判据出处 ghidra-core 铁律 10②：差异呈规律 = 接口/搬运写错，
不是"程序少了运算"）:
  长度不一致      输出长度不同            -> 疑似接口错（framing/编码/换行/padding）
  低半字全对      每字节低 4 bit 全部相等  -> 疑似接口错（半字/位宽搬运错）
  高低半字交换    model == 逐字节半字交换(oracle) -> 疑似接口错（hex 解码/字节序错）
  单常量差        恰好 1 个字节不同        -> 疑似接口错（单字段/边界处理错）
  全体偏移固定值  所有字节的差值恒定        -> 疑似接口错（基址/起点/常量加错）
  完全无关        无上述规律              -> 疑似算法错（模型本身错）

统计: mismatch 率 + 全部分歧的指纹汇总（--json 输出机器可读结构）。
exit: 0 全部一致; 2 有分歧; 3 命令错误（子进程非零退出/超时/启动失败/用法错）。
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from collections import Counter

for _stream in (sys.stdout, sys.stderr):
    if _stream.encoding and _stream.encoding.lower() not in ("utf-8", "utf8"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

TIMEOUT = 10  # 每组输入的子进程超时（秒）

VERDICT_INTERFACE = ("疑似接口/搬运错，不是算法错（铁律 10②）：输出结构对得上，"
                     "先怀疑输入输出解析、半字/位宽、基址偏移——修接口，别改算法")
VERDICT_LENGTH = ("疑似接口错（framing）：先核对编码（hex vs raw）、换行、padding、"
                  "长度前缀——输出形状都不对，谈不上算法")
VERDICT_ALGORITHM = ("疑似算法错/模型整体错误：差异无搬运规律，回到算法层面对照"
                     "（此时才允许怀疑程序/模型少了运算）")


def gen_input(spec: str, rng: random.Random) -> bytes:
    parts = spec.split(":")
    kind = parts[0].lower()
    try:
        if kind == "hex":
            n = int(parts[1]) if len(parts) > 1 else 32
            return bytes(rng.randrange(256) for _ in range(n))
        if kind == "dec":
            lo = int(parts[1]) if len(parts) > 2 else 0
            hi = int(parts[2]) if len(parts) > 2 else 2**31 - 1
            return (str(rng.randint(lo, hi)) + "\n").encode()
        if kind == "ascii":
            n = int(parts[1]) if len(parts) > 1 else 16
            return bytes(rng.randrange(0x20, 0x7F) for _ in range(n))
    except (ValueError, IndexError):
        pass
    raise ValueError(f"未知 --input-gen 规格: {spec!r}"
                     "（支持 hex:N / dec[:min:max] / ascii:N）")


def run_cmd(cmd: str, data: bytes) -> tuple[str, bytes, bytes]:
    """-> (status, stdout, stderr); status: ok|timeout|spawn-error|nonzero-exit"""
    try:
        p = subprocess.run(cmd, input=data, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return ("timeout", b"", b"")
    except OSError as ex:
        return ("spawn-error", b"", str(ex).encode())
    if p.returncode != 0:
        return ("nonzero-exit", p.stdout, p.stderr)
    return ("ok", p.stdout, p.stderr)


def _swap_nib(b: int) -> int:
    return ((b & 0x0F) << 4) | (b >> 4)


def fingerprint(model_out: bytes, oracle_out: bytes) -> tuple[str, str, str]:
    """-> (指纹名, 细节, 判词)"""
    if len(model_out) != len(oracle_out):
        return ("长度不一致",
                f"model={len(model_out)}B vs oracle={len(oracle_out)}B",
                VERDICT_LENGTH)
    n = len(model_out)
    diffs = [i for i in range(n) if model_out[i] != oracle_out[i]]
    if all((model_out[i] & 0x0F) == (oracle_out[i] & 0x0F) for i in range(n)):
        bad = next(i for i in range(n) if model_out[i] != oracle_out[i])
        return ("低半字全对",
                f"{len(diffs)}/{n} 字节高半字不同，低半字全部一致"
                f"（首个 offset {bad}: model=0x{model_out[bad]:02x} "
                f"oracle=0x{oracle_out[bad]:02x}）",
                VERDICT_INTERFACE)
    if all(model_out[i] == _swap_nib(oracle_out[i]) for i in range(n)):
        return ("高低半字交换",
                f"model 输出 = oracle 输出逐字节半字交换（{len(diffs)}/{n} 字节），"
                "典型的 hex 解码/位拼接写反",
                VERDICT_INTERFACE)
    if len(diffs) == 1:
        i = diffs[0]
        return ("单常量差",
                f"仅 offset {i} 不同: model=0x{model_out[i]:02x} "
                f"oracle=0x{oracle_out[i]:02x}",
                VERDICT_INTERFACE)
    deltas = {(model_out[i] - oracle_out[i]) % 256 for i in range(n)}
    if len(deltas) == 1:
        d = deltas.pop()
        return ("全体偏移固定值",
                f"所有字节 model = oracle + 0x{d:02x}（mod 256）",
                VERDICT_INTERFACE)
    return ("完全无关",
            f"{len(diffs)}/{n} 字节不同且无搬运规律",
            VERDICT_ALGORITHM)


def hexs(b: bytes, limit: int = 64) -> str:
    s = b[:limit].hex(" ")
    return s + (f" …(+{len(b) - limit}B)" if len(b) > limit else "")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="模型 vs oracle 随机对拍 + 分歧指纹（铁律 10②）")
    ap.add_argument("--model", required=True,
                    help="我方模型实现命令（stdin 喂输入/stdout 出结果）")
    ap.add_argument("--oracle", required=True, help="真实 oracle 命令（同约定）")
    ap.add_argument("--input-gen", required=True,
                    help="hex:N（N 随机字节）| dec[:min:max]（随机整数行）| "
                         "ascii:N（N 随机可打印字符）")
    ap.add_argument("--n", type=int, default=200, help="投喂组数（默认 200）")
    ap.add_argument("--seed", type=int, default=1, help="确定性 seed（默认 1）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    mismatches = []
    errors = []
    for i in range(args.n):
        data = gen_input(args.input_gen, rng)
        om_status, om_out, om_err = run_cmd(args.oracle, data)
        mo_status, mo_out, mo_err = run_cmd(args.model, data)
        if om_status != "ok" or mo_status != "ok":
            errors.append({"index": i, "input_hex": data.hex(),
                           "oracle_status": om_status,
                           "model_status": mo_status,
                           "oracle_stderr": om_err[:200].decode("utf-8", "replace"),
                           "model_stderr": mo_err[:200].decode("utf-8", "replace")})
            continue
        if mo_out != om_out:
            fp, detail, verdict = fingerprint(mo_out, om_out)
            mismatches.append({"index": i, "input_hex": data.hex(),
                               "oracle_hex": om_out.hex(),
                               "model_hex": mo_out.hex(),
                               "fingerprint": fp, "detail": detail,
                               "verdict": verdict})

    if errors:
        result = {"ok": False, "error": "子进程运行错误（命令本身有问题，先修命令）",
                  "runs": args.n, "run_errors": len(errors),
                  "first_error": errors[0]}
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"[model_diff] 命令错误：{len(errors)}/{args.n} 组输入子进程非正常结束")
            e = errors[0]
            print(f"  首例 #{e['index']}: oracle={e['oracle_status']} "
                  f"model={e['model_status']}")
            print(f"  oracle stderr: {e['oracle_stderr']!r}")
            print(f"  model  stderr: {e['model_stderr']!r}")
            print("先让两条命令单独跑通再对拍。")
        return 3

    fp_counter = Counter(m["fingerprint"] for m in mismatches)
    result = {
        "ok": not mismatches, "runs": args.n, "seed": args.seed,
        "input_gen": args.input_gen,
        "mismatches": len(mismatches),
        "mismatch_rate": len(mismatches) / max(args.n, 1),
        "fingerprint_histogram": dict(fp_counter),
        "first_divergence": mismatches[0] if mismatches else None,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"[model_diff] n={args.n} seed={args.seed} gen={args.input_gen}")
        print(f"  oracle: {args.oracle}")
        print(f"  model : {args.model}")
        if not mismatches:
            print(f"结果: {args.n}/{args.n} 全部一致——模型与 oracle 在该输入分布下逐字节相同")
        else:
            m = mismatches[0]
            print(f"首个分歧（第 {m['index']} 组）:")
            print(f"  input : {hexs(bytes.fromhex(m['input_hex']))}")
            print(f"  oracle: {hexs(bytes.fromhex(m['oracle_hex']))}")
            print(f"  model : {hexs(bytes.fromhex(m['model_hex']))}")
            print(f"  指纹: {m['fingerprint']} —— {m['detail']}")
            print(f"  判词: {m['verdict']}")
            rate = result["mismatch_rate"] * 100
            print(f"统计: mismatch {len(mismatches)}/{args.n}（{rate:.1f}%）")
            for fp, cnt in fp_counter.most_common():
                print(f"  {fp} × {cnt}")
    return 2 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
