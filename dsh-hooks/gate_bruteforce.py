#!/usr/bin/env python
"""gate_bruteforce.py - PreToolUse 自建大枚举器闸：约束系统的第一解不是爆破。

matcher "Pwsh|pwsh|Bash|bash"。判例 285db822（同题二刷）：
BV32 约束系统（ror/add/mul，z3 毫秒出唯一解），agent 全程 z3/SMT 零调用，
连写 4 个 OpenMP C 枚举器（2^31~2^32，单发 timeout 1800s）。失败触发的
断路器（铁律 6 连错 2 次升级）对「永远有产出」的枚举器结构性失效——
它一直在跑、一直在吐进度，从不"卡住"，所以枚举本身必须有自己的门。

判定（命中且未登记 -> exit 2 阻断）：
  命令文本中出现「自建大枚举器」指纹：
    A. C 系 for 循环上界可静态求值且 >= 2^28
       （for (...; i < 0x80000000; ...) / 1<<31 / 大十进制字面量）
    B. omp parallel for 与任何 >2^24 的循环界同现（并行爆破签名）
    C. python range(>=2^28) / range(0x...)
    D. itertools.product(..., repeat=N>=4)（隐式指数空间）
  且活跃台账（~/.dsh/ghidra-workspace/out/*.ledger.jsonl，12h 内）中
  没有任何 "type": "brute" 登记条目。

豁免（不过本门）：
  · skill 自带脚本（/scripts/）、ledger.py 等台账/工具链命令
  · hashcat/john 等专用爆破工具（铁律 13 正当爆破通道——约束系统之外的
    弱口令/小密钥空间枚举走那里，不需要 SMT 论证）
  · 已登记：任何活跃台账存在 brute 条目即放行（登记一次，放行后续）

放行条件 = 先落账：
  ledger.py brute <binary> --keyspace "2**31" --eta "25min @ 8线程" \
      --why-no-smt "①密码学黑盒比对 / ②SMT 已证不可行" [--tool ...]

任何内部异常 -> 放行（exit 0），门禁故障不许阻塞正常工作。
"""
import ast
import json
import operator
import re
import sys
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OUT = Path.home() / ".dsh" / "ghidra-workspace" / "out"
LEDGER_ACTIVE_SEC = 12 * 3600
BRUTE_ENTRY_SEC = 24 * 3600        # brute 登记的有效期
BIG = 1 << 28                      # 2^28 = 268,435,456
OMP_BIG = 1 << 24                  # omp 同现时放宽到 2^24

# skill 自带脚本与台账/工具链命令：不是自建枚举器
ALLOW = re.compile(
    r"ledger\.py|doctor\.py|rpc_driver\.py|driver\.py|/scripts/|"
    r"\\scripts\\|guarded_run\.py")
# 专用爆破工具：铁律 13 正当爆破通道，不过本门
DEDICATED = re.compile(r"\b(hashcat|john|john-the-ripper|hydra|crunch|maskprocessor)\b", re.IGNORECASE)

C_FOR = re.compile(
    r"\bfor\s*\(\s*[^;]*;[^;<>]*(?:<|<=|!=)\s*(\(?\s*\d+(?:[uUlL]*)\s*<<\s*\d+\s*\)?"
    r"|\d+\s*\*\*\s*\d+|[0-9xXa-fA-F_]+(?:[uUlL]*))")
PY_RANGE = re.compile(
    r"\brange\s*\(\s*(\d+\s*\*\*\s*\d+|\d+\s*<<\s*\d+|[0-9xXa-fA-F_]+)")
PRODUCT_REPEAT = re.compile(
    r"\b(?:itertools\.)?product\s*\([^)]*?repeat\s*=\s*(\d+)", re.DOTALL)
OMP = re.compile(r"omp\s+parallel\s+for")


def eval_bound(expr: str):
    """静态求值循环上界字面量；含标识符/函数调用返回 None（不判）。"""
    ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
           ast.Pow: operator.pow, ast.LShift: operator.lshift,
           ast.RShift: operator.rshift}
    s = re.sub(r"(?i)(?<=\d)[ul]+\b", "", expr.strip())  # 去 C 整数后缀
    try:
        tree = ast.parse(s, mode="eval")
    except SyntaxError:
        return None

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return int(node.value)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        if isinstance(node, ast.BinOp) and type(node.op) in ops:
            return ops[type(node.op)](ev(node.left), ev(node.right))
        raise ValueError

    try:
        return ev(tree)
    except (ValueError, OverflowError, ZeroDivisionError):
        return None


def detect(cmd: str):
    """-> (命中描述, 上界值) | None"""
    for m in C_FOR.finditer(cmd):
        v = eval_bound(m.group(1))
        if v is not None and v >= BIG:
            return (f"C 循环上界 {m.group(1).strip()} ≈ 2^{v.bit_length() - 1}", v)
        if v is not None and v >= OMP_BIG and OMP.search(cmd):
            return (f"OpenMP 并行循环上界 {m.group(1).strip()}", v)
    for m in PY_RANGE.finditer(cmd):
        v = eval_bound(m.group(1))
        if v is not None and v >= BIG:
            return (f"range({m.group(1).strip()}) ≈ 2^{v.bit_length() - 1}", v)
    m = PRODUCT_REPEAT.search(cmd)
    if m and int(m.group(1)) >= 4:
        return (f"itertools.product repeat={m.group(1)}（隐式指数空间）", None)
    return None


def active_ledgers():
    if not OUT.is_dir():
        return []
    now = time.time()
    res = []
    for j in OUT.glob("*.ledger.jsonl"):
        try:
            if now - j.stat().st_mtime <= LEDGER_ACTIVE_SEC:
                res.append(j)
        except OSError:
            continue
    return res


def has_brute_registration(ledgers) -> bool:
    now = time.time()
    for j in ledgers:
        try:
            for line in j.read_text(
                    encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or '"brute"' not in line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("type") != "brute":
                    continue
                # 条目时间窗：ts 格式 "YYYY-MM-DD HH:MM:SS"
                try:
                    from datetime import datetime
                    ts = datetime.strptime(e.get("ts", ""), "%Y-%m-%d %H:%M:%S").timestamp()
                except (ValueError, TypeError):
                    ts = 0
                if ts and now - ts <= BRUTE_ENTRY_SEC:
                    return True
        except OSError:
            continue
    return False


def block(msg):
    print(msg, file=sys.stderr)
    return 2


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ti.get("cmd") or ""
    if not isinstance(cmd, str) or not cmd.strip():
        return 0
    if ALLOW.search(cmd) or DEDICATED.search(cmd):
        return 0
    hit = detect(cmd)
    if hit is None:
        return 0
    desc, _ = hit
    if has_brute_registration(active_ledgers()):
        return 0
    return block(
        f"[gate_bruteforce · 铁律13 约束系统路由闸] 检测到自建大枚举器（{desc}，"
        "候选空间 ≥ 2^28），但活跃台账没有任何 brute 登记。\n"
        "约束系统（等式/不等式组求未知输入）的第一工具是 z3/SMT，不是手写枚举器——\n"
        "判例 285db822：BV32 方程组（ror/add/mul）z3 毫秒出唯一解，"
        "agent 连写 4 个 OpenMP C 枚举器烧 20+ min（z3 全程零调用）。\n"
        "失败触发的断路器拦不住「永远有产出」的枚举器，所以枚举必须先过账。\n"
        "大枚举仅在两种情况合法：\n"
        "  ① 密码学黑盒比对（KDF/加解密输出比对，SMT 结构性不适用）\n"
        "  ② SMT 已证不可行（unsat/超时证据已落账）\n"
        "开跑前登记（登记一次即放行后续）：\n"
        "  python ~/.dsh/skills/ghidra-core/scripts/ledger.py brute <binary> \\\n"
        "    --keyspace \"2**31\" --eta \"25min @ 8线程\" \\\n"
        "    --why-no-smt \"①或②的理由\" [--tool \"c/openmp\"]\n"
        "hashcat/john 等专用工具不过本门（铁律 13 正当爆破通道）。"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_bruteforce hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
