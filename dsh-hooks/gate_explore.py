#!/usr/bin/env python
"""gate_explore.py - PreToolUse 探索运行熔断：heredoc 载体盲区 + 变体枚举 + angr 禁项 + Cython 前置。

matcher "Pwsh|pwsh|Bash|bash"。f862c151 session 事故：97 次 heredoc 探索、
写出的 .py 仅 ~2 个——gate_churn（Write 侧，数文件）完全失效；128 个手写
结构变体盲搜，gdb/frame_map/model_diff/emulate 全程 0 次；最后要上 angr
（16 轮 × 68 次 mod-65537 乘 + 192 次查表的 ARX/模乘密文，必爆）。

四类判定（任一命中 exit 2 阻断，顺序即优先级）：
  A. angr 禁项：命令（含内联脚本体）命中 \\bangr\\b，且活跃台账无帧槽位/仿真类
     证据（frame_map|emulate|gdb|帧槽|插桩）-> 给升级阶梯，禁止跳档
  B. Cython 前置：命令作用于 python_ext=true 的样本（读 <样本>.triage.json），
     且台账无 const_scan/frame_map 证据 -> 先跑 §12 元数据 + 帧槽位再建模
  C. 变体枚举：本次为探索性运行，其脚本体与滑窗内 >=2 次历史脚本体相似
     （difflib ratio > 0.7，"同一思路换措辞"的指纹），且台账条目数自最早
     相似运行起未增长 -> 直指 model_diff.py 分歧指纹分类
  D. 探索计数熔断：滑窗 30min 内探索运行 >= 25 次且活跃台账 stuck=0
     -> 强制 ledger.py stuck 落账（与 Write 侧 gate_churn 共用"零 stuck
     熔断"判定核，两个载体都封死）

探索运行认定（全部是"不落盘的临时代码"，落盘的由 gate_churn 管）：
  python[3] - <<'PY' ...（heredoc）；python -c "..."；echo/printf ... | python[3]
skill 自带脚本（路径含 /scripts/）与台账/工具链命令不算探索。

计数文件：<ws>/out/.explore-runs.jsonl（{"ts","body","ledger_n"}，24h 滚动）。
任何内部异常 -> 放行（exit 0），门禁故障不许阻塞正常工作。
"""
import difflib
import json
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
RUNS = OUT / ".explore-runs.jsonl"

EXPLORE_WINDOW = 30 * 60      # 探索计数滑窗
EXPLORE_LIMIT = 25            # 窗内历史探索运行达到此数后熔断
RECENT_SEC = 24 * 3600        # 计数文件滚动窗口
LEDGER_ACTIVE_SEC = 12 * 3600
SIM_RATIO = 0.7               # 脚本体相似度阈值
SIM_MIN = 2                   # 窗内相似历史达到此数触发变体枚举熔断
BODY_KEEP = 2000              # 相似度比对保留的脚本体长度

ANGR = re.compile(r"\bangr\b")
FRAME_EVIDENCE = re.compile(
    r"frame_map|emulate[-_]|emulate_blob|gdb|帧槽|p-?code|插桩", re.IGNORECASE)
CYTHON_EVIDENCE = re.compile(r"const_scan|frame_map")

# skill 自带脚本与台账/工具链命令：不是探索
ALLOW = re.compile(
    r"ledger\.py|doctor\.py|rpc_driver\.py|driver\.py|/scripts/|"
    r"\\scripts\\|guarded_run\.py")

PY = re.compile(r"\bpython[0-9.]*(?:\.exe)?\b")
HEREDOC = re.compile(
    r"<<-?\s*['\"]?(\w+)['\"]?\s*\n(.*?)\n\1(?=\s|$)", re.DOTALL)
DASH_C = re.compile(r"\bpython[0-9.]*(?:\.exe)?\s+-c\s+('([^']*)'|\"([^\"]*)\")",
                    re.DOTALL)
STDIN_PIPE = re.compile(r"\|\s*python[0-9.]*(?:\.exe)?\b")

SAMPLE_EXT = {".exe", ".dll", ".so", ".bin", ".elf", ".dex", ".apk",
              ".class", ".sys", ".com", ".scr", ".ocx", ".dylib", ".o", ".a"}
EXEMPT_EXT = {".pcap", ".pcapng", ".txt", ".md", ".json", ".jsonl", ".py",
              ".c", ".cpp", ".h", ".log", ".hex", ".xml", ".yml", ".yaml"}
MAGICS = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe",
          b"\xca\xfe\xba\xbe", b"dex\n", b"\xde\xc0\x17\x0b")


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


def ledger_text(ledgers):
    parts = []
    for j in ledgers:
        try:
            parts.append(j.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(parts)


def ledger_entries(ledgers):
    n = 0
    for j in ledgers:
        try:
            n += sum(1 for line in j.read_text(
                encoding="utf-8", errors="replace").splitlines() if line.strip())
        except OSError:
            continue
    return n


def ledger_stucks(text):
    n = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if json.loads(line).get("type") == "stuck":
                n += 1
        except Exception:
            continue
    return n


def find_sample(cmd, cwd):
    tokens = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', cmd)
    # 兜底：heredoc 体内路径常嵌在 CDLL('...')/open("...") 里，不作为独立 token
    tokens += [q for pair in re.findall(r"'([^']+)'|\"([^\"]+)\"", cmd)
               for q in pair if q]
    for tok in tokens:
        t = tok.strip("\"'")
        if not t or t.startswith("-") or len(t) > 300:
            continue
        p = Path(t)
        if not p.is_absolute():
            p = cwd / p
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        ext = p.suffix.lower()
        if ext in EXEMPT_EXT:
            continue
        if ext in SAMPLE_EXT:
            return p
        try:
            with p.open("rb") as f:
                head = f.read(8)
        except OSError:
            continue
        if any(head.startswith(m) for m in MAGICS):
            return p
    return None


def python_ext_unprimed(sample):
    """triage 报 python_ext 且台账无 const_scan/frame_map 证据 -> True。"""
    triage = OUT / (sample.name + ".triage.json")
    if not triage.is_file():
        return False
    try:
        hints = json.loads(triage.read_text(
            encoding="utf-8", errors="replace")).get("lang_hints") or {}
    except Exception:
        return False
    if not hints.get("python_ext"):
        return False
    ledger = OUT / (sample.name + ".ledger.jsonl")
    if ledger.is_file():
        try:
            if CYTHON_EVIDENCE.search(
                    ledger.read_text(encoding="utf-8", errors="replace")):
                return False
        except OSError:
            pass
    return True


def exploration_body(cmd):
    """是探索性运行则返回归一化脚本体（无法提取时返回 ''），否则 None。"""
    if ALLOW.search(cmd) or not PY.search(cmd):
        return None
    m = HEREDOC.search(cmd)
    if m:
        return norm(m.group(2))
    m = DASH_C.search(cmd)
    if m:
        return norm(m.group(2) if m.group(2) is not None else m.group(3) or "")
    if STDIN_PIPE.search(cmd) or re.search(r"\bpython[0-9.]*(?:\.exe)?\s+-\s*$",
                                           cmd.strip()):
        return ""
    return None


def norm(body):
    return re.sub(r"\s+", " ", body).strip()[:BODY_KEEP]


def load_runs():
    if not RUNS.is_file():
        return []
    now = time.time()
    runs = []
    try:
        for line in RUNS.read_text(
                encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if now - float(r.get("ts", 0)) <= RECENT_SEC:
                runs.append(r)
    except OSError:
        return []
    return runs


def save_runs(runs):
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        RUNS.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n"
                                for r in runs[-200:]), encoding="utf-8")
    except OSError:
        pass


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

    ledgers = active_ledgers()
    ltext = ledger_text(ledgers)

    # A. angr 禁项：未走完便宜档位不许上符号执行
    if ANGR.search(cmd) and not FRAME_EVIDENCE.search(ltext):
        return block(
            "[gate_explore · 升级阶梯禁项] 检测到 angr 调用，但活跃台账没有任何"
            "帧槽位/仿真类证据（frame_map/emulate/gdb/插桩）。\n"
            "ARX/模乘类密文上 angr 是最贵且最可能爆掉的一档"
            "（f862c151：16 轮 × 68 次 mod-65537 乘 + 192 次查表）。\n"
            "升级阶梯（禁止跳档）：\n"
            "  ① gdb 断轮体读帧槽位真值（先用 frame_map.py 定位槽位）\n"
            "  ② model_diff.py 分歧指纹分类（替代手写变体枚举）\n"
            "  ③ emulate-function / p-code 插桩取语句级真值\n"
            "  ④ 把已有 trace 当方程组解接线（数据够时差的是「解」不是「枚举」）\n"
            "  ⑤ angr 殿后——且须先论证对本密文可行\n"
            "走完前四档并把证据落账（observe --source runtime-oracle）后本门放行。"
        )

    # B. Cython 前置：python_ext 样本建模前必须有 §12 元数据 + 帧槽位
    cwd = Path(payload.get("cwd") or ".").resolve() \
        if payload.get("cwd") else Path.cwd()
    sample = find_sample(cmd, cwd)
    if sample is not None and python_ext_unprimed(sample):
        return block(
            f"[gate_explore · Cython 前置] {sample.name} 的 triage 判定 "
            f"lang_hints.python_ext=true，但台账没有 const_scan / frame_map 证据。\n"
            "Cython/CPython 扩展建模轮函数之前必须先取两类真值"
            "（f862c151：跳过本步 → 手写 95 项 datmap + 128 变体盲搜）：\n"
            "  ① python ~/.dsh/skills/ghidra-core/scripts/const_scan.py "
            "--binary <样本>（§12 元数据：PyList/PyTuple 常量重建）\n"
            "  ② python ~/.dsh/skills/ghidra-core/scripts/frame_map.py "
            "<函数地址>（栈帧槽位归属——伪码 local_XXXX 命名不可信）\n"
            "两者落账（observe）后本门放行。"
        )

    # C/D 只针对探索性运行
    body = exploration_body(cmd)
    if body is None:
        return 0
    runs = load_runs()
    now = time.time()
    window = [r for r in runs if now - float(r.get("ts", 0)) <= EXPLORE_WINDOW]
    lentries = ledger_entries(ledgers)
    nstuck = ledger_stucks(ltext)

    # C. 变体枚举：脚本体与窗内 >=2 次历史相似且台账无新条目
    if body:
        sims = [r for r in window if r.get("body")
                and sim(body, r["body"]) >= SIM_RATIO]
        if len(sims) >= SIM_MIN:
            earliest_n = min(int(r.get("ledger_n", 0)) for r in sims)
            if lentries <= earliest_n:
                return block(
                    f"[gate_explore · 铁律6 变体枚举熔断] 本次脚本体与近 30 分钟内 "
                    f"{len(sims)} 次历史探索高度相似（ratio>{SIM_RATIO}），"
                    "且台账自最早一次相似运行起没有新条目——"
                    "这是「同一思路换措辞重试」的机械指纹"
                    "（f862c151：128 个手写结构变体盲搜，model_diff 0 次）。\n"
                    "禁止写下一个变体。现在执行：\n"
                    "  ① python ~/.dsh/skills/ghidra-core/scripts/model_diff.py "
                    "<模型命令> --input-gen hex:N 与真实 oracle 对拍，"
                    "拿分歧指纹分类（宽度级 > 字节级 > 无规律）\n"
                    "  ② 分歧指纹落 ledger.py observe --source runtime-oracle\n"
                    "局部 8/8 全对、链式一断全崩的静默接线 bug，枚举变体找不回来，"
                    "只能靠测。"
                )

    # D. 探索计数熔断：窗内 >=25 次且零 stuck
    if len(window) >= EXPLORE_LIMIT and nstuck == 0:
        return block(
            f"[gate_explore · 铁律6 探索熔断] 近 30 分钟已有 {len(window)} 次 "
            "heredoc/-c/管道式探索运行（不落盘、不过 churn 闸门的载体盲区），"
            "且活跃台账 stuck 条目为 0。\n"
            "继续探索前必须落一条卡点：\n"
            "  python ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本> "
            "--at <卡点> --tried <已试路径> --escalate <升级去向>\n"
            "升级去向按性价比：gdb 帧槽位真值 > model_diff 分歧分类 > "
            "emulate-function 插桩 > trace 方程组求解。angr 殿后（见升级阶梯禁项）。"
        )

    # 放行并记账（body 截断存储，仅供相似度比对）
    runs.append({"ts": now, "body": body, "ledger_n": lentries})
    save_runs(runs)
    return 0


def sim(a, b):
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    sm = difflib.SequenceMatcher(None, a, b)
    if sm.quick_ratio() < SIM_RATIO:
        return 0.0
    return sm.ratio()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_explore hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
