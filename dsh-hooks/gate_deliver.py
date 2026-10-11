#!/usr/bin/env python
"""gate_deliver.py - PreToolUse 交付物否定判词闸:交付文本含能力类否定判词
(不可求逆/不可建模/unsolvable/not invertible…),但台账无 conclude --kind
negative --proof -> 拦截,强制撤回判词或坐实判词。

修的是 c3964a8b / f7b0ecc2 双判例(同一题两次盲测同一死法):agent 读了
runtime-dependent-verifier.md 的「仿射证伪≠不可逆」「Feistel 轮函数单向也
整体可逆」,8 分钟后仍以「链上有 SHA-256 -> 非线性 -> 不可求逆 -> infeasible」
收尾交卷;WP 正解是 32 轮 Feistel 反序跑轮。纪律卡铁律 4 的
conclude --kind negative --proof 硬门只在 agent 自愿调用时生效——它直接把
判词写进 REPORT.md / answers.txt / present 交付,从不走 conclude。
文本纪律两轮实盘自觉率 0/2,故把否定判词从「自愿落账」改成「交付物机械闸」。

判定(PreToolUse,matcher 覆盖 present/write/edit/bash 系):
  1. 存在 12h 内活跃台账(否则不是逆向语境,普通开发会话写 "unsolvable"
     不该被拦——本闸只在逆向任务下执勤,与 gate_stuck 同一守卫)。
  2. 交付内容扫描:
       - write/edit: 文件像文档(.md/.txt/.rst 或文件名含 report/answer/
         solution/writeup/summary/readme/报告/答案/结论)才扫 content/
         new_string;
       - present: 读 args 里列出的每个文件(上限 512KB/个,10 个)扫内容;
       - bash/pwsh: 仅当命令含重定向/heredoc 写入交付向文件名
         (report|answer|solution|writeup|summary|报告|答案|结论)时扫命令全文。
  3. 命中【能力类否定判词】(见 VERDICT_RE)且活跃台账没有任何
     type=conclude + kind=negative 的条目 -> 拦。
     判词表只收「能力断言」(无法求逆/不可建模/cannot be inverted…),
     不收「状态描述」(尚未解出/未收敛/not yet solved)——诚实汇报进度
     不交卷判词是合法收尾。
  4. 无冷却:判词不撤、proof 不落,每次交付都拦(这是终审,不是噪声)。

出口(二选一):
  ① 撤回判词:改成状态描述(「尚未解出/未收敛」+ 下一步路径);
  ② 坐实判词:先完成 runtime-dependent-verifier.md §② 三个结构侦察动作
     (链上 call 目标清单 / 短回跳簇轮计数 / input-vs-runtime 数据流二分)
     并落 observe,再 conclude --kind negative --proof
     "static-constraint: …" 或 "dynamic-forced: …"(ledger.py 强制前缀,
     缺 proof exit 2)。「真单向只有一类:输出被压缩/截断」——proof 必须
     指认截断点,指认不出判词不予成立。

失效方向(有意如此):文件读不到/太大 -> 放行;agent 把判词只写进最终
回复文本、交付物里只字不提 -> 本闸够不着(PreToolUse 拦不了纯文本),
靠 present 前的 write 闸与 stop_check 兜底;本闸不防蓄意换措辞。
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from gate_stuck import active_ledgers, block
except Exception:
    active_ledgers = None

    def block(msg: str) -> int:
        print(msg, file=sys.stderr)
        return 2

LEDGER_ACTIVE_SEC = 12 * 3600
MAX_FILE_BYTES = 512 * 1024
MAX_PRESENT_FILES = 10

# 能力类否定判词(只收能力断言,不收状态描述;大小写不敏感)
VERDICT_RE = re.compile(
    r"不可求逆|无法求逆|无法反解|不可逆推|不可求解|无法求解|"
    r"不可恢复|无法恢复|不可建模|无法建模|不可还原|无法还原|"
    r"infeasible to (?:invert|recover|reverse|solve)|"
    r"not feasible to (?:invert|recover|reverse|solve)|"
    r"cannot be (?:inverted|recovered|reversed|solved|decrypted)|"
    r"can't be (?:inverted|recovered|reversed|solved)|"
    r"not (?:invertible|recoverable|reversible)|non-invertible|"
    r"impossible to (?:invert|recover|reverse|solve)|"
    r"unsolvable|no (?:input|solution|key) exists",
    re.IGNORECASE,
)

# 文档向文件名(write/edit 的扫描门槛)
_DOC_NAME_RE = re.compile(
    r"(?i)(report|answer|solution|writeup|summary|readme|报告|答案|结论)"
    r"|\.(?:md|txt|rst)$"
)
# bash 交付向写入:重定向/heredoc 到交付向文件名
_BASH_WRITE_RE = re.compile(
    r"(?:>>?|tee)\s*[\"']?([^\s\"'>|;&]+)", re.IGNORECASE)
_BASH_DELIVER_RE = re.compile(
    r"(?i)(report|answer|solution|writeup|summary|报告|答案|结论)")


def has_negative_conclude(ledgers) -> bool:
    """活跃台账里存在 type=conclude + kind=negative 条目(ledger.py 已强制
    --proof 前缀,存在即视为判词已走硬门)。"""
    for j in ledgers:
        try:
            lines = j.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or '"conclude"' not in line or '"negative"' not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("type") == "conclude" and e.get("kind") == "negative":
                return True
    return False


def collect_text(tool_name: str, ti: dict) -> str:
    """按工具类型抽取待扫文本;不像交付物的返回空串(不扫)。"""
    name = tool_name.lower()
    if name in ("write", "edit", "multiedit"):
        path = str(ti.get("file_path") or ti.get("path") or ti.get("filePath") or "")
        if not _DOC_NAME_RE.search(path):
            return ""
        parts = [str(ti.get("content") or ""), str(ti.get("new_string") or "")]
        for ed in ti.get("edits") or []:
            if isinstance(ed, dict):
                parts.append(str(ed.get("new_string") or ""))
        return "\n".join(parts)[:MAX_FILE_BYTES]
    if name == "present":
        buf = []
        files = ti.get("files") or ti.get("deliverables") or []
        for f in files[:MAX_PRESENT_FILES]:
            if not isinstance(f, dict):
                continue
            p = f.get("path") or f.get("file") or ""
            if not p:
                continue
            try:
                fp = Path(str(p))
                if fp.stat().st_size > MAX_FILE_BYTES:
                    continue
                buf.append(fp.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
        return "\n".join(buf)
    if name in ("bash", "pwsh", "shell"):
        cmd = str(ti.get("command") or "")
        for m in _BASH_WRITE_RE.finditer(cmd):
            if _BASH_DELIVER_RE.search(os.path.basename(m.group(1))):
                return cmd[:MAX_FILE_BYTES]
        return ""
    return ""


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    if active_ledgers is None:
        return 0
    ledgers = active_ledgers()
    if not ledgers:
        return 0  # 非逆向语境,不执勤

    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
    ti = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(ti, dict):
        return 0

    text = collect_text(tool_name, ti)
    if not text:
        return 0
    m = VERDICT_RE.search(text)
    if not m:
        return 0
    if has_negative_conclude(ledgers):
        return 0  # 判词已走 negative conclude 硬门,放行

    return block(
        f"[gate_deliver · 否定判词交付闸] 交付内容含能力类否定判词 "
        f"「{m.group(0)}」(不可求逆/不可建模/unsolvable/not invertible 类),"
        "但活跃台账没有任何 conclude --kind negative --proof 条目。\n"
        "判例 c3964a8b/f7b0ecc2(同一题两次盲测同一死法):agent 读了"
        "「仿射证伪≠不可逆」「Feistel 轮函数单向也整体可逆」的文档,仍以"
        "「链上有 SHA-256 → 非线性 → 不可求逆」收尾交卷——WP 正解是 32 轮 "
        "Feistel 反序跑轮,轮函数单向不影响整体可逆。文本纪律两轮自觉率 "
        "0/2,故此闸把否定判词从自愿落账改成交付物机械门。\n"
        "立即执行(二选一):\n"
        "  ① 撤回判词:交付文本改为状态描述(「尚未解出/未收敛」+ 下一步"
        "路径),删除能力类否定断言——诚实汇报进度不需要 proof;\n"
        "  ② 坐实判词:先完成 ghidra-static "
        "references/runtime-dependent-verifier.md §② 的三个结构侦察动作"
        "(1. 链上 call 目标清单识别原语;2. 短回跳簇轮结构计数;"
        "3. 数据流二分:哪些 buffer 依赖 input、哪些只依赖 runtime/常量)"
        "并逐条落 ledger.py observe,然后:\n"
        "     python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py conclude "
        "<样本> --kind negative --proof \"static-constraint: <每条路径不可满足"
        "的约束>\"(或 \"dynamic-forced: <强制到线后仍不执行的实测>\")\n"
        "     注意:「真单向只有一类——输出被压缩/截断(digest 直接当答案/"
        "mod 小空间/丢位)」。proof 必须指认截断点;指认不出,判词不予成立,"
        "回到 ①。\n"
        "台账写操作命令本身不受本闸限制。"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_deliver hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
