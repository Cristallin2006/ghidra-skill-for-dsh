#!/usr/bin/env python
"""gate_stuck.py - PreToolUse 卡点自述熔断:自述卡住却从不 stuck 落账 -> 强制落账。

修的是 b781ff3c(25 强网杯 adventure,38 min 零 exploit)的归因:agent 全场
至少 4 次在思考/回复里自述卡住("I'm going around in circles"、"Not feasible…
the author must…"),ledger.py 调用 6/215,stuck 0 次——10:11 已识别 shop 整数
溢出、10:40 算出龙 800 万 HP 正常打不死,两个半边事实因从不盘点账本无接线,
会话被外部硬切。纪律卡的「卡住先 stuck」是纯文字约束,自觉率 0/4;本闸把它
变成机械门。

判定(PreToolUse,matcher 覆盖 bash/write/edit/read 系):
  1. 本会话日志(经 stop_check 的 zstd 流式解码)最近 WINDOW_SEC 内出现
     卡点自述:
       强措辞 1 次即命中(going in circles / i'm stuck / 死循环 / 原地打转…);
       弱措辞(not feasible / doesn't work / 行不通 / 卡住…)需 >=2 条不同消息
       ——单发弱措辞多为健康换路,不拦。
  2. 存在 12h 内活跃台账(否则不是逆向任务,普通开发会话的 "doesn't work"
     会满天飞——本闸只在逆向语境下执勤)。
  3. 活跃台账中最新 stuck 时间 <= 最新自述时间(自述后已落账则放行)。
  4. 冷却标记:每个自述episode 只 deny 一次(.stuck-gate.json 按 session_id
     记录 last_deny;deny 之后出现新自述才再拦)。

出口(全部低成本,速度坎不是墙):
  · python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本>
    --at <卡点> --tried "..." --escalate "..."   ← 预期动作
  · 命令里含 ledger.py 一律放行(落账/盘点中)。
  · 自述是误检(在描述题目现象) -> 跑任意一条 ledger.py observe 说明后即
    满足「最新台账动作晚于自述」之外的冷却条件——或者干脆 stuck 一条,
    语义=「我知道自己卡没卡」。

失效方向(有意如此):会话日志读不到/解不开 -> 放行;大日志(>60MB 压缩)
跳过本闸保延迟;本闸不防蓄意绕过(自述换措辞即可隐身),目标是接住
「诚实自述但不落账」的惯性。
"""
import json
import os
import re
import sys
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import stop_check  # 复用 session_log_text / zstd 流式解码
except Exception:
    stop_check = None

OUT = Path(os.environ.get("DSH_HOME") or str(Path.home() / ".dsh")) \
    / "ghidra-workspace" / "out"
MARKER = OUT / ".stuck-gate.json"

WINDOW_SEC = 45 * 60          # 自述回看窗口
LEDGER_ACTIVE_SEC = 12 * 3600
MAX_COMPRESSED_BYTES = 60 * 1024 * 1024  # 超过则跳过本闸(保 hook 延迟)
TAIL_SCAN_CHARS = 4 * 1024 * 1024        # 只扫解码尾部(自述必是近期)

# 强措辞:一次即命中(明确的原地打转自述)
STRONG = (
    "going in circles", "going around in circles", "running in circles",
    "going around in circle", "going nowhere", "i'm stuck", "i am stuck",
    "im stuck", "totally stuck", "completely stuck", "really stuck",
    "死循环", "兜圈", "原地打转", "走投无路", "彻底卡", "完全卡",
    "毫无进展",
)
# 弱措辞:窗口内 >=2 条不同消息命中才拦(单发多为健康换路)
WEAK = (
    "not feasible", "infeasible", "isn't feasible", "not viable",
    "doesn't work", "does not work", "didn't work", "isn't working",
    "dead end", "dead-end", "no idea", "at a loss", "back to square one",
    "must be another way", "there must be another", "hitting a wall",
    "行不通", "不可行", "没有思路", "没思路", "卡住", "卡在",
    "没有进展", "没进展", "此路不通", "换个思路", "毫无头绪", "无从下手",
)


def block(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 2


def self_report_times(text: str, now: float):
    """扫描会话日志尾部,返回 (强措辞时间列表, 弱措辞命中的消息时间集合)。"""
    strong, weak_msgs = [], set()
    for line in text.splitlines():
        if '"assistant/message"' not in line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("type") != "assistant/message":
            continue
        t = ev.get("time")
        if not isinstance(t, (int, float)):
            continue
        ts = t / 1000.0
        if now - ts > WINDOW_SEC:
            continue
        parts = ((ev.get("data") or {}).get("message") or {}).get("content") or []
        buf = []
        for p in parts:
            if isinstance(p, dict) and p.get("type") in ("text", "reasoning"):
                buf.append(str(p.get("text") or ""))
        body = " ".join(buf).lower()
        if not body:
            continue
        if any(s in body for s in STRONG):
            strong.append(ts)
        if any(s in body for s in WEAK):
            weak_msgs.add(ts)
    return strong, weak_msgs


def latest_stuck_ts(ledgers) -> float:
    """活跃台账里最新 stuck 的时间(本地 ts 字符串 -> epoch);无则 0。"""
    latest = 0.0
    for j in ledgers:
        try:
            lines = j.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or '"stuck"' not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("type") != "stuck":
                continue
            try:
                ts = time.mktime(time.strptime(str(e.get("ts") or ""),
                                               "%Y-%m-%d %H:%M:%S"))
                latest = max(latest, ts)
            except (ValueError, OverflowError):
                continue
    return latest


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


def load_marker():
    try:
        return json.loads(MARKER.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_marker(m):
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        # 只留最近 50 个会话的标记
        items = sorted(m.items(), key=lambda kv: kv[1])[-50:]
        MARKER.write_text(json.dumps(dict(items)), encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    session_id = str(payload.get("session_id") or "")
    if not session_id or stop_check is None:
        return 0

    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ""
    if isinstance(cmd, str) and "ledger.py" in cmd:
        return 0  # 正在落账/盘点,放行

    ledgers = active_ledgers()
    if not ledgers:
        return 0  # 非逆向任务语境,不执勤

    log = stop_check.session_log(session_id)
    if log is None:
        return 0
    try:
        if log.stat().st_size > MAX_COMPRESSED_BYTES:
            return 0
    except OSError:
        return 0
    text = stop_check.session_log_text(session_id)
    if not text:
        return 0

    now = time.time()
    strong, weak_msgs = self_report_times(text[-TAIL_SCAN_CHARS:], now)
    if not strong and len(weak_msgs) < 2:
        return 0
    latest_sr = max(strong) if strong else max(weak_msgs)

    if latest_stuck_ts(ledgers) > latest_sr:
        return 0  # 自述之后已 stuck 落账,episode 已收口

    marker = load_marker()
    if float(marker.get(session_id) or 0) > latest_sr:
        return 0  # 本 episode 已拦过一次,冷却中
    marker[session_id] = now
    save_marker(marker)

    which = "强措辞自述" if strong else f"弱措辞自述 x{len(weak_msgs)}"
    return block(
        f"[gate_stuck · 卡点熔断] 本会话最近 45min 内检测到卡点{which}"
        "(如 \"going in circles\"/\"not feasible\"/\"卡住\"/\"行不通\"),"
        "但活跃台账没有任何 stuck 落账。\n"
        "判例 b781ff3c(25 强网杯 adventure,38min 零 exploit):4 次自述卡住、"
        "stuck 0 次——10:11 已识别 shop 整数溢出、10:40 算出龙 800 万 HP 正常"
        "打不死,两个半边事实因从不盘点账本而始终没接线。\n"
        "立即执行(二选一):\n"
        "  ① python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本> "
        "--at <卡点> --tried \"已试路径\" --escalate \"能力范围内的下一步\"\n"
        "  ② 先 python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py query <样本>"
        " 全量盘点已有 conclude/observe——专找「已识别但从未利用」的发现"
        "(洞、异常值、天量数字),把它接到当前断点上;接不上再 ①。\n"
        "若刚才是误检(在描述题目现象而非自己卡住):跑一条 ledger.py observe "
        "说明现状即不再拦;本闸每个卡点 episode 只拦一次。"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_stuck hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
