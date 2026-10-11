#!/usr/bin/env python
"""gate_stuck.py - PreToolUse 卡点自述熔断:自述卡住却从不 stuck 落账 -> 强制落账。

修的是 b781ff3c(38 min 零产出)的归因:agent 全场
至少 4 次在思考/回复里自述卡住("I'm going around in circles"、"Not feasible…
the author must…"),ledger.py 调用 6/215,stuck 0 次——两个半边事实早已分别
识别,因从不盘点账本无接线,
会话被外部硬切。纪律卡的「卡住先 stuck」是纯文字约束,自觉率 0/4;本闸把它
变成机械门。

判定(PreToolUse,matcher 覆盖 bash/write/edit/read/ask_user_question 系):
  1. 本会话日志(经 stop_check 的 zstd 流式解码)最近 WINDOW_SEC 内出现
     卡点自述:
       强措辞 1 次即命中(going in circles / i'm stuck / 死循环 / 原地打转…);
       弱措辞(not feasible / doesn't work / 行不通 / 卡住…)需 >=2 条不同消息
       ——单发弱措辞多为健康换路,不拦。
  2. 存在 12h 内活跃台账(否则不是逆向任务,普通开发会话的 "doesn't work"
     会满天飞——本闸只在逆向语境下执勤)。
  3. 活跃台账中最新【写操作落账】时间 <= 最新自述时间才拦:
     自述之后已有 observe/conclude/stuck 等任意写条目 = 卡点已在台账
     收口(或属误检已说明),放行。只读子命令(query/render/status/validate)
     不算落账——读不产生证据。
  4. 冷却标记:每个自述 episode 只 deny 一次(.stuck-gate.json 按 session_id
     记录 last_deny);deny 之后出现新自述才再拦。
  5. 复拦阻尼:首次拦截后 REPEAT_WINDOW 内,仅弱措辞复诉不再拦
     (正常调试迭代噪声);窗口内出现新的【强措辞】自述才复拦。

出口(全部低成本,速度坎不是墙):
  · python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本>
    --at <卡点> --tried "..." --escalate "..."   ← 预期动作
  · 命令级豁免(仅以下两类,堵 query 前缀通行证):
      a. 命令含台账写操作子命令(observe/conclude/stuck/anomaly/resolve/
         hypothesis/plan/brute)——写条目本身即清 episode,一律放行;
      b. 纯台账命令(只读 query/render/status/validate 单独成令,或与
         cd/echo/赋值/管道查看工具组合)——盘点不拦。
    变量间接引用(VAR=...ledger.py; python3 "$VAR" ...)会先内联归一化再判,
    贴 `query >/dev/null; <真实工作>` 前缀不再放行(f7b0ecc2 判例:
    agent 自述 "prepend a ledger query to every command",20 分钟内全部
    命令带 query 前缀,闸门被架空)。
  · 自述是误检(在描述题目现象) -> 跑任意一条 ledger.py observe 说明现状,
    写条目晚于自述即清 episode(本闸 v2 起 observe 真实生效)。

失效方向(有意如此):会话日志读不到/解不开 -> 放行;大日志(>60MB 压缩)
跳过本闸保延迟;本闸不防蓄意绕过(自述换措辞即可隐身),目标是接住
「诚实自述但不落账」的惯性。

c50c8812 判例(提问绕道):被本闸拦 2 次后,agent 改用 ask_user_question
把回合终结在选择题上(还列了违反用户明示指令的选项),空选驳回后空转
收场——故 matcher 扩展覆盖 ask_user_question,提问同样要先落账;
拦截文案附带铁律 15(空选 = 按推荐选项立即自主继续)。

f7b0ecc2 判例(应试绕过 + 误报风暴):agent 发现「命令含 ledger.py 即放行」
后把 `query >/dev/null` 当前缀贴满全场;且旧版仅 stuck 条目清 episode,
文档承诺的 observe 清 episode 并未生效,10.5-10.9m 被连拦 6 次——
v2 一并修复:只读子命令不豁免真实工作,写操作(含 observe)真实清 episode,
弱措辞复拦加 15min 阻尼。
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
REPEAT_WINDOW = 15 * 60       # 首次拦截后,弱措辞复拦阻尼窗口

# 台账写操作子命令(命令级):出现其一 = 正在落账,命令放行
WRITE_SUB = ("observe", "conclude", "anomaly", "resolve", "hypothesis",
             "plan", "brute", "stuck")
# 只读子命令:单独成令放行(盘点不拦),作真实工作的前缀不放行
READONLY_SUB = ("query", "status", "render", "validate")
# 台账条目类型(文件级):写条目晚于自述 = episode 已收口
WRITE_TYPES = frozenset(WRITE_SUB) | {"anomaly-resolve", "hypothesis-resolve"}

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

_LEDGER_CALL_RE = re.compile(r'\S*ledger\.py["\']?\s+(\w+)')
_VAR_ASSIGN_RE = re.compile(r'\b([A-Za-z_]\w*)=("|\')([^"\';|&]*)\2'
                            r'|\b([A-Za-z_]\w*)=([^\s;|&"\']+)')
_TRIVIAL_SEG_RE = re.compile(
    r'^(cd\s+\S+|echo\b.*|true|false|:|exit(\s+\d+)?|export\s+\w+=.*|'
    r'[A-Za-z_]\w*=\S*|pwd|set\s+.*|ulimit\s+.*|umask\s+.*|'
    r'(head|tail|wc|cat|grep|jq|less|more|sort|uniq|column)\b.*)$')


def block(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 2


def _inline_vars(cmd: str) -> str:
    """把 VAR=<含 ledger.py 的值> 赋值内联回 $VAR 引用,统一后续结构判断。"""
    out = cmd
    for m in _VAR_ASSIGN_RE.finditer(cmd):
        name = m.group(1) or m.group(4)
        val = m.group(3) if m.group(1) else m.group(5)
        if not name or not val or "ledger.py" not in val:
            continue
        for ref in (f'"${name}"', f'"${{{name}}}"', f'${{{name}}}', f'${name}'):
            out = out.replace(ref, val)
    return out


_ASSIGN_ONLY_RE = re.compile(r'^[A-Za-z_]\w*=[^\n]*$')


def _seg_kind(seg: str) -> str:
    """'write'=含台账写子命令; 'ledger'=纯台账只读; 'trivial'; 其余 'work'。"""
    s = seg.strip()
    if not s:
        return "trivial"
    if _ASSIGN_ONLY_RE.match(s):
        return "trivial"  # 含 L="...ledger.py" 路径赋值(配合 _inline_vars)
    m = _LEDGER_CALL_RE.search(s)
    if m:
        sub = m.group(1)
        if sub in WRITE_SUB:
            return "write"
        return "ledger"  # query/render/status/validate/未知子命令按只读计
    if _TRIVIAL_SEG_RE.match(s):
        return "trivial"
    return "work"


def command_exempt(cmd: str) -> bool:
    """命令级豁免:含台账写操作,或整条命令只有台账调用/琐碎段。"""
    if not isinstance(cmd, str) or not cmd:
        return False
    norm = _inline_vars(cmd)
    if "ledger.py" not in norm:
        return False
    kinds = [_seg_kind(s) for s in re.split(r'&&|\|\||;|\|', norm) if s.strip()]
    if not kinds:
        return False
    if "write" in kinds:
        return True
    return all(k in ("ledger", "trivial") for k in kinds)


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


def latest_write_ts(ledgers) -> float:
    """活跃台账里最新【写条目】的时间(本地 ts 字符串 -> epoch);无则 0。

    只读子命令不产生条目;observe/conclude/stuck 等任意写条目晚于自述
    即视为 episode 已收口(含「误检说明」路径)。
    """
    latest = 0.0
    for j in ledgers:
        try:
            lines = j.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("type") not in WRITE_TYPES:
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


def should_block(now: float, strong, weak_msgs, latest_write: float,
                 last_deny: float) -> bool:
    """纯判定:给定自述/台账/冷却状态,是否拦截。

    - 无自述信号 -> 不拦(调用方保证 strong/weak 已达触发阈值)
    - 自述之后已有写条目 -> episode 已收口,不拦
    - 本 episode 已拦过(last_deny 晚于最新自述)-> 冷却,不拦
    - 阻尼:上次拦截在 REPEAT_WINDOW 内,且此后无新强措辞 -> 不拦
    """
    if not strong and len(weak_msgs) < 2:
        return False
    latest_sr = max(strong) if strong else max(weak_msgs)
    if latest_write > latest_sr:
        return False
    if last_deny > latest_sr:
        return False
    if last_deny and now - last_deny < REPEAT_WINDOW \
            and not any(t > last_deny for t in strong):
        return False
    return True


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    payload = json.loads(raw)
    session_id = str(payload.get("session_id") or "")
    if not session_id or stop_check is None:
        return 0

    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
    is_ask = "ask" in tool_name.lower()

    ti = payload.get("tool_input") or {}
    cmd = ti.get("command") or ""
    if command_exempt(cmd):
        return 0  # 正在落账/纯盘点,放行

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
    marker = load_marker()
    last_deny = float(marker.get(session_id) or 0)

    if not should_block(now, strong, weak_msgs, latest_write_ts(ledgers),
                        last_deny):
        return 0

    marker[session_id] = now
    save_marker(marker)

    which = "强措辞自述" if strong else f"弱措辞自述 x{len(weak_msgs)}"
    ask_note = (
        "提问不能绕过落账:卡点自述未落账时禁止 ask_user_question;"
        "且提问被空选/驳回 = 按推荐选项立即自主继续,禁止以提问结束回合"
        "(铁律 15,判例 c50c8812:提问绕道 + 列违规选项 + 空选后死寂收场)。\n"
        if is_ask else ""
    )
    return block(
        ask_note
        + f"[gate_stuck · 卡点熔断] 本会话最近 45min 内检测到卡点{which}"
        "(如 \"going in circles\"/\"not feasible\"/\"卡住\"/\"行不通\"),"
        "但活跃台账没有任何晚于自述的写落账。\n"
        "判例 b781ff3c(38min 零产出):4 次自述卡住、"
        "stuck 0 次——两个半边事实早已分别识别,"
        "因从不盘点账本而始终没接线。\n"
        "立即执行(二选一):\n"
        "  ① python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck <样本> "
        "--at <卡点> --tried \"已试路径\" --escalate \"能力范围内的下一步\"\n"
        "  ② 先 python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py query <样本>"
        " 全量盘点已有 conclude/observe——专找「已识别但从未利用」的发现"
        "(洞、异常值、天量数字),把它接到当前断点上;接不上再 ①。\n"
        "若刚才是误检(在描述题目现象而非自己卡住):跑一条 ledger.py observe "
        "说明现状即清 episode(写条目晚于自述即放行);本闸每个卡点 episode "
        "只拦一次,15min 内仅弱措辞复诉不再拦。\n"
        "注意:把 query 当前缀贴在无关命令上不再豁免——只有台账写操作"
        "(stuck/observe/conclude/…)或纯台账命令才放行。"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"gate_stuck hook warning (放行): {e}", file=sys.stderr)
        sys.exit(0)
