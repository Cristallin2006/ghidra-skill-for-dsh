#!/usr/bin/env python
"""session_start.py - dsh SessionStart/SubagentStart 纪律注入（hooks-claude-code 桥）。

会话/子代理创建时把压缩版逆向纪律卡注入上下文（additionalContext ->
agent.inject user message）。不依赖 agent 自觉读 SKILL.md——catalog 里只有
description，铁律全文在 ghidra-core §1，这张卡是常驻上下文的最低保障。

输入：stdin 的 hook payload JSON（含 hook_event_name）。
输出：stdout 一行 JSON {"hookSpecificOutput": {...}}。任何异常都静默 exit 0
（注入失败不许影响会话创建）。
"""
import json
import os
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
_SKILLS_DIR = os.path.join(os.path.expanduser("~"), ".dsh", "skills")


def _integrity_check():
    """语法体检所有 hook/skill 脚本（compile() 纯语法检查，不写 __pycache__）。

    判例：某轮 in-place 修复把 ledger.py 一行换行吃成空格，全部机械门依赖
    ledger 却无任何告警，解题 agent 在 session 里自己修 skill 脚本才发现。
    返回坏文件相对路径列表；异常按无告警处理（不许影响会话创建）。
    """
    bad = []
    try:
        targets = [
            os.path.join(_HOOKS_DIR, f)
            for f in os.listdir(_HOOKS_DIR)
            if f.endswith(".py")
        ]
        if os.path.isdir(_SKILLS_DIR):
            for skill in os.listdir(_SKILLS_DIR):
                sdir = os.path.join(_SKILLS_DIR, skill, "scripts")
                if not os.path.isdir(sdir):
                    continue
                for f in os.listdir(sdir):
                    if f.endswith(".py"):
                        targets.append(os.path.join(sdir, f))
        hj = os.path.join(_HOOKS_DIR, "hooks.json")
        if os.path.isfile(hj):
            try:
                json.load(open(hj, encoding="utf-8"))
            except Exception:
                bad.append("hooks/hooks.json(JSON)")
        for p in targets:
            try:
                with open(p, encoding="utf-8") as fh:
                    compile(fh.read(), p, "exec")
            except Exception:
                bad.append(os.path.relpath(p, os.path.expanduser("~")))
    except Exception:
        return []
    return bad


CARD = """\
[逆向纪律卡 · ghidra-skill-for-dsh｜格式：触发器 → 动作（机械门注明闸名）。判例与细则全文在 ghidra-core §1，需要时按指针加载]
1. 开局：逆向任务先加载对应 SKILL.md 全文；样本先 re-triage 分诊，不凭扩展名猜；decompile/exec-code/仿真等深挖前先加载 ghidra-static 全文，gdb/写 .gdb 脚本等动态操作前先加载 re-dynamic 全文（gate_sample 加载门机械拦——程序 ID/包装脚本一样拦）；手写 .gdb 脚本第二个起禁抄样板，改用 re-dynamic 的 gdbkit.py（gate_gdbscript 机械拦）。
2. 落账：观察 → ledger.py observe；结论 → conclude --source --independent；分析任何区域前先 ledger.py query。语法速查见 ghidra-core §2——禁止读 ledger.py 源码或逐命令 --help 轮询。
3. 回访：同区二次观察必须 --delta（"这次差在哪"）；肉眼 hex 同区最多 2 次，第 3 次机械拒绝。
4. 否定判词：不一致 → anomaly --consequence；「不可达/不适用/red herring/工具不可用」及能力类判词「不可求逆/不可建模/无法求解/unsolvable/not invertible」→ conclude --kind negative --proof（缺 proof exit 2；交付物 write/present 含此类判词而无 negative 落账 → gate_deliver 机械拦）。状态描述「尚未解出/未收敛」+ 下一步路径是合法收尾，不算否定判词。观测缺失 ≠ 不存在；仿射证伪 ≠ 不可逆（Feistel 轮函数单向也整体可逆，细则见 ghidra-static runtime-dependent-verifier.md §②）。信号处理器/裸 UD2 样本的 non-returning/死代码判定不可信 → noreturn_fix.py 修视图（--fix/--flow）。
5. 枚举与约束：枚举类先出轴矩阵+候选预算，无 oracle 不跑全交叉。约束系统第一工具 = z3，但 z3 之前先过剥离闸（gate_smt 机械拦）：有直线程序先 peel_inverse.py（检出段 → --emit-solver 骨架；无结构 → cone_invert.py），peel 不适用须 conclude 落账。≥2^28 自建枚举先 ledger.py brute 登记（gate_bruteforce 拦；hashcat/john 豁免）。
6. 卡点：卡住 → ledger.py stuck（有 open anomaly 须 --ack）。stuck 的 escalate 必须换路——与上次雷同或技术类落在已试清单内 → 机械拒收（正当同类重试加 --note）。自述「卡住/行不通」未落账 → gate_stuck 拦下一次工具调用（含 ask_user_question）。escalate 在能力范围内必须先执行再交卷；未收敛禁止以「上下文将尽」默默交卷（stop_check 拦）。提问仅限缺凭据/授权/裁决，空选 = 按推荐选项立即自主继续。
7. flag 验证：唯一合法证据 = 未修改原程序/平台接受候选输入；conclude --kind flag --program-accept（缺证据 exit 2，禁止 --source self-script）。
8. 长任务：timeout ≥300s 必须走 guarded_run.py（gate_longrun 拦裸 timeout——块缓冲+SIGTERM 会丢光部分结果）。
9. 中断恢复：第一动作 = 清上轮最后一个 open hypothesis（--status confirmed|killed --evidence；不可检验走 waived）。宣布「模型闭合」须 conclude --kind model --anchor L2 左逆锚定实测（inv(fwd(已知))==已知；fwd(inv(B))==B 恒真，零信息量）。
10. 处方纪律：工具输出末尾的 advice/下一步处方必须照抄执行，或 ledger.py --note 落账不执行的理由。冲突字段是键的确定函数时是复合抵消项（纳入组合），不是无信息，禁止剔除。"""


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = "SessionStart"
        if raw.strip():
            event = json.loads(raw).get("hook_event_name", event)
        card = CARD
        bad = _integrity_check()
        if bad:
            warn = ("\n[完整性告警 · session_start 体检] 以下 hook/skill 脚本语法损坏，"
                    "依赖它们的机械门可能已静默失效——先 py_compile 定位并修复再继续做题： "
                    + ", ".join(bad))
            card += warn
            print("session_start integrity: BROKEN " + ", ".join(bad), file=sys.stderr)
        json.dump({"hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": card,
        }}, sys.stdout, ensure_ascii=False)
    except Exception as e:
        print(f"session_start hook warning: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
