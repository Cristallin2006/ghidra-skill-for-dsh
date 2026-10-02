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
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CARD = """\
[逆向纪律卡 · ghidra-skill-for-dsh，铁律全文见 ghidra-core/SKILL.md §1]
1. 逆向/流量/脱壳/漏洞任务：动手前先用 skill 工具加载对应 SKILL.md 全文；拿到样本先 re-triage 分诊，不凭扩展名猜；反编译/exec-code/仿真等深挖前必须先加载 ghidra-static 全文。
2. 一切区域级观察走 ledger.py observe、结论走 conclude --source --independent；分析任何区域前先 ledger.py query。
3. 同区回访必须带 --delta（答"这次和上次差在哪"）；肉眼 hex 同区最多 2 次，第 3 次机械拒绝。
4. 观测到不一致（重复键冲突/两次读数不同）必须 ledger.py anomaly --consequence 落账，禁止降级为"噪声/待枚举"；**「工具判词不适用/red herring」是否定性结论，必须 conclude 落账——后续观测推翻它时必须 anomaly + --overturn 标 killed，禁止带已崩前提继续（判例：4ccec36c 自证 mask 链数据相关后仍按「peel 不适用」走 z3 70 min 交卷）**。
5. 枚举类解码先出轴矩阵+候选预算；无 oracle（hash/一致性/校验位）不跑全交叉。
6. 卡住先 ledger.py stuck（有 open anomaly 须 --ack 或 resolve --waive）再升级工具层级，禁止换措辞重试同一路径；拟合/接线连错 2 次 → 强制升级 z3/SMT 或 emulate_blob/emulate-function，禁止写第 3 个手写拟合脚本；**手上有 ssa_reconstruct 直线程序时，任何求逆/SMT 之前 MUST 先跑 peel_inverse.py 查掩码依赖图**——检出可剥离递推段就逐层手工剥离，无干净结构才放行 SMT（跳过本闸直接 z3 实证丢 flag：be20d7dc，40 min 全 unknown）；**反向闸：peel 检出递推段后禁止直奔 z3/SMT**——下一步是 `peel_inverse.py <recon> --emit-solver peel_solve.py` 生成骨架、填 KNOWN/CALL_TABLES 逐层反解（检出后 0 次剥离直奔 z3 实证丢 flag：47246ce9，z3 模型连修 4 次未收敛，47 min 无 flag）；**z3/SMT 模型接线连错 2 次（unsat 无法解释/换输入不泛化/污点断链）→ 禁止修第 3 次模型，强制回到剥离路径或 ledger.py stuck 升级**；**骨架使用闸：emit-solver 骨架 0 次填写/运行 = 未过闸，主张「检出段不适用」须 conclude 带证据，递推段非目标转 cone_invert.py 锥形反推别跳 SMT（判例：4ccec36c 骨架 head 一眼弃用，z3 长征 91 min 交卷丢 flag）；stuck 是升级起点不是终点：--escalate 在能力范围内（机械步骤/已有部分验证）必须先执行再交卷——stop_check 机械拦截「末条 stuck 且 escalate 未执行」；**升级未收敛 ≠ 升级穷尽：escalate 执行后未收敛，禁止以「上下文将尽/预算不足」为由默默交卷——补规则重跑/换新路径/ask_user_question 三选一（判例：29bf99c0 谎称 context exhausted，实测 1M 窗口占用不足三成，19 min 交卷丢 flag），stop_check 机械拦截未收敛投降；cone_invert 报矛盾先看判词：矛盾锥无未知量 = 符号化不完整，跑 --diff-symbolize 补符号化重跑，不是路径死了**。
7. flag 的唯一合法验证 = 未修改的原程序/平台接受候选输入；自写探针的等价式不是程序判定。flag 结论必须 ledger.py conclude --kind flag --program-accept "投喂命令+成功响应"（缺证据 exit 2）。
8. timeout ≥300s 的长任务必须走 guarded_run.py（tee 落盘+无缓冲+杀前保全）；裸 `timeout N python3 x.py > log` 会因块缓冲+SIGTERM 丢光部分结果。
9. 中断/恢复后第一动作 = 清掉上轮最后一个 open hypothesis（ledger.py hypothesis --resolve-id --status confirmed|killed --evidence，客观不可检验走 waived --waive），再写报告。宣布「模型/反演已闭合」必须 conclude --kind model --anchor "L2 左逆锚定实测"：inv(fwd(已知答案))==已知答案；fwd(inv(B))==B 恒真，零信息量，不算验证。手上有已知答案（如 'A'*L 的 trace）就必须拿它当锚。
10. 工具输出的 advice/下一步处方（如 conflict_oracle 末尾的 decode_engine 命令）必须照抄执行，或 ledger.py --note 落账不执行的理由；无视处方转手搓脚本 = 违规（判例：decode_engine 零调用，>2e5 手搓候选全在缺轴空间，42 min 无 flag）。真复合不一定消除冲突——冲突排名不收敛时改走处方里的「铺轴 + oracle 过滤」；冲突字段是键的确定函数时，它是复合值的抵消项（纳入组合），不是"无信息"（禁止剔除）。"""


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = "SessionStart"
        if raw.strip():
            event = json.loads(raw).get("hook_event_name", event)
        json.dump({"hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": CARD,
        }}, sys.stdout, ensure_ascii=False)
    except Exception as e:
        print(f"session_start hook warning: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
