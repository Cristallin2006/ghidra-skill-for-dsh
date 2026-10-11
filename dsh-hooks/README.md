# dsh-hooks —— skill 准则强制层（hooks 机械门）

解决「AI 自由逆向时不遵守 skill 准则」：catalog 只注入 description，SKILL.md 正文和
ghidra-core §1 铁律不在上下文里，文字纪律无强制力（chal session 实证：纪律卡注入了、
skill 加载了、规则能逐条背出，仍违反 9 条）。本目录用 dsh 内置的
`@deepseek-ai/dsh-hooks-claude-code` 桥（Claude Code 格式 hooks）把关键纪律变成机械门。

## 组成

| 文件 | 事件 | 作用 |
|---|---|---|
| `session_start.py` | SessionStart / SubagentStart | 把压缩版纪律卡注入会话/子代理上下文（additionalContext），10 条，触发器→动作格式（2026-10-10 瘦身：3543→1583 字符，判例叙述剥离留指针）；附带 hook/skill 全脚本语法体检（compile() 不写 __pycache__，~0.15s），损坏文件以完整性告警注入卡片（判例：be6391dc 会话 ledger.py 换行被吃成空格，机械门静默失效） |
| `inject_rules.py` | PostToolUse（matcher bash 系） | **即时规则注入**：命中特征就把那一条规则在需要它的一秒注入。R1-R3 扫 tool_response（R1 triage `selfmod_signal.hit=true` → 铁律 10⑦+noreturn_fix/import-raw；R2 jumptable 未恢复 → jt_resolve；R3 `python_ext=true` → Cython 前置）；R4/R5 扫 tool_input.command（R4 写 *.gdb → gdbkit 阶梯指针；R5 `set $pc/$eflags` 跳分支 → force compare 反模式 + runtime-dependent-verifier.md 配方指针）；R6 扫 command+Write content 并以会话日志为条件（gdbkit `Force(` × assistant 自述的跨 run 不一致实锤 → 塌缩点前置指针；证据只认 assistant/message 行，skill 文档不算）。每会话每条只注入一次（`.inject-rules.json` dedupe，24h 后可重注入）；静默失败不阻断 |
| `gate_smt.py` | PreToolUse（bash + Write 两组） | **SMT 剥离前置闸**（be20d7dc：跳过 peel 直接 z3 丢 40min+flag；47246ce9：检出段后直奔 z3 丢 47min+flag）：z3 指纹命中且活跃台账无 peel/cone 痕迹 → exit 2。出口：跑 peel_inverse.py / conclude「peel 不适用」/ 台账已有痕迹天然放行。与 gate_bruteforce 对称：那扇拦绕过 SMT 去爆破，这扇拦绕过剥离去 SMT |
| `gate_sample.py` | PreToolUse（matcher `Pwsh\|pwsh\|Bash\|bash`） | ① 对**无台账样本**的分析类直读 + rpc 深挖子命令 exit 2 阻断；有台账放行；pcap 豁免；Cython 前置 ② **铁律1 加载门**（51bb491d：全程只加载 re-triage+ghidra-core 就深挖，references 配方零曝光，stage5 误判放弃）：逆向活跃会话（session log 含 ledger.py）里命中静态深挖动词（decompile/exec-code/disassemble/emulate/patch…）或动态深挖动词（gdb/layer_dump/frida，含写 .gdb）且本会话未加载 ghidra-static/re-dynamic → exit 2，加载一次即放行；程序 ID、grpc.sh 包装一样拦，纯开发会话（log 无 ledger.py）不执勤 |
| `gate_gdbscript.py` | PreToolUse（bash 组 + Write 组） | **gdb 手写脚本计数门**（51bb491d：手写 8 个 .gdb 脚本逐个踩坑，gdbkit 零使用）：对 *.gdb 的重定向/tee/Write 写入计数（`.gdb-writes.json` 按 session_id，24h TTL），第 1 个放行（快速探针），第 2 个起 exit 2 指 gdbkit.py；逃生门：内容含 `gdbkit-gap: <缺什么>` 注释放行留痕 |
| `gate_churn.py` | PreToolUse（matcher `Write\|write`） | 拟合熔断：目录近 24h ≥8 个 .py 且活跃台账零 stuck → 阻断，逼 stuck 落账或升级 z3/emulate；**可重触发**：一次台账接触（任一条目）换 8 个脚本额度，用尽重新熔断（gate_explore B2 同核） |
| `gate_explore.py` | PreToolUse（同 bash matcher） | **heredoc 载体盲区**（f862c151：97 次 heredoc 探索不过 churn 闸门）：① angr 禁项（台账无帧槽位/仿真证据不许上符号执行）② Cython 前置（python_ext 样本无 const_scan/frame_map 证据不许建模）③ 变体枚举熔断（脚本体与窗内 ≥2 次历史相似且台账无增长 → 直指 model_diff.py）④ 探索计数熔断（30min ≥25 次且零 stuck）⑤ **cat/tee 落盘 churn**（`cat > x.py <<EOF` 载体，与 gate_churn 同判定核——92a0a107：19 次 cat<<EOF 落盘 16 个脚本） |
| `gate_longrun.py` | PreToolUse（同 bash matcher） | 长任务落盘门：`timeout ≥300s` 裸跑 python 脚本 → 阻断，指引 guarded_run.py |
| `gate_stuck.py` | PreToolUse（matcher bash 系 + Write/Edit/Read/AskUserQuestion 大小写全） | **卡点自述熔断**（b781ff3c：4 次自述「going in circles / Not feasible」、stuck 0 次，10:11 识别的 shop 溢出与 10:40 的 800 万血条 30 分钟未接线，38min 零 exploit）：扫本会话日志近 45min 的 assistant 消息——强措辞（going in circles/死循环/原地打转…）1 次即命中，弱措辞（not feasible/doesn't work/行不通/卡住…）≥2 条不同消息才命中；命中且有活跃台账、自述后无 stuck 落账 → exit 2 强制 `ledger.py stuck`（先 `query` 盘点接线）。每 episode 只拦一次（`.stuck-gate.json` 按 session_id 冷却）；无活跃台账不执勤（普通开发会话豁免）；命令含台账写操作或纯台账命令才放行（v2 起 `query` 前缀贴真实工作不豁免，变量内联后判定）。**下游配套（ledger.py stuck 换路校验，2026-10-10）**：补账式落账被机械拒收——tried/escalate 与上次雷同（>0.8）或 escalate 技术类落在已试清单内 → exit 2，正当同类重试加 `--note` |
| `gate_deliver.py` | PreToolUse（matcher bash 系 + Write/Edit/MultiEdit/Present 大小写全） | **否定判词交付闸**（c3964a8b/f7b0ecc2 双判例：同一题两次盲测同一死法——读了「仿射证伪≠不可逆」文档 8 分钟后仍以「链上有 SHA-256 → 非线性 → 不可求逆」交卷，文本纪律自觉率 0/2）：交付内容含能力类否定判词（不可求逆/不可建模/无法求解/cannot be inverted/unsolvable…）且活跃台账无 `conclude --kind negative --proof` → exit 2。出口：① 撤回判词改状态描述（「尚未解出/未收敛」+ 下一步路径，合法收尾）② 坐实判词：先落三个结构侦察动作（call 清单/回跳簇轮计数/数据流二分）再 negative conclude，proof 必须指认截断点。write/edit 只扫文档向文件（.md/.txt/.rst 或 report/answer/solution 等文件名）；present 读交付文件内容；bash 只扫重定向到交付向文件名的命令。无冷却，判词不撤每次交付都拦；无活跃台账不执勤 |
| `stop_check.py` | Stop | 收尾核对（v3 = v2 会话归属 + 三类检查）：本会话写过的台账 ① 有 observe 无 conclude/stuck ② flag 结论缺 program_accept ③ **存在 open hypothesis**（铁律 4 闭环门）→ deny 强制核对 |
| `hooks.json` | — | Claude Code 格式挂载清单（`${CLAUDE_PLUGIN_ROOT}` = 本目录） |

## ⚠ matcher 是大小写敏感的字面量匹配（2026-09-26 事故）

dsh-hook-protocol 对纯 `[A-Za-z0-9_|]` 模式走 `split("|").includes(query)` **精确匹配**，
不做大小写折叠。WSL/Linux 的 shell 工具名是小写 `bash`、Write 工具是小写 `write`——
只写 `"Bash"` 在其上**静默失效**（chal session 的 PreToolUse 门因此从未触发，
session 里零 `hook/invoked` 记录）。matcher 必须写全：`Pwsh|pwsh|Bash|bash`、
`Write|write`。Windows 侧工具名是 `Pwsh`（大写），旧配置只在 Windows 生效过。

## 安装（Windows）

`~/.dsh/profiles/web/cordis.patch.yml` 末尾的 `[]` 替换为：

```yaml
- insert:
    - id: hooks-claude-code
      name: '@deepseek-ai/dsh-hooks-claude-code'
      config:
        configPath: 'C:\Users\Lenovo\.dsh\hooks\hooks.json'
        pluginRoot: 'C:\Users\Lenovo\.dsh\hooks'
```

WSL 侧路径改为 `/root/.dsh/hooks/...`，hooks.json 里命令的 `python` 改 `python3`。
**改 hooks.json / 挂新 hook 后必须重启 `dsh web` 才生效**（插件树在启动时加载）。

## 排障与回滚

- **整体回滚**：cordis.patch.yml 恢复为顶层 `[]`，hooks.json 留置无害
- dsh web 启动报插件树错误 → 检查 name 解析；包名解析失败时把 `name` 改成
  app 内模块绝对路径（`.../npm/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-hooks-claude-code/lib/index.js`）
- 验证 hook 是否真的跑了：session 的 jsonl 里应有 `hook/invoked` + `hook/result`
  记录（PreToolUse/Stop 在 turn 内会落这对记录）；没有 = matcher 没命中或插件没加载
- gate_sample 误伤 → 对被拦样本先跑一次 `ledger.py query <样本>` 建台账即可放行；
  长期误伤样本类型加进脚本的 EXEMPT_EXT
- gate_churn 误伤（正常多文件开发）→ 豁免根含 `.dsh`/`node_modules`/`site-packages`；
  项目目录被误拦时把该目录移出题目工作区，或在台账落一条 stuck（语义：我知道卡在哪）
- gate_explore 误伤 → 探索计数文件是 `<ws>/out/.explore-runs.jsonl`（24h 滚动，
  可整删重置）；angr 禁项/Cython 前置靠台账证据放行（落一条含 frame_map/emulate/
  const_scan 字样的 observe 即可）；变体熔断靠台账条目增长放行
- gate_stuck 误检（自述是在描述题目现象而非自己卡住）→ 跑一条 `ledger.py observe`
  说明现状，或干脆 stuck 一条（语义：我知道自己卡没卡）；冷却标记在
  `<ws>/out/.stuck-gate.json`，按 session_id 记录，可整删重置；自测：
  `bash dsh-hooks/test_gate_stuck.sh`（15 用例，假 DSH_HOME 离线跑）。
  **v2（2026-10-11，判例 f7b0ecc2）**：只读子命令（query/render/status/validate）
  前缀贴在真实工作上不再豁免（应试绕过封堵——agent 曾把 `query >/dev/null` 贴满
  全场）；任意写条目（observe/conclude/stuck/…）晚于自述即清 episode（文档承诺的
  observe 路径此前并未生效）；首次拦截后 15min 内仅弱措辞复诉不再拦（阻尼防
  误报风暴），窗口内新强措辞仍复拦
- **gate_explore 计数文件长期不增长的排查**（92a0a107 实盘冻结成因）：该 hook 只计
  「内联代码运行」（heredoc / `-c` / stdin 管道）与 `cat/tee` 落盘 .py 两类载体；
  `python3 已落盘脚本.py` 的**运行**有意不计（正常 write-run-debug 循环误伤面太大，
  脚本积累由 churn 判定核管）。若确认载体在识别集内仍不计数，查 hook stderr 的
  `gate_explore hook warning`（异常即放行）与 hooks.json 挂载顺序
- **被 hook exit 2 拦住时，第一步是读 hook 源码**（`~/.dsh/hooks/gate_*.py`，放行条件
  都写在里头），不是换目录/改名绕过——858e13b3 session 在此烧掉 ~25 次调用，且换目录
  = 样本路径变 = 台账断链，反而触发更多拦截
- hook 脚本自身异常一律放行（exit 0），不会阻塞正常工作

## 设计边界

- 防惯性直读/惯性堆脚本，不防蓄意绕过（命令写进脚本文件即可绕过；绕过会在台账缺失上留痕）
- 不改 dsh 本体、不动 profile 的 package.json（2026-09 双拷贝崩溃事故的教训）
- gate_churn 是速度坎不是墙：落一条 stuck 即放行；此后每 8 个脚本需要一次台账接触（任一条目）续额度——目的是逼台账接触成为节奏，不是禁止迭代
