# 证据台账（Evidence Ledger）——铁律 7 的机械执行载体

每个被分析的二进制维护一份台账。「我是不是在原地打转」不能靠记忆回答，要靠记录回答——
而记录不能靠自觉，所以台账的唯一入口是 `scripts/ledger.py`：**文字纪律管不住的手，由脚本拦住。**

## 文件形态

| 文件 | 角色 | 维护方式 |
|------|------|----------|
| `<ws>/out/<样本名>.ledger.jsonl` | 机器真相（append-only，每行一条 JSON） | 只能由 ledger.py 追加 |
| `<ws>/out/<样本名>.ledger.md` | 人读视图（四张表：权威结论/已踏勘区域/卡点/异常） | 每次入账后自动重建，手工改动会被覆盖 |

## 命令

**必填项速查**（参数错误是最高频往返，先扫这张表再敲命令）：

| 子命令 | 必填 | 可选 |
|---|---|---|
| `query` | `<binary>` | `--region/--id/--text` |
| `observe` | `<binary> --region --tool --note` | 同区回访时 `--delta` 必填 |
| `conclude` | `<binary> --address --conclusion --evidence --source --independent` | `--harness`（self-script 时必填）`--quote --id --overturn` |
| `anomaly` | `<binary> --region --note --consequence` | — |
| `resolve` | `<binary> --anomaly <id>` + `--note`/`--waive` 二选一；`--note` 关闭时 `--evidence` **必填**（反向门，缺证据 exit 2） | `--evidence-file` |
| `stuck` | `<binary> --at --tried --escalate` | 有 open anomaly 时 `--ack "A1,A3"` 必填 |
| `status` / `render` | `<binary>` | — |

`--source` 枚举：`read_views / runtime-oracle / runtime-gdb / decompiler-render / self-script / manual`；
`--independent` 枚举：`yes / no`（详见下文「结论来源标注」）。

```bash
LEDGER="$HOME/.dsh/skills/ghidra-core/scripts/ledger.py"

# 先查后析：分析任何函数/区域之前先查。命中 = 直接引用结论，禁止重析
python "$LEDGER" query <binary> --region 0x140001000-0x140001060

# 观察落账：每个区域级观察（反编译/反汇编/读字节/搜索命中）都必须入账
python "$LEDGER" observe <binary> --region <区间|函数名> --tool <工具> --note "看到了什么"

# 权威结论：写入即锁定；必须标注读数来源与独立性（铁律 10）
python "$LEDGER" conclude <binary> --conclusion "check_flag 是 XOR 0x37 比较" \
  --address 0x140001064 --evidence "decompile + read-bytes .rodata" \
  --source read_views --independent yes --quote "83 f0 37 ..."

# 推翻留痕：同 id 覆盖必须 --overturn + 新证据（旧结论自动留在 JSONL 里）
python "$LEDGER" conclude <binary> --id 1 --overturn --conclusion "其实是 XOR 0x38" \
  --address 0x140001064 --evidence "oracle.py 实测" \
  --source runtime-oracle --independent yes

# --id 接受字符串（C1、Q5-1…），缺省 = 下一个空闲整数
# 长文本走文件（PowerShell 5.1 内嵌引号会炸参数边界，见 windows-powershell.md §1）：
python "$LEDGER" conclude <binary> --conclusion-file c.txt --evidence-file e.txt \
  --quote-file q.txt --address 0x140001064 --source read_views --independent yes

# 卡点必记：断路器触发后，升级前先把「卡在哪、试过什么」留下来
python "$LEDGER" stuck <binary> --at 0x140002000-0x140002040 \
  --tried "肉眼 hex,search_bytes" --escalate "确认是否 packed -> re-unpack"
# 存在 open anomaly 时 stuck 被拒（exit 2）：要么 --ack 全部列出，要么先 resolve --waive
python "$LEDGER" stuck <binary> --at 0x140002000 --tried "..." \
  --escalate "..." --ack "A1,A3"

# 异常落账（铁律 12）：观测到的不一致必须转成可检验假设，--consequence 必填
python "$LEDGER" anomaly <binary> --region 0x140003000-0x140003040 \
  --note "同一字段两次读出不同值" \
  --consequence "若该字段是明文，则重复包取值必须一致"

# 关闭异常：append-only，不改旧行；--note（如何解决）与 --waive（为何豁免）二选一
# 反向门（机械门）：--note 关闭必须同时给 --evidence（命令/地址/读数），否则 exit 2——
# 叙述性机制解释不是证据，不许用它解除约束
python "$LEDGER" resolve <binary> --anomaly A1 --note "read_views 重读，第一次是渲染错位" \
  --evidence "read-bytes 0x140003010 16 -> 89 50 46，与反汇编一致"
python "$LEDGER" resolve <binary> --anomaly A2 --waive "需要 trace 工具，本机未装"

# 总览（新会话接手旧样本的第一件事）/ 手动重建 md
python "$LEDGER" status <binary>
python "$LEDGER" render <binary>
```

区域写法：`0x1000-0x1100` / `0x1000+0x40` / `0x1000`（点）/ `check_flag`（名字）/
`name:fac`（强制按名字，防止全 hex 字符的名字被当成地址）。区间判定用**重叠**——
`0x1000-0x1100` 与 `0x1080` 也算同一区域。

## 断路器语义（这是机制，不是建议）

`observe` 是唯一的观察入账口，它在写入前做两道机械检查，命中即 **exit 2 + 打印强制问题**：

1. **同区回访**：目标区域与任一已入账观察重叠 → 必须提供 `--delta` 回答
   **"这次观测和上次差在哪"**。`--delta` 缺失、或与 `--note` 相同 → 拒绝入账。
   第 3 次起即使放行也会带 warning：delta 仍无实质增量就必须升级工具层级。
2. **肉眼预算**：工具是 xxd/hexdump/肉眼 等裸 hex 读取时，同一区域最多 2 次，
   第 3 次无条件拒绝——字节只能通过工具解读，肉眼仅用于验证工具输出。

断路器触发时 stdout 打印：该区域全部历史观察 + 强制问题 + 升级菜单：

```
答不出 -> 禁止换第 3 种方式重试同一路径，必须升级其一：
  · 换工具层级: read-bytes -> disassemble -> decompile -> pcode / search-decompiled
  · 疑似 packed/加密 -> re-unpack（upx -d / upx_repair.py / unpacker）
  · 静态卡住 -> re-dynamic（跑起来看 / oracle.py / emulate-function）
  · 都不行 -> ledger.py stuck ... 然后问用户
```

exit 2 不是错误，是门。**正确处理是回答强制问题或升级，不是换措辞重试。**

## 异常即约束（铁律 12 的机械执行）

观测到的不一致**不许**在心里标注"噪声/歧义待枚举"然后继续——它必须立刻变成一条
可检验的假设落账：`anomaly` 的 `--consequence` 必填，回答"**若该不一致成立，什么必须为假**"。
没有 consequence 的"异常"只是感受，不是约束。

**什么时候必须 anomaly**（命中其一即落账，不许掂量）：

| 场景 | anomaly 示例 |
|------|-------------|
| 重复键冲突（同一键两个取值） | `--note "seq=0x10 的包 payload 两次不同" --consequence "若 payload 是明文，则同键取值必须一致"` |
| 伪码声明长度 vs 实测处理长度不符 | `--note "伪码读 32 字节，实测处理 64" --consequence "若长度域是明文，则处理长度不能超过它"` |
| 同一事实两次读数不同 | `--note "0x140003010 两次 read 值不同" --consequence "若该区域是 rodata，则两次读数必须一致"` |
| 工具 verdict 与结构证据冲突（如 triage 报 packed 但节布局正常） | `--note "triage=packed-unknown 但存在 .CRT/.tls 节" --consequence "若样本真有壳，则不应出现 MinGW 标准布局"` |
| **自己 harness 的异常**（假分配/越界/调用"成功"但零效果） | `--note "HeapReAlloc 桩一次分配跳 0x30000000" --consequence "若桩实现正确，则堆顶不应跳跃式增长"` |

**「我心里已经解释清楚了」不是免落账的理由**——happyVm 复盘：6 次不一致（triage 误报、
harness bug、"多解"假象）全部心里解释掉、0 次落账，正是铁律 12 要拦的行为。解释清楚也要落账，
落账成本一行命令，不落账的代价是断路器与复盘双双失效。`status` 在 ≥5 次观察且 0 条 anomaly
时会打印提示——看到它就回查一遍"这期间有没有被我消化掉的不一致"。

consequence 的写法要点：指向一个**可检验的外部事实**，形如
"若该字段是明文，则重复包取值必须一致"——之后任何一次观测都能拿来证伪它。

**与 stuck 的联动（机械门，不是建议）**：该二进制存在 open anomaly 时，`stuck` 直接
exit 2 并打印全部 open 清单。两条出路：

1. **明知未查** → `stuck --ack "A1,A3"` 把每个 open id 列出来（语义：我知道这些没查），
   正常入账。ack 不全（漏 id、错 id）同样 exit 2。
2. **工具缺失等客观不可查** → `resolve --waive "为何豁免"` 先豁免，不许硬卡。
   waive 不是放弃：豁免理由落账，后来工具到位可随时再 anomaly 一次重新追。

**关闭异常的机械门（反向门，比正向门更重要）**：`resolve --note` 必须同时给
`--evidence`（复核命令/地址/读数），否则 **exit 2**——叙述性机制解释不是证据，
不许用它解除约束；没有反向门，"我大概搞清楚了"就能无条件关闭任何 anomaly。
waive 通道豁免 `--evidence`（豁免理由即 `--waive` 文本本身，已强制入账），
但 `waived` 在 `status`/render 里与 `resolved` 单独区分、全程可见。
证据写入 `anomaly-resolve` 条目的 `evidence` 字段并在 render 异常表「解决/豁免」列
带出；`validate` 只约束新条目（历史无 evidence 字段的 resolve 不判违规）。

append-only 原则不变：`resolve` 不改 anomaly 旧行，只追加 `anomaly-resolve` 记录；
open 状态由回放计算（有 anomaly 且无对应 resolve = open），`status`/`query` 输出
`open_anomalies` 列表，render 的第四张表「异常（anomaly）」状态列齐全（open/resolved/waived）。

## 结论来源标注（铁律 10，conclude 强制字段）

每条结论必须交代「读数是谁的、有没有第二来源」——encode 复盘的错误结论若被强制标注
`source=self-script, independent=no`，在交付前就显眼到无法忽略：

| 字段 | 取值 | 语义 |
|------|------|------|
| `--source` | `read_views` / `runtime-oracle` / `runtime-gdb` / `decompiler-render` / `self-script` / `manual` | 读数通道。可信度从高到低；`decompiler-render` 与 `manual` 承载关键常量前应先过 read_views 对照（铁律 8） |
| `--harness` | 脚本路径+版本 | `source=self-script` 时**必填**；未通过已知答案自检的 harness 输出是零证据 |
| `--independent` | `yes` / `no` | 是否有第二独立来源（静态常量/第二输入/已知明文）交叉印证。`no` → render 标 **⚠UNVERIFIED** 且入账时打印警告——禁止原样交付 |
| `--quote` | 工具输出原文 | 结论所依赖的 verbatim 输出；引不出原文的结论按未验证假设对待 |

## 六条规则（与机制一一对应）

1. **先查后析** → `query`：命中已踏勘区域 = 直接引用，重析会在 `observe` 时被拦。
2. **写入即锁定** → `conclude`：权威结论是当前事实源，后续推理引用它，不再从字节重推。
3. **推翻留痕** → `conclude --overturn`：只能被新证据推翻；旧结论永久留在 JSONL。
4. **卡点必记** → `stuck`：每次断路器触发都留「卡在哪、试过什么、升级去哪」。
5. **跨会话续命** → `status`：新会话接手旧样本，先 `status` + 读 `.ledger.md` 再动手；
   台账与 triage.json 并列为两份权威源。
6. **产物锁定**（G8）：脱壳/patch/提取产出的**每一个新文件**，产出当刻 `observe` 一条带 SHA256 的记录
   （`sha256sum <file>` 或 `Get-FileHash`）。后续所有分析只认台账里锁过哈希的产物；
   磁盘上的文件与台账哈希不符 = 权威源被破坏，停下来查原因，不要接着分析。

## 最小例子（一次完整循环）

```bash
# 首访：直接入账
$ python "$LEDGER" observe app.exe --region 0x140001000-0x140001060 --tool decompile --note "entry 仅初始化"
{"ok": true, "booked": true, "visit": 1, ...}

# 回访：被拦
$ python "$LEDGER" observe app.exe --region 0x140001020 --tool read-bytes --note "再看看"
[断路器 · 铁律7] 区域 "0x140001020" 第 2 次回访 —— 缺少 --delta
──── 已有观察 ────
[1] ... tool=decompile  note="entry 仅初始化"
──── 强制问题 ────
这次观测和上次差在哪？
（exit 2）

# 答得出：带 delta 放行
$ python "$LEDGER" observe app.exe --region 0x140001020 --tool read-bytes \
    --note "44 89 是 mov" --delta "上次只看伪码，本次确认原始字节与反汇编一致"
{"ok": true, "booked": true, "visit": 2, ...}

# 答不出：留卡点后升级，而不是再换种说法看一遍
$ python "$LEDGER" stuck app.exe --at 0x140002000-0x140002040 \
    --tried "肉眼 hex,search_bytes" --escalate "确认是否 packed -> re-unpack"
```
