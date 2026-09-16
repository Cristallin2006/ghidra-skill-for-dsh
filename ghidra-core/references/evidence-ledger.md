# 证据台账（Evidence Ledger）——铁律 7 的机械执行载体

每个被分析的二进制维护一份台账。「我是不是在原地打转」不能靠记忆回答，要靠记录回答——
而记录不能靠自觉，所以台账的唯一入口是 `scripts/ledger.py`：**文字纪律管不住的手，由脚本拦住。**

## 文件形态

| 文件 | 角色 | 维护方式 |
|------|------|----------|
| `<ws>/out/<样本名>.ledger.jsonl` | 机器真相（append-only，每行一条 JSON） | 只能由 ledger.py 追加 |
| `<ws>/out/<样本名>.ledger.md` | 人读视图（三张表：权威结论/已踏勘区域/卡点） | 每次入账后自动重建，手工改动会被覆盖 |

## 命令

```bash
LEDGER="$HOME/.dsh/skills/ghidra-core/scripts/ledger.py"

# 先查后析：分析任何函数/区域之前先查。命中 = 直接引用结论，禁止重析
python "$LEDGER" query <binary> --region 0x140001000-0x140001060

# 观察落账：每个区域级观察（反编译/反汇编/读字节/搜索命中）都必须入账
python "$LEDGER" observe <binary> --region <区间|函数名> --tool <工具> --note "看到了什么"

# 权威结论：写入即锁定
python "$LEDGER" conclude <binary> --conclusion "check_flag 是 XOR 0x37 比较" \
  --address 0x140001064 --evidence "decompile + read-bytes .rodata"

# 推翻留痕：同 id 覆盖必须 --overturn + 新证据（旧结论自动留在 JSONL 里）
python "$LEDGER" conclude <binary> --id 1 --overturn --conclusion "其实是 XOR 0x38" \
  --address 0x140001064 --evidence "oracle.py 实测"

# 卡点必记：断路器触发后，升级前先把「卡在哪、试过什么」留下来
python "$LEDGER" stuck <binary> --at 0x140002000-0x140002040 \
  --tried "肉眼 hex,search_bytes" --escalate "确认是否 packed -> re-unpack"

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

## 五条规则（与机制一一对应）

1. **先查后析** → `query`：命中已踏勘区域 = 直接引用，重析会在 `observe` 时被拦。
2. **写入即锁定** → `conclude`：权威结论是当前事实源，后续推理引用它，不再从字节重推。
3. **推翻留痕** → `conclude --overturn`：只能被新证据推翻；旧结论永久留在 JSONL。
4. **卡点必记** → `stuck`：每次断路器触发都留「卡在哪、试过什么、升级去哪」。
5. **跨会话续命** → `status`：新会话接手旧样本，先 `status` + 读 `.ledger.md` 再动手；
   台账与 triage.json 并列为两份权威源。

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
