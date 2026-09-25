# Smoke Cases —— 每个 skill 一条最小触发用例

> 用途：防止"写了但永远不走"的盲区（评测实测：android-re / vuln-audit 在三轮真题中零触发）。
> 每条用例给：**输入场景 → 应触发的路由/动作 → 最小验证**。
> 改 skill 后拿对应条目过一遍；新 skill 入库必须先在这里登记一条。

| Skill | 输入场景 | 应触发 | 最小验证 |
|---|---|---|---|
| re-triage | 任意新样本到手 | `ensure` + `triage`，先记录 imports + 语言/壳判定再深挖（铁律 4） | triage JSON 含 `packer` 块与 `lang_hints` |
| ghidra-core | 任何区域级分析 | `ledger.py observe` 落账；同区第二次 observe 被断路器拦（exit 2） | `ledger.py validate <bin>` exit 0 |
| ghidra-static | 判型为普通 native、要读懂逻辑 | Recon→Analysis 流程；引用伪码结论前先 `decomp_lint.py` 体检 | fatal 函数清单非空时禁止读这些函数的伪码 |
| re-dynamic | 静态 15 分钟无关键路径 | 直接运行/oracle.py/Frida 入口；patch 态结论标 `--independent no` | oracle 有正例+负例成对（铁律 11） |
| re-unpack | triage `packer.verdict=upx` 或高熵+导入异常 | `upx -d` / `upx_repair.py`；脱壳产物回 re-triage 重新分诊 | 脱壳前后 imports 对比，验证清单全过 |
| traffic-analysis | 输入是 pcap/pcapng | 流量分诊（协议树/隧道/隐信道）；提取出的二进制回 re-triage | tshark 可用性以 doctor toolchain 节为准 |
| android-re | 输入是 APK 且纯 DEX（无 lib/） | apk-triage：多 dex 启发式（真逻辑常在极小 dex）、签名/debuggable 判定、flag 形态全扫 | jadx/apktool 可用性以 doctor 为准 |
| vuln-audit | 任务目的是找漏洞/攻击面 | 按 checklist 逐项排查，命中项回 ghidra-static 深挖确认 | 排查结论逐项给"已查/未查+原因"，禁止默认无洞 |

## 判据自动化

- 台账 schema：`ledger.py validate <bin>`（exit 0 = 全部条目符合最小 schema）——CI 回归的机械判据
- 结构自检：`doctor.py --quick`（exit 0 = Ghidra 核心环境可用；toolchain 分层报告）
- 触发评测（description 是否会被 agent 正确路由）属于 agent 行为层，用 skill-up/skill-comply 类评测框架跑，不在本文件范围

## 脚本级冒烟用例（ghidra-core/scripts/）

> 每个脚本一条；优先用 `--selftest`/fixture，无自带 fixture 的用 happyVm 样本（`SHA256 80f96be1…`，已知期望值来自 `Desktop/happyVm_skill修复审计.md` 附录 A）。

| 脚本 | 输入 | 最小验证 |
|---|---|---|
| `emulate_program.py` | console 型校验 PE + `--break-success/--break-fail` | 正例命中成功断点、改末位的负例不命中（天然正负对照，禁止只跑正例） |
| `jt_resolve.py` | 跳转表分发点地址（happyVm: `0x40aba0`） | 解出**双表** `0x442b90`+`0x442ba0`；`0x442ba0[0..3]` = `0x40adf9/0x40ae31/0x40ae4f/0x40ae79` |
| `frame_map.py` | 大栈帧函数（happyVm: `0x40b2e0`） | 帧 `0xc48`；标出 `+0x80..0x90` 同槽多宽度可疑；`+0x49c` 失败计数器 |
| `const_audit.py` | 含小整数渲染的函数（happyVm: `0x40b2e0`） | 抓到 `&DAT_00000007`（= 长度 7）类嫌疑；真实 `LEA` 立即数（如字符串中部指针）**不**报漂移 |
| `call_histogram.py` | 反汇编 listing 文件（happyVm: main_asm.lst） | 头号命中 `0x40aba0` × 22（≥3 次高亮） |
| `const_scan.py` | Cython/C 反编译 C 或 decompile-all @out JSON | 重建 `PyList_New/PyTuple_New` 字面量；小整数聚集告警（chal 复盘 L 表 48 项） |
| `xor_scan.py` | 含单字节 XOR 层的 blob | Top N 命中正确密钥；`--dump` 产物可打印/magic 正确 |
| `emulate_blob.py` | 裸 blob + `--base/--entry/--rsp` | 停止原因分类输出；unicorn 缺失时 exit 3 且提示进 re-tools-venv |
