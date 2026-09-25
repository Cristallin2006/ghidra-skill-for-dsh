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
