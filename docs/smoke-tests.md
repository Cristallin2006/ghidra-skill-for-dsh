# Smoke Cases —— 每个 skill 一条最小触发用例

> 用途：防止"写了但永远不走"的盲区（评测实测：android-re / vuln-audit 在三轮真题中零触发）。
> 每条用例给：**输入场景 → 应触发的路由/动作 → 最小验证**。
> 改 skill 后拿对应条目过一遍；新 skill 入库必须先在这里登记一条。

| Skill | 输入场景 | 应触发 | 最小验证 |
|---|---|---|---|
| re-triage | 任意新样本到手 | `ensure` + `triage`，先记录 imports + 语言/壳判定再深挖（铁律 4） | triage JSON 含 `packer` 块与 `lang_hints`；仅 `.bss` 族未初始化块的 ELF 共享库不得判 `packed-unknown`（hollow 信号降级进 `false_positive_hints`） |
| ghidra-core | 任何区域级分析 | `ledger.py observe` 落账；同区第二次 observe 被断路器拦（exit 2） | `ledger.py validate <bin>` exit 0 |
| ghidra-static | 判型为普通 native、要读懂逻辑 | Recon→Analysis 流程；引用伪码结论前先 `decomp_lint.py --binary <bin>` 体检（尾调用甄别剔除良性误报） | fatal 函数清单非空时禁止读这些函数的伪码；尾调用类单列不算 fatal |
| re-dynamic | 静态 15 分钟无关键路径 | 直接运行/oracle.py/Frida 入口；patch 态结论标 `--independent no` | oracle 有正例+负例成对（铁律 11） |
| re-unpack | triage `packer.verdict=upx` 或高熵+导入异常 | `upx -d` / `upx_repair.py`；脱壳产物回 re-triage 重新分诊 | 脱壳前后 imports 对比，验证清单全过 |
| traffic-analysis | 输入是 pcap/pcapng | 流量分诊（协议树/隧道/隐信道）；提取出的二进制回 re-triage | tshark 可用性以 doctor toolchain 节为准 |
| android-re | 输入是 APK 且纯 DEX（无 lib/） | apk-triage：多 dex 启发式（真逻辑常在极小 dex）、签名/debuggable 判定、flag 形态全扫 | jadx/apktool 可用性以 doctor 为准 |
| vuln-audit | 任务目的是找漏洞/攻击面 | 按 checklist 逐项排查，命中项回 ghidra-static 深挖确认 | 排查结论逐项给"已查/未查+原因"，禁止默认无洞 |
| pwn-exploit | 漏洞已定位要写 exp / 附件是 binary+libc+nc 地址 | 先 `pwn_triage.py` 保护矩阵硬门再选线；exp 一律 WSL 跑；flag 结论必须远程回显 `--program-accept` | 未跑 pwn_triage 直接写 exp = 流程违规；patchelf 副本上的成功只算中间结论 |

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
| `decomp_lint.py` | decompile-all @out JSON + `--binary`（happyVm: happyvm.all.c） | fatal **13/468 = 2.8%**（尾调用已剔除，单列 15 个）；有 fatal exit 2。不给 `--binary` 时旧口径 28/468（尾调用混入 fatal） |
| `const_scan.py` | Cython/C 反编译 C 或 decompile-all @out JSON | 定位 `PyList_New(n)` 形状（chal 复盘 L 表 = n=48）+ 小整数聚集告警；加 `--binary`（须先 ensure）把 `<DAT_…>` 缓存 PyLong 还原成 Python 值（CPython 布局自动投票，`--py` 可强制）；落在 `.bss`（initialized=False）的引用**静态不可还原**——脚本会单列 `unresolved_in_bss` 并指向 ctf-patterns §12 元数据或运行期取数，不是 daemon 故障 |
| `xor_scan.py` | 含单字节 XOR 层的 blob | Top N 命中正确密钥；`--dump` 产物可打印/magic 正确 |
| `emulate_blob.py` | 裸 blob + `--base/--entry/--rsp` | 停止原因分类输出；入口未映射判「entry-unmapped（harness 配置错）」exit 4；blob 不可读/空 blob/未知 `--reg` 也是 exit 4；unicorn 缺失时 exit 3 且提示进 re-tools-venv |
| `model_diff.py` | 玩具对（**命令形式必须是 `python3 x.py`，裸路径会被当命令 → exit 3**）：oracle=正确实现 stdin→stdout 恒等，model=真 16 位半字交换（`d[2:4]+d[0:2]`）/ chal 形状（低 16 位原样、高 16 位 ^0x1234）/ 逐字节 nibble 交换 | 16 位交换判「高低半块交换（按 4 字节块）」、chal 形状判「低半块全对+高半块 XOR 恒定」、nibble 交换判「高低半字节交换」，判词均为疑似接口错且 exit 2（宽度级规律永不落"疑似算法错"）；恒等对 exit 0；不存在命令 exit 3 |
| `oracle_family.py` | 玩具 C（`factor` 参与计算 + `noise` 无关，gcc -O0 -no-pie）+ `--stub addr=0x0/0xff` | factor 两个值均判「变 → 参与计算」、noise 均判「不变 → 无关通道」exit 0；非 x86-64 / imm32 溢出（不加 `--rax`）exit 3 |
| `ssa_trace.py` | 玩具模块（`key=random.getrandbits(8); acc=(key^0x2a)*3&0xff`）+ `--class/--ctor-input 'A*8' --observe-builtins sum --seed 1 --out t.json` | 事件链含 `RNG:getrandbits→^→*&` 且 `&` 事件值 == 手算 `((k^0x2a)*3)&0xff`；`BLK:sum` 命中；`result.acc` 为 `名=值` 形式；exit 0 |
| `ssa_reconstruct.py` | 上一条的 t.json → `--out recon.txt --lits l.json` | 直线程序含 `(k1) ^ (42)` 形行与 `sum(...)` 调用行；字面量报告打印且 exit 0；**带 `--out` 时打印「下一步（铁律 6 闸）」+ peel_inverse.py 确切命令**；坏 trace 路径 exit 2 |
| `peel_inverse.py` | 滞后-2 掩码链玩具（`m_i = (m_{i-2} + m_{i-1}*3) & 0xffffffff` ×6）经 ssa_trace→ssa_reconstruct 的 recon.txt | 检出「滞后-2 递推段 (6 项)」并印逐层反解提示，exit 0；**检出段时印「下一步（闸的输出是命令不是建议）」+ `--emit-solver` 确切命令 + 骨架使用闸文案（0 填 0 跑 = 未过闸，4ccec36c）**；`--emit-solver s.py` 生成骨架后：未填 KNOWN 运行时指名缺哪两个段末掩码且 exit 2；填入段末两掩码正确值后反解出全部 6 项、前向验证通过、exit 0；**无结构输入印 cone_invert.py 锥形反推指引（不再是放行 z3 文案），exit 0**；缺文件 exit 2 |
| `cone_invert.py` | 玩具 recon：`t1=(x)^(111); t2=(t1)+(1000); t3=(t2)&(4294967295); t4=_p1(t3,7); t5=(t4)<<(3)`（x=42 → t5=59864）+ `--calls` 给 `_p1(a,b)=((a*b)&0xffff)-((a*b)>>16)`；符号化玩具：reconA `k1=111; t1=(60486)*(k1); t2=(t1)^(k1); t3=(t2)<<(3)`，reconB 同构但常量 61253，reconC 同构多插一行（行号错位模拟） | `--known t5=59864` 全链反解出 **x=42**（掩码处模派生带 mod 传播）exit 0；加错锚点 `--known t1=70` 报矛盾（前向 59920 != 59864）exit 1；缺 `--calls` 或 `--brute _p1=100` 时断链原因（无实现/域太小）进「缺料警告」单列——即使该变量已从他路解出也可见；无 `--known` exit 2；**矛盾分类（29bf99c0 判例）**：未符号化 reconA + 外部锚点（另一输入的 t3）→ 印「锥体不含任何未知量 = 输入符号化不完整」+ `--diff-symbolize` 确切命令，exit 1；锥内含未知量 x 的真矛盾 → 保持「方程/常量错了」原判词；**`--diff-symbolize`**：A vs B 符号化出 `IN0=60486`（exit 0，文件头带映射注释），A vs C 行号错位仍正确符号化；asym + 真锚点反解出 **IN0=65000**（即真实输入常量），exit 0 |
| `dsh-hooks/stop_check.py` | 测试架（DSH_HOME 指向临时 home）：台账 stuck（escalate 含可执行路径）→ 后续 observe 落账「未收敛/未拿到 flag」；会话日志用未压缩 `session.v3.jsonl`（含 ownership 写命令 + user/message 时间戳） | **第五类闸（29bf99c0 未收敛投降）**：stuck 后未收敛、无新 stuck、无 flag 结论、用户在 stuck 前发话 → deny exit 2（印四个出口）；用户在 stuck 之后发过话 → 放行（视为已问用户）；stuck 后有 `--kind flag` 结论 → 放行；stuck 后正常进展（无未收敛词）→ 放行；回归：末条 stuck 且 escalate 未执行 → 闸 4 仍 deny exit 2 |
| `dsh-hooks/gate_stuck.py` | 离线测试架 `dsh-hooks/test_gate_stuck.sh`（DSH_HOME 指向临时 home + 伪造会话日志/台账）；真实回归：b781ff3c adventure session 导出件 | 测试架 9 用例全过：强措辞 1 次即拦 exit 2 / 拦后冷却放行 / 自述后已 stuck 放行 / 弱措辞单发放行、两发拦截 / 无活跃台账放行 / 命令含 ledger.py 放行 / 坏 payload 放行 / 冷却标记改旧后新 episode 再拦。真实回归：对 b781ff3c 日志扫出弱措辞 5 条消息（最早 10:10:44——紧跟 shop 溢出识别之后）+ 强措辞 3 条（10:34–10:38），闸在 10:11 就会首次触发 |

## 脚本级冒烟用例（traffic-analysis/scripts/）

> 用 AegisTrace 样本（WSL `/root/src/aegis-work-fresh/samples/`，golden 值见 `docs/cases/aegis-composite-carrier.md`——判例存档在 skill 之外，勿链回 skill 内文件）。

| 脚本 | 输入 | 最小验证 |
|---|---|---|
| `decode_engine.py` | aegis_telemetry.pcap + `--stream "10.77.3.41:49622->10.77.3.9:8443" --key-expr "(tsval>>8)&0xff" --fields pay.lo,tsval.n0,seq.n1 --ops xor --arity 3 --order perm:<rodata[0x32e0:0x3320]> --packing hi --oracle sha256:75c75a60…ff45146f`（**不做 tshark 预过滤**） | 自动剔除 3 个同键无载荷握手包并告警（71→68 包）；命中 `8f6419d4…e25577a1`，exit 0；`--keep-empty` 时保留污染（流 71 包，可 miss）——T-A2#1 回归 |
| `conflict_oracle.py` | 同上 pcap + 同 stream/key-expr | 冲突集干净：仅 tsval/tsval.n0/pkt 在键 {5,12,31,45} 冲突（无 sport/dport/flags 假冲突）；打印「重生字段」冲突诊断；末尾恒输出 decode_engine 处方（排名不收敛时给「铺轴+oracle 过滤」窄字段池命令）；多流且未给 `--stream` 时 stderr 告警选流；`--keep-empty` 时假冲突原样可见 |
| 边界：纯元数据信道 | 全无载荷的合成 pcap | 两个脚本都**不**剔除任何包（纯元数据信道不受污染防护影响） |

## 脚本级冒烟用例（pwn-exploit/scripts/）

> 玩具样本现做现用（WSL `gcc` 一把出）；`/bin/ls` 的期望值以 pwntools `checksec --file=/bin/ls` 为交叉 oracle（双源互验，铁律 11 精神）。

| 脚本 | 输入 | 最小验证 |
|---|---|---|
| `pwn_triage.py` | ① WSL `/bin/ls`；② 全裸玩具（`gcc -fno-stack-protector -z execstack -no-pie -z norelro`）；③ seccomp 玩具（内嵌 `"seccomp"` 字符串）+ 同目录拷 libc.so.6/ld-linux；④ 非 ELF（.c 文件）；⑤ 不存在路径 | ① NX 开/Canary 有/PIE 开/RELRO Full，exit 0，与 checksec 一致；② 四项全关 + 「可直接塞 shellcode」hint，exit 0；③ seccomp 检出 → stderr 硬门提示 + **exit 2**，libc+ld 附件触发 patchelf 对齐告警；④⑤ 均 exit 4；附件扫描不得把 `corelist` 误判为 core dump |
