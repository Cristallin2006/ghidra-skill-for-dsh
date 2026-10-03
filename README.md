# ghidra-skill-for-dsh

**简体中文 | [English](README_EN.md) | [日本語](README_JA.md)**

[![Release](https://img.shields.io/github/v/release/Cristallin2006/ghidra-skill-for-dsh)](https://github.com/Cristallin2006/ghidra-skill-for-dsh/releases)
[![License: MIT](https://img.shields.io/github/license/Cristallin2006/ghidra-skill-for-dsh)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Cristallin2006/ghidra-skill-for-dsh)](https://github.com/Cristallin2006/ghidra-skill-for-dsh/stargazers)
[![dsh skill](https://img.shields.io/badge/dsh-skill-blue)](https://www.npmjs.com/package/@deepseek-ai/dsh)
[![Ghidra 12.x headless](https://img.shields.io/badge/Ghidra-12.x%20headless-red)](https://ghidra-sre.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20WSL-lightgrey)](TOOLCHAIN.md)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.11-blue)](TOOLCHAIN.md)

面向 [dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)（DeepSeek Harness）的逆向工程 agent skill 家族：Ghidra 12.x headless 常驻 daemon（~0.2s/命令，无 Jython/GUI/MCP 依赖）+ 八场景方法论。覆盖 CTF 逆向、crackme、恶意样本分诊、漏洞预筛、二进制利用（pwn）、pcap 取证、APK 分析。

Reverse-engineering agent skills for dsh: a Ghidra headless RPC daemon (vendored [ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc) + dsh patches) plus eight scenario skills — triage / unpack / static / vuln-audit / dynamic / pwn / traffic / android-re — for CTF reverse engineering, unpacking, malware triage, binary exploitation, pcap forensics and APK analysis.

## 实测性能

全部结果为真实 CTF 题独立求解（不参考旧台账/WP），经原程序正负对照验证、session 逐行审计确认。

| 题目 | 题型 | 成绩 | 关键证据 |
|---|---|---|---|
| encode | UPX 壳 + 换表 base64 + RC4 | 40 min 做不出 → **16 min 解出** | 调校前后同题对比；提速来自机制而非模型：常驻 daemon + 三道脚本闸门 + 函数级 Oracle + 脱壳域 |
| Reverse-chal | Cython 3.0.10 CPython 扩展；IDEA 变体（mod-65537 乘）+ SM4 S 盒 + 随机掩码诱饵门 | **30 min 解出**（同题最快，首解 55 min） | 语义建模路径：识别算法族后重建分组密码求逆；flag 结论带 `--program-accept` 落账 |
| AegisTrace | pcap 三字段半字节隐信道 + 零引用置换表 + 自定义协议完整利用链 | **29 min / 169 步**盲测解出 | 判例文件与全部答案要素脱敏移出后重测（对照组 20 min）；golden 值首现于 oracle 命中输出，结论经原程序 8/8 次接受回执终审 |

**同题三轮回放（Reverse-chal，2026-09-30）**——每次失败都归因落地为机械修复，直到解出：

1. `4ccec36c` 骨架弃用投降（121 min 无 flag）→ 落地四处修复：骨架使用闸 / 否定论断强制落账 / stop_check 带路径投降闸 / `cone_invert.py` 锥形反推
2. `29bf99c0` 谎称「上下文将尽」投降（19 min 无 flag，实测 1M 窗口占用不足三成）→ 再落三处修复：矛盾分类判词 / `--diff-symbolize` 输入字面量自动符号化 / 未收敛投降闸
3. `ddf11a87` **30 min 解出**，两道机械闸门按设计拦截

**持续硬化指标**（多轮真题复盘 + 第三方对抗审计，happyVm / DEFCON26 quals 等）：

- 伪码 fatal 误判基线 **6.0% → 2.8%**（尾调用甄别）
- 跳转表 / 栈帧 / 常量三类「手读 asm」高危动作全部脚本化
- 台账从 observe/conclude 扩展为 **observe / conclude / anomaly / hypothesis / plan / stuck** 六种对象——假设与枚举预算不再只活在聊天里

## 结构（1 底座 + 8 场景）

| 目录 | 职责 |
|---|---|
| `ghidra-core` | 唯一放代码的底座：engine（ghidra-rpc + dsh 补丁）、`rpc_driver.py` 统一入口、`doctor.py` 环境自检、三道闸门 `ledger.py` / `read_views.py` / `crypto_sanity.py`、分析脚本层（`decomp_lint` 伪码体检 / `jt_resolve` 跳转表 / `frame_map` 栈帧 / `const_audit` 常量对照 / `emulate_program` 整程序仿真 / `model_diff` 模型对拍 / `oracle_family` 打桩因子隔离等，全部自包含可独立调用） |
| `re-triage` | 未知二进制第一步：判型/语言/壳三信号交叉（节名 + magic + 结构），输出路线决策；foreign-arch ELF 路由（Ghidra processor 反编译优先，objdump 只核对单点） |
| `re-unpack` | 脱壳 + 强制验证：UPX/ASPack/Themida/VMProtect/多层壳，PyInstaller 一条龙（pycdc 覆盖 Python ≥3.9） |
| `ghidra-static` | 静态深挖：反编译/xref/标注/patch/交付；Go/Rust stripped 指纹、CTF 模式库（含 fp16 自检向量） |
| `vuln-audit` | 漏洞模式 checklist：内存破坏/格式化串/整数溢出/命令注入等 8 类，可达性优先 |
| `re-dynamic` | 跑起来看：函数级 Oracle（qiling）、打桩 oracle 家族（单因子隔离）、模型差分校验、跨架构 qemu-user/gdb-multiarch、Frida 时间/随机源 hook、Windows GUI 消息驱动 |
| `pwn-exploit` | 从洞到 flag：pwn_triage 保护矩阵硬门、checksec 决策树、ROP/fmtstr/堆/FSOP/内核配方库（370KB 按需 grep）、pwntools 模板五件套、游戏/文字冒险题专章（`references/game-pwn.md`：经济溢出/数值墙路标/道具编辑堆原语）；「本地通≠远程通」验证门强制远程回显落账 |
| `traffic-analysis` | pcap 分诊、DNS/ICMP/时序隐信道、USB HID 还原、WPA/TLS 解密；脚本全零依赖 + tshark |
| `android-re` | 纯 DEX APK：多 dex 启发式、jadx 四档反编译、Toast 锚点定位、真机 oracle、v1 重签 |
| `docs` | 横向文档：`smoke-tests.md`（新脚本/新能力的最小冒烟判据——防"写了但永远不走"）、`legacy-plugin-pitfalls.md`（旧插件坑归档）、`cases/`（真题判例归档，含完整题解，仅供写 smoke 判据时人工参考，不链回 skill） |

边界规则：执行代码在 core，场景 skill 只有方法论；知识存 `references/` 可 grep 的纯数据文件，路由靠触发点指针，不建"知识库 skill"。

## 安装

0. **作为 dsh Skill 市场安装**：市场源填仓库地址 + git 引用 `v0.9-market`（收录版，不含尚在实测的 pwn-exploit；见 [Release 页](https://github.com/Cristallin2006/ghidra-skill-for-dsh/releases/tag/v0.9-market)）；手动安装走下面：
1. 九个目录拷到 `~/.dsh/skills/`（pwn-exploit / traffic-analysis / android-re 独立可选；pwn-exploit 的 exp 执行依赖 WSL 工具链，见 TOOLCHAIN.md）
2. 建引擎 venv（Python ≥ 3.11）并 editable 安装引擎：
   ```bash
   python3.12 -m venv ~/ghidra-rpc-venv
   ~/ghidra-rpc-venv/Scripts/python.exe -m pip install -e ~/.dsh/skills/ghidra-core/engine/ghidra-rpc
   ```
3. 工具层见 [TOOLCHAIN.md](TOOLCHAIN.md)（Tier A/B/C 分级清单；已装状态以 `doctor.py` toolchain 节为准）
4. 设 `GHIDRA_INSTALL_DIR`（Ghidra 12.x 安装目录）与 `JAVA_HOME`（JDK 21+）；可选 `DSH_GHIDRA_WS` 指定工作区
5. 自检：`python ~/.dsh/skills/ghidra-core/scripts/doctor.py`（全绿 exit 0）

**Windows 注意**：Ghidra 的 `ProjectLocator` 拒绝以 `.` 开头的路径元素，`~/.dsh/...` 不能直接传给 JVM——底座自动走 junction `~/dsh-ghidra-workspace`。

## 用法（30 秒）

```bash
SK=~/.dsh/skills/ghidra-core/scripts

python "$SK/rpc_driver.py" ensure /path/to/binary          # daemon 起停 + 导入分析（幂等）
python "$SK/rpc_driver.py" triage /path/to/binary          # 一键分诊
python "$SK/rpc_driver.py" decompile /path/to/binary main  # 反编译
python "$SK/rpc_driver.py" rename-function /path/to/binary FUN_00401000 check_flag
python "$SK/rpc_driver.py" version-track old.exe new.exe --changed-only
```

`@绝对路径` 作首个参数 = 完整 JSON 落盘；写操作即刻生效并自动存盘。完整命令清单见 `ghidra-core/SKILL.md`。

## 设计要点

- **常驻 daemon**：JVM 只起一次，温热后每条命令亚秒级；长任务（load / version-track）走后台 + `@out` 落盘
- **机械闸门，不靠自觉**：14 条铁律的执行载体是脚本——`ledger.py`（同区回访强制 `--delta`、结论写入即锁定、`resolve` 缺证据 exit 2 的反向门、hypothesis/plan 落账、`--kind model` 结论强制 `--anchor` L2 左逆锚定实测、hypothesis 三态闭环 confirmed/killed/waived）、`read_views.py`（渲染文本 vs 真实字节对照）、`crypto_sanity.py`（求逆前后合法性检查），违规一律 exit 2
- **判定性实验优先**：参数角色/因子参与度不靠调用约定猜——`oracle_family.py` 打桩隔离单因子（基线无输出自动抑制因果判词）、`model_diff.py` 模型对拍输出分歧指纹（宽度级 16/32 位半块规律 + 字节级 nibble 规律 ⇒ 接口错不是算法错；宽度级命中绝不落"疑似算法错"）
- **验证独立性**：结论强制独立来源，无则标 ⚠UNVERIFIED——Google P0 Naptime 的 Perfect Verification 原则
- **能力边界**：动态调试外包 Frida/GDB/Qiling/angr；协作式项目不做（ghidra-core/SKILL.md §8）

## 准则强制层（dsh-hooks/，可选）

catalog 只注入 skill 的 description，SKILL.md 正文和铁律不在上下文里——"AI 不遵守 skill 准则"多源于此。`dsh-hooks/` 用 dsh 内置的 hooks-claude-code 桥把关键纪律变成机械门：

- **SessionStart/SubagentStart**：会话创建即注入压缩版纪律卡（10 条，不依赖 agent 自觉读 SKILL.md）
- **PreToolUse（Pwsh|Bash）**：`gate_sample.py` 对**无台账样本**的分析类直读（xxd/strings/objdump…）exit 2 阻断并给出流程指引（建台账后放行，pcap 修头等合法开局已豁免）；`gate_explore.py` 熔断 heredoc/cat 落盘式探索——angr 禁项（无帧槽位/仿真证据不许上符号执行）、Cython 前置、变体枚举熔断（直指 model_diff.py）、30min ≥25 次探索且零 stuck 强制落账；`gate_longrun.py` 长任务强制落盘
- **PreToolUse（Pwsh|Bash|Write|Edit|Read）**：`gate_stuck.py` 卡点自述熔断——会话日志近 45min 内自述卡住（强措辞 1 次/弱措辞 ≥2 条）而台账零 stuck → exit 2 强制落账（判例 b781ff3c：4 次自述零落账，两个半边事实 30min 未接线，38min 零 exploit）；每 episode 只拦一次，无活跃台账不执勤
- **PreToolUse（Write）**：`gate_churn.py` 拟合熔断——目录 24h ≥8 个 .py 且活跃台账零 stuck → 逼 stuck 落账或升级 z3/emulate
- **Stop**：`stop_check.py` 收尾核对（默认启用，会话归属判定）——本会话台账有 observe 无下文 / flag 结论缺 program_accept / 存在 open hypothesis → deny 强制核对

安装：`dsh-hooks/` 拷到 `~/.dsh/hooks/`，在 profile 的 `cordis.patch.yml` 插入 hooks-claude-code 挂载条目（完整 YAML 与排障回滚见 `dsh-hooks/README.md`）。改动需**重启 dsh 服务 + 新开会话**生效。

## 许可与致谢

本仓库代码以 [MIT](LICENSE) 发布。衍生自以下来源，感谢原作者：

- [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc)（MIT，执行引擎）
- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT，方法论）
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse 知识库
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools)（ghidra_scripts 脚本集，现为 legacy 冻结层）
- [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)（Apache-2.0，Go/Rust/crypto 识别/JS 反调试知识片段）
- [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)（MIT：ctf-forensics → traffic-analysis 配方；ctf-pwn → pwn-exploit 知识配方库 18 篇 + pwntools 模板 5 件）
- [yaklang/hack-skills](https://github.com/yaklang/hack-skills) traffic-analysis-pcap（MIT，决策树骨架）
