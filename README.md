# ghidra-skill-for-dsh

Ghidra 12.x headless 自动化逆向 skill 集，适配 [dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)（DeepSeek Harness）。面向 CTF 逆向题、crackme、恶意样本分诊、固件分析、漏洞预筛，覆盖 PE / ELF / Mach-O / raw 固件。

执行引擎是 **ghidra-rpc 常驻 daemon**（vendor 自 [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc) 0.2.0 + dsh 补丁，见 `ghidra-core/engine/VENDOR.md`）：一次启动常驻 JVM，之后每条命令 ~0.2s——不依赖 Jython 扩展、不需要 Ghidra GUI、不需要 MCP server。

## 实测性能

> 同一道 CTF 逆向题（UPX 壳 + 换表 base64 + RC4，ctf.show `encode`）：**调校前 40 分钟做不出（且交付错误结论）→ 调校后 16 分钟解出**。提速来自机制而非模型——每次实战踩坑都被固化成铁律 + 脚本闸门（见下表）。

| 优化 | 解决的问题 | 载体 |
|---|---|---|
| 常驻 daemon | analyzeHeadless 每次冷启动 JVM，单命令半分钟 → **~0.2s** | `rpc_driver.py` + engine |
| Triage 多信号壳判定 | 只查节名 "UPX"，改节名即漏报 | 节名 + `UPX!` magic + 结构特征三信号交叉 |
| 死循环断路器（铁律 7） | 同一地址区间肉眼↔脚本横跳几十轮 | `ledger.py`：同区回访强制 `--delta`，答不出 exit 2；结论写入即锁定 |
| 权威读数（铁律 8） | 反编译器渲染吞前导 0、手工转录错长度 | `read_views.py`：三视图 + `--expect-len`/`--expect-hex` 对照 |
| 求逆闸门（铁律 9） | 跨缓冲区误读（28 字节读成 49 字符）后带病求逆 | `crypto_sanity.py`：hex 奇数 / base64 非 4 倍数 / 流密码不等长 → exit 2 |
| 验证独立性（铁律 10） | 用自己 patch 的进程+自写 harness 验证自己的理解 | `ledger.py conclude` 强制 `--source`/`--independent`，无独立来源标 ⚠UNVERIFIED |
| 函数级 Oracle | "跑起来看"缺失，求逆靠脑推 | `oracle.py`（qiling）：单函数真实调用 + `--break`/`--dump` 抓中间态，x86-64/i386 |
| 脱壳域 | packed 字节上死磕 30+ 轮 | re-unpack：upx / upx_repair.py（改头 UPX）/ unpacker + 强制验证三件套 |
| Go stripped 识别 | 字符串扫描在 stripped Go 二进制上漏报 | triage 补 buildinfo magic（`\xff Go buildinf:`）内存字节扫描兜底，实测 Go 1.26 stripped PE 命中 |

## 结构（1 底座 + 6 场景）

```
ghidra-core/     # 底座：怎么执行（唯一放代码的地方）
├── SKILL.md             # 环境、十条铁律、快速上手、三层能力清单、移植坑、能力边界
├── engine/ghidra-rpc/   # vendored 引擎源码 + dsh 补丁（VENDOR.md 跟踪）
├── scripts/             # rpc_driver.py（统一入口）/ doctor.py / launch_gui.py
│                        # + 三道闸门：ledger.py（断路器）/ read_views.py（权威读数）/ crypto_sanity.py（求逆闸门）
│                        # + legacy 冻结脚本
└── references/          # headless.md（执行模型）、scripting.md（脚本惯用法）、evidence-ledger.md（台账机制）
                         # crypto-ident.md（加密算法识别：常量指纹/API 对照/弱点清单，铁律 9 上游）

re-triage/       # 场景 1：这是什么？——判文件类型/语言/壳/威胁面，决定路线
├── SKILL.md             # Triage 硬门、分诊流程、语言/平台路由表
└── references/          # triage.md（分诊细则）、anti-analysis.md（反调试/反混淆/反 VM 对照）

re-unpack/       # 场景 2：脱壳——检出壳后的唯一下一站（脱壳+强制验证+失败阶梯）
├── SKILL.md             # 选型表（壳→工具 tier）、验证三件套、防死循环专节
├── scripts/             # upx_repair.py（UPX 头篡改修复）
└── references/          # unpack-playbook.md（多层壳/IAT 重建/各壳对策）

ghidra-static/   # 场景 3：深挖它——反编译/xref/标注/patch/交付
├── SKILL.md             # Recon/Analysis/Annotate/Patch 工作流、交付纪律
└── references/          # ctf-patterns.md（CTF 模式库与 flag 狩猎）
                         # go-binary.md（pclntab/buildinfo 指纹、garble/GoResolver）
                         # rust-binary.md（panic 路径=源码地图、crate 依赖还原）

vuln-audit/      # 场景 4：它有没有病？——漏洞模式 checklist
├── SKILL.md             # 审计流程、可达性优先纪律
└── references/          # vuln-patterns.md（8 类漏洞模式：信号/命令/判定/误报）

re-dynamic/      # 场景 5：跑起来看——直接运行/函数级 Oracle/动态插桩入口
├── SKILL.md             # 先跑起来看纪律、oracle.py 用法与边界、升级阶梯
├── scripts/             # oracle.py（qiling 后端的函数级 Oracle，WSL 运行）
└── references/          # js-antidebug.md（JS 混淆分类/反调试中和模板/vm 沙箱脱 eval 链）

traffic-analysis/ # 场景 6：流量里找信号——pcap 分诊/隧道/隐信道/USB HID/WiFi/TLS
├── SKILL.md             # 开局三连、路由表（分诊发现→配方）、证据落账、时间盒
├── scripts/             # 全零依赖（Python stdlib）：pcap_triage.py（协议分布+路由 hint，
│                        # 占比 >60% exit 2）/ hid_keyboard.py / mouse_render.py /
│                        # dnscat2_reassemble.py / timing_decode.py
└── references/          # pcap-triage.md（修头/文件提取/凭据）、tunnels.md（DNS/ICMP/时序
                         # 隐信道 + 元数据直方图方法论）、usb-hid.md、wifi-tls.md
```

边界规则：执行代码在 ghidra-core（脱壳/动态域脚本归 re-unpack/re-dynamic 自管）；场景 skill 只有方法论，命令细节一律指针回 ghidra-core；知识不重复、路由互斥。**知识片段的形态纪律：存储 = references/ 下可 grep 的纯数据文件，路由 = 消费它的 skill 在触发点写一行指针——不新建"知识库 skill"**（agent 不知道自己不知道什么，无触发点的知识库会被闲置）。

## 安装

1. 七个目录全部拷到 `~/.dsh/skills/`：`ghidra-core`、`re-triage`、`re-unpack`、`ghidra-static`、`vuln-audit`、`re-dynamic`、`traffic-analysis`（traffic-analysis 独立可选——不用流量分析可以不拷）
2. 建引擎 venv（Python ≥ 3.11）并 editable 安装引擎：
   ```bash
   python3.12 -m venv ~/Desktop/src/ghidra-bridge/ghidra-rpc-venv
   ~/Desktop/src/ghidra-bridge/ghidra-rpc-venv/Scripts/python.exe -m pip install \
       -e ~/.dsh/skills/ghidra-core/engine/ghidra-rpc
   ```
3. 工具层：**完整清单与安装步骤见 [TOOLCHAIN.md](TOOLCHAIN.md)**（Ghidra 引擎栈 / Windows CLI 双 venv / tools\ 绿色软件 / WSL Ubuntu / Ghidra 插件 / 未装项）。三层分级：Tier A 轻量高频全装、Tier B 重 pip 或 WSL、Tier C GUI/插件。是否已装以 `doctor.py` 的 toolchain 节为机器可读真相源。
4. 设 `GHIDRA_INSTALL_DIR`（Ghidra 12.x 安装目录，含 `support/` 那层）与 `JAVA_HOME`（JDK 21+）
5. 自检：`python ~/.dsh/skills/ghidra-core/scripts/doctor.py`（8 项全绿 exit 0）

| 环境变量 | 示例 | 含义 |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | `C:\t001s\...\ghidra_12.1.3_PUBLIC` | Ghidra 安装目录 |
| `JAVA_HOME` | `C:\Java` | JDK 21+ |
| `DSH_GHIDRA_WS` | `~/.dsh/ghidra-workspace` | 工作区（projects/out/logs） |

**Windows 注意**：Ghidra 的 `ProjectLocator` 拒绝任何以 `.` 开头的路径元素，`~/.dsh/...` 不能直接传给 JVM——底座自动走 junction `~/dsh-ghidra-workspace`（engine 已打不解析 junction 的补丁）。

## 用法（30 秒）

```bash
SK=~/.dsh/skills/ghidra-core/scripts

python "$SK/rpc_driver.py" ensure /path/to/binary          # daemon 起停 + 导入分析（幂等）
python "$SK/rpc_driver.py" triage /path/to/binary          # 一键分诊
python "$SK/rpc_driver.py" decompile /path/to/binary main  # 反编译
python "$SK/rpc_driver.py" rename-function /path/to/binary FUN_00401000 check_flag
python "$SK/rpc_driver.py" version-track old.exe new.exe --changed-only
```

结果约定：`@绝对路径` 作为首个参数 = 完整 JSON 落盘；写操作即刻生效并自动存盘。完整命令清单见 `ghidra-core/SKILL.md` §5。

## 设计要点

- **常驻 daemon**：JVM 只起一次，温热后每条命令亚秒级；`load`（大文件导入分析）和 `version-track`（全函数关联）是仅有的长任务，用 run_in_background + `@out` 落盘
- **1+6 拆分**：执行（core）与方法论（triage/unpack/static/audit/dynamic/traffic）解耦，场景 skill 原则上零代码（traffic-analysis 例外：工具链完全不同，自带零依赖 stdlib 脚本，不污染 Ghidra 底座）
- **Triage 硬门**：未记录 imports + 语言/壳判定前不深挖；干净导入表触发动态加载警告；壳判定三信号交叉（节名/magic/结构）
- **确认即标注**：函数搞清立即 rename + plate comment，结论必须带地址与可复现命令
- **机械闸门，不靠自觉**：文字纪律管不住的手由脚本拦——`ledger.py`（同区回访强制 `--delta`、结论写入即锁定、来源强制标注）、`read_views.py`（渲染文本与真实字节对照）、`crypto_sanity.py`（求逆前后合法性检查），违规一律 exit 2
- **验证独立性**：patch 态只能探索控制流，禁止验证数据模型；自建 harness 先过已知答案自检；否定性结论必须先正向复现已知输出——灵感来自 Google P0 Naptime 的 Perfect Verification 原则
- **能力边界**：动态调试外包 Frida/GDB/Qiling/angr；协作式项目不做。详见 ghidra-core/SKILL.md §8

## 许可与致谢

本仓库代码以 [MIT](LICENSE) 发布。衍生自以下来源，感谢原作者：

- [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc)（MIT，执行引擎）
- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT，方法论）
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse 知识库
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools)（ghidra_scripts 脚本集，现为 legacy 冻结层）
- [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)（Apache-2.0，Go/Rust/crypto 识别/JS 反调试知识片段的提炼来源，已剔除 SOC/IOC 向内容）
- [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) ctf-forensics（MIT，traffic-analysis 的 network/tunnel/USB HID 配方提炼来源，赛题出处随方保留）
- [yaklang/hack-skills](https://github.com/yaklang/hack-skills) traffic-analysis-pcap（MIT，traffic-analysis 决策树骨架参考）
