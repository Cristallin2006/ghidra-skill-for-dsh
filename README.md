# ghidra-skill-for-dsh

Ghidra 12.x headless 自动化逆向 skill 集，适配 [dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)（DeepSeek Harness）。面向 CTF 逆向题、crackme、恶意样本分诊、固件分析、漏洞预筛，覆盖 PE / ELF / Mach-O / raw 固件。

执行引擎是 **ghidra-rpc 常驻 daemon**（vendor 自 [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc) 0.2.0 + dsh 补丁，见 `ghidra-core/engine/VENDOR.md`）：一次启动常驻 JVM，之后每条命令 ~0.2s——不依赖 Jython 扩展、不需要 Ghidra GUI、不需要 MCP server。

## 结构（1 底座 + 4 场景）

```
ghidra-core/     # 底座：怎么执行（唯一放代码的地方）
├── SKILL.md             # 环境、六条铁律、快速上手、三层能力清单、移植坑、能力边界
├── engine/ghidra-rpc/   # vendored 引擎源码 + dsh 补丁（VENDOR.md 跟踪）
├── scripts/             # rpc_driver.py（统一入口）/ doctor.py / launch_gui.py + legacy 冻结脚本
└── references/          # headless.md（执行模型）、scripting.md（脚本惯用法）

re-triage/       # 场景 1：这是什么？——判文件类型/语言/壳/威胁面，决定路线
├── SKILL.md             # Triage 硬门、分诊流程、语言/平台路由表
└── references/          # triage.md（分诊细则）、anti-analysis.md（反分析对照）

re-unpack/       # 场景 2：脱壳——检出壳后的唯一下一站（脱壳+强制验证+失败阶梯）
├── SKILL.md             # 选型表（壳→工具 tier）、验证三件套、防死循环专节
└── references/          # unpack-playbook.md（多层壳/IAT 重建/各壳对策）

ghidra-static/   # 场景 3：深挖它——反编译/xref/标注/patch/交付
├── SKILL.md             # Recon/Analysis/Annotate/Patch 工作流、交付纪律
└── references/          # ctf-patterns.md（CTF 模式库与 flag 狩猎）

vuln-audit/      # 场景 4：它有没有病？——漏洞模式 checklist
├── SKILL.md             # 审计流程、可达性优先纪律
└── references/          # vuln-patterns.md（8 类漏洞模式：信号/命令/判定/误报）
```

边界规则：代码只在 ghidra-core；场景 skill 只有方法论，命令细节一律指针回 ghidra-core；知识不重复、路由互斥。

## 安装

1. 五个目录全部拷到 `~/.dsh/skills/`：`ghidra-core`、`re-triage`、`re-unpack`、`ghidra-static`、`vuln-audit`
2. 建引擎 venv（Python ≥ 3.11）并 editable 安装引擎：
   ```bash
   python3.12 -m venv ~/Desktop/src/ghidra-bridge/ghidra-rpc-venv
   ~/Desktop/src/ghidra-bridge/ghidra-rpc-venv/Scripts/python.exe -m pip install \
       -e ~/.dsh/skills/ghidra-core/engine/ghidra-rpc
   ```
3. 脱壳工具（re-unpack 用；不需要脱壳可跳过）：
   ```bash
   python3.12 -m venv ~/Desktop/src/unpacker-venv
   ~/Desktop/src/unpacker-venv/Scripts/python.exe -m pip install -e <Unpacker 克隆路径>
   # UPX 原生二进制：https://github.com/upx/upx/releases（win64 zip）解压到 ~/Desktop/src/tools/upx/
   ```
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
- **1+4 拆分**：执行（core）与方法论（triage/static/audit）解耦，场景 skill 零代码
- **Triage 硬门**：未记录 imports + 语言/壳判定前不深挖；干净导入表触发动态加载警告
- **确认即标注**：函数搞清立即 rename + plate comment，结论必须带地址与可复现命令
- **能力边界**：动态调试外包 Frida/GDB/Qiling/angr；协作式项目不做。详见 ghidra-core/SKILL.md §8

## 许可与致谢

本仓库代码以 [MIT](LICENSE) 发布。衍生自以下来源，感谢原作者：

- [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc)（MIT，执行引擎）
- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT，方法论）
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse 知识库
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools)（ghidra_scripts 脚本集，现为 legacy 冻结层）
