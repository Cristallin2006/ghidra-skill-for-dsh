# ghidra-skill-for-dsh

Ghidra 12.x headless 自动化逆向 skill，适配 [dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)（DeepSeek Harness）。面向 CTF 逆向题、crackme、恶意样本分诊、固件分析，覆盖 PE / ELF / Mach-O / raw 固件。

融合三个开源项目的所长并做了 Windows + Ghidra 12.x 适配：

| 来源 | 取用 |
|---|---|
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | 阶段门闩方法论（Triage 硬门 / 时间盒 / IAT 修复铁律）、证据纪律 |
| [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) `skills/ctf/ctf-reverse` | 语言识别特征库、反分析 Check→Bypass 对照表、CTF 模式与 flag 狩猎启发式 |
| [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools) | 19 个 headless Jython 脚本与调用模型（已去 MCP 化，改为批量调用 + 结果落文件） |

原创新增：`triage_scan.py`（一键分诊报告）、`decompile_all.py`（批量导出伪码）、`run-headless.sh`（import / exec / exec-w 三命令封装）。

## 结构

```
ghidra-reverse/
├── SKILL.md                  # 路由层：六条铁律、四阶段工作流、脚本清单、语言路由表
├── references/
│   ├── headless.md           # analyzeHeadless 全参数、Windows 坑、项目缓存
│   ├── scripting.md          # Jython 脚本惯用法、事务、EmulatorHelper 仿真模板
│   ├── triage.md             # 分诊硬门、语言/壳识别、高危 API 组合、平台速查
│   ├── anti-analysis.md      # 反调试/反混淆/自校验识别与绕过
│   └── ctf-patterns.md       # CTF 模式库与 flag 狩猎启发式
└── scripts/                  # 21 个 Ghidra headless 脚本（Jython）+ run-headless.sh
```

## 环境要求

- Ghidra 12.x（12.1.3 实测通过）
- JDK 21+
- **Jython 扩展**：Ghidra 12.1 移除了内置 Jython，需把 `<GHIDRA_HOME>\Extensions\Ghidra\*_Jython.zip` 解压安装到**用户设置目录** `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\`（解到 Ghidra 安装目录下不生效）
- Windows + Git Bash（`run-headless.sh` 依赖；Linux/macOS 改路径亦可用）

## 安装

```bash
# dsh 的用户级 skill 根目录（filesystem provider 自动扫描，无需重启）
cp -r ghidra-reverse ~/.dsh/skills/
```

## 配置

`run-headless.sh` 默认 `GHIDRA_HOME=C:/t001s/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC`，用环境变量覆盖成你的安装路径（必须指向含 `support/` 的那层）：

```bash
export GHIDRA_HOME="D:/tools/ghidra_12.1.3_PUBLIC"
```

**Windows 注意**：Ghidra 的 `ProjectLocator` 拒绝任何以 `.` 开头的路径元素，因此工作区不能直接放在 `~/.dsh/` 下传给 JVM。`run-headless.sh` 会自动创建 junction `~/dsh-ghidra-workspace` → `~/.dsh/ghidra-workspace` 规避；手写裸 `analyzeHeadless` 命令时也要用无点的路径。

## 用法

```bash
SK=~/.dsh/skills/ghidra-reverse/scripts

# 导入 + 全量分析 + 一键分诊 → out/<名>.triage.json
bash $SK/run-headless.sh import /path/to/binary

# 批量导出全部函数伪码 → out/<名>.decompiled.c
bash $SK/run-headless.sh exec /path/to/binary decompile_all.py "@$HOME/dsh-ghidra-workspace/out/app.json"

# 单函数反编译 / xref / 字符串搜索……（读操作）
bash $SK/run-headless.sh exec /path/to/binary get_xrefs.py "@$HOME/dsh-ghidra-workspace/out/xrefs.json" 0x401000 both

# 写操作（重命名/注释/补丁）：用 exec-w，退出时自动保存项目
bash $SK/run-headless.sh exec-w /path/to/binary rename_symbol.py 0x401000 check_flag
```

脚本通用约定：首个参数 `@绝对路径` = 完整结果写文件（JSON），stdout 只留 `===JSON_START===/===JSON_END===` 状态摘要。函数定位支持 `0x地址` / 精确名 / 模糊子串三级查找。

## 设计要点

- **去 MCP 化**：原版依赖常驻 MCP server；本 skill 面向"每次调用都是 JVM 冷启动"的现实，规则是**一次调用批量做事 + 结果落文件**，项目缓存在 `projects/` 下复用（`-process -noanalysis`）
- **Triage 硬门**：未记录 imports + 语言/壳判定前不深挖；干净导入表（仅 kernel32/ntdll）触发动态加载警告
- **确认即标注**：函数搞清立即 rename + plate comment，结论必须带地址与可复现命令

## 许可与致谢

本仓库代码以 [MIT](LICENSE) 发布。衍生自以下来源，感谢原作者：

- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT）
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse 知识库
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools)（ghidra_scripts 脚本集）
