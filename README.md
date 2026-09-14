# ghidra-skill-for-dsh

Ghidra 12.x headless 自动化逆向 skill，适配 [dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)（DeepSeek Harness）。面向 CTF 逆向题、crackme、恶意样本分诊、固件分析，覆盖 PE / ELF / Mach-O / raw 固件。

脚本基于 **PyGhidra**（Ghidra 12.x 官方 Python 3 桥，经 JPype 起 JVM），由 `scripts/driver.py` 统一驱动——不依赖 Jython 扩展、不需要 Ghidra GUI、不需要 MCP server。

融合三个开源项目的所长并做了 Windows + Ghidra 12.x 适配：

| 来源 | 取用 |
|---|---|
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | 阶段门闩方法论（Triage 硬门 / 时间盒 / IAT 修复铁律）、证据纪律 |
| [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) `skills/ctf/ctf-reverse` | 语言识别特征库、反分析 Check→Bypass 对照表、CTF 模式与 flag 狩猎启发式 |
| [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools) | 19 个 headless 脚本与调用模型（去 MCP 化：批量调用 + 结果落文件；移植 PyGhidra） |

原创新增 6 个脚本：`triage_scan.py`（一键分诊报告）、`decompile_all.py`（批量导出伪码）、`exec_code.py`（任意 Ghidra API 逃生舱）、`export_binary.py`（headless 导出 patched 二进制）、`apply_c_types.py` / `apply_data_type.py`（C 语法定义 struct/enum 并套用）。

## 结构

```
ghidra-reverse/
├── SKILL.md                  # 路由层：铁律、四阶段工作流、脚本清单、语言路由、能力边界
├── references/
│   ├── headless.md           # driver.py 执行模型、Windows/PyGhidra 坑、ghidriff diff
│   ├── scripting.md          # PyGhidra 脚本惯用法、exec_code、事务、仿真模板
│   ├── triage.md             # 分诊硬门、语言/壳识别、高危 API 组合、平台速查
│   ├── anti-analysis.md      # 反调试/反混淆/自校验识别与绕过
│   └── ctf-patterns.md       # CTF 模式库与 flag 狩猎启发式
└── scripts/                  # 25 个 PyGhidra 脚本 + driver.py + analysis_config.py
```

## 环境要求

- Ghidra 12.x（12.1.3 实测通过）
- **JDK 21+**（必须 JDK 不是 JRE，JPype 起 JVM 需要）
- Python 3 + `pyghidra`（用 Ghidra 自带 wheel 离线安装即可：`pip install <GHIDRA_HOME>/GPL/pyghidra/dist/pyghidra-*.whl`，建议专用 venv）
- Windows + Git Bash（Linux/macOS 改路径亦可用）

## 安装

```bash
# dsh 的用户级 skill 根目录（filesystem provider 自动扫描，无需重启）
cp -r ghidra-reverse ~/.dsh/skills/
```

## 配置

`driver.py` 的环境变量（默认值是作者的部署，按需覆盖）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | `C:\t001s\...\ghidra_12.1.3_PUBLIC` | Ghidra 安装目录（含 `support/` 的那层） |
| `JAVA_HOME` / `PYGHIDRA_JAVA_HOME` | `C:\Java` | JDK 21+ 路径 |
| `DSH_GHIDRA_WS` | `~/.dsh/ghidra-workspace` | 工作区（projects/out/logs） |
| `DSH_GHIDRA_WS_LINK` | `~/dsh-ghidra-workspace` | 无 `.` 路径元素的 junction（见下） |

**Windows 注意**：Ghidra 的 `ProjectLocator` 拒绝任何以 `.` 开头的路径元素，所以 `~/.dsh/...` 不能直接传给 JVM——`driver.py` 会自动建/复用 junction `~/dsh-ghidra-workspace` 指向同一物理目录。

## 用法

```bash
PY=<pyghidra-venv>/Scripts/python.exe
SK=~/.dsh/skills/ghidra-reverse/scripts

"$PY" "$SK/driver.py" export /path/to/binary      # 建可复用项目（一次性，走 Ghidra 自带导入器）
"$PY" "$SK/driver.py" exec /path/to/binary triage_scan.py "@$HOME/dsh-ghidra-workspace/out/app.triage.json"
"$PY" "$SK/driver.py" exec /path/to/binary decompile_all.py "@$HOME/dsh-ghidra-workspace/out/app.json"
"$PY" "$SK/driver.py" exec-w /path/to/binary rename_symbol.py 0x401000 check_flag   # 写操作用 exec-w 才存盘
"$PY" "$SK/driver.py" exec /path/to/binary export_binary.py "@$HOME/dsh-ghidra-workspace/out/x.json" patched.exe
```

脚本通用约定：首个参数 `@绝对路径` = 完整结果写文件（JSON），stdout 只留 `===JSON_START===/===JSON_END===` 状态摘要。函数定位支持 `0x地址` / 精确名 / 模糊子串三级查找。

**清单内 25 个脚本不够用时**：写一个 Python payload 文件喂给 `exec_code.py`（预置 `program`/`fm`/`listing`/`find_function`/`output_json` 等 helper），不必为一次性逻辑新建脚本。

## 设计要点

- **去 MCP 化**：不依赖常驻 server；每次调用是 JVM 冷启动（10~60s），规则是**一次调用批量做事 + 结果落文件**，项目缓存在 `projects/` 复用
- **export / import 分工**：PyGhidra 无法持久化自己加载的程序（只读 DomainFileProxy），所以 `export` 走 Ghidra 自带 `analyzeHeadless -import` 建持久项目，`import` 只做进程内分析 + triage
- **Triage 硬门**：未记录 imports + 语言/壳判定前不深挖；干净导入表（仅 kernel32/ntdll）触发动态加载警告
- **确认即标注**：函数搞清立即 rename + plate comment，结论必须带地址与可复现命令
- **能力边界**：动态调试外包 Frida/GDB/Qiling/angr；二进制 diff 用 [ghidriff](https://github.com/clearbluejar/ghidriff)；协作式项目不做。详见 SKILL.md §8

## 许可与致谢

本仓库代码以 [MIT](LICENSE) 发布。衍生自以下来源，感谢原作者：

- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)（MIT）
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse 知识库
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools)（ghidra_scripts 脚本集）
