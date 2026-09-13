---
name: ghidra-reverse
description: 用 Ghidra 12.x headless 自动化做二进制逆向 —— CTF 逆向题、crackme、恶意样本分诊、固件分析。触发场景：逆向/反编译/反汇编/二进制分析/脱壳后分析/patch 二进制/批量分析/无 IDA 可用。覆盖 PE/ELF/Mach-O/raw 固件。
whenToUse: 收到未知二进制需要分诊、反编译、提取算法、批量 headless 分析或 patch 时；用户提到 Ghidra、逆向、crackme、CTF reverse 时
---

# Ghidra Reverse（dsh 版）

融合自三个来源，取长补短适配 dsh + Windows：
- `zhaoxuya520/reverse-skill`：阶段门闩方法论、证据纪律、Windows 工具链实战坑
- `wgpsec/AboutSecurity ctf-reverse`：CTF 知识库（语言识别、反分析、模式库）
- `und3rf10w/ai-ghidra-tools`：19+2 个 headless 脚本与调用模型（已修 Windows/12.x 兼容性）

## 0. 环境（本机已配好）

- `GHIDRA_HOME = C:\t001s\ghidra_12.1.3_PUBLIC_20260817\ghidra_12.1.3_PUBLIC`（含 `support/` 的内层目录）
- 运行方式：**PyGhidra**（`scripts/driver.py`）。GUI：`%GHIDRA_HOME%\ghidraRun.bat`
- **JDK 21+**（本机 `C:\Java`，Java 25），且必须是 JDK 而非 JRE——PyGhidra 通过 JPype 起 JVM
- **Python 环境**：`C:\Users\Lenovo\Desktop\src\ghidra-bridge\pyghidra-venv`（pyghidra 3.1.0 + JPype1 1.5.2，从 Ghidra 自带 wheel 离线装好）。调用时用该 venv 的 `Scripts\python.exe`
- 工作区：`~/.dsh/ghidra-workspace/`（`projects/` 项目缓存、`out/` 产物、`logs/` 日志）
- **传给 Ghidra 的路径必须走 junction `~/dsh-ghidra-workspace`**：Ghidra 的 `ProjectLocator` 拒绝任何以 `.` 开头的路径元素（`~/.dsh/...` 会 abort）。`driver.py` 的 `project_root()` 自动建/复用该 junction，物理位置不变

### 为什么不是 Jython / analyzeHeadless

Ghidra 12.1.3 **没有** Jython 扩展可用，且 `analyzeHeadless.bat` 起的是普通 JVM，遇到 `.py` 脚本会直接失败：

```
ghidra.app.script.JythonStubScriptProvider$JythonStubException:
  In order to use Jython based scripts, you must install the Jython Ghidra Extension,
  or (recommended) port your script to PyGhidra or Java.
```

把 `@runtime Jython` 的脚本交给 PyGhidra 启动器又会得到 `Ghidra was not started with PyGhidra. Python is not available`。因此**全部 21 个脚本已移植为 `@runtime PyGhidra`，并统一由 `driver.py` 启动**（`run-headless.sh` 已废弃，见 §2）。移植后实测 20/21 可跑，剩余差异见 §7。

## 1. 六条铁律（先读这个再动手）

1. **一次调用，批量做事**：每次启动 = JVM 冷启动 + 项目加载（10~60 秒）。禁止"一个函数一次调用"的交互式节奏——用 `triage_scan.py` / `decompile_all.py` 一把出，或写一个组合脚本一次完成 N 件事。
2. **导入分析一次做足**：`driver.py import` 只做一次全量分析；之后一律 `driver.py exec`（PyGhidra 无 `-noanalysis` 概念，脚本阶段不会重跑分析）。
3. **大输出落文件**：所有脚本约定首个参数 `@绝对路径` = 完整结果写该文件（JSON/文本），stdout 只留状态行。agent 用 Read 读文件，不要从 stdout 抠大输出。
4. **Triage 硬门**：未记录 imports（DLL/SYS 还要 exports）+ 语言/壳判定之前，MUST NOT 进入深挖或动态分析。导入表只有 kernel32/ntdll 且极少 → 高度怀疑 `LoadLibrary`+`GetProcAddress` 动态加载，禁止宣称"无网络/无文件能力"。
5. **确认即标注**：搞清一个函数立即 `rename_symbol.py` 改成语义名 + `add_comment.py` 写 plate comment（地址/作用/依据）。结论必须带地址和可复现命令。写操作后需 `exec-w` 才会存盘。
6. **时间盒**：静态深挖 ~15 分钟无关键路径 → 转动态（Frida/GDB/Qiling/angr，选型见 `references/ctf-patterns.md`）；同一路径失败 2 次 → 换工具，禁止空转。

## 2. 快速上手（3 行）

```bash
PY="C:/Users/Lenovo/Desktop/src/ghidra-bridge/pyghidra-venv/Scripts/python.exe"
SK="$HOME/.dsh/skills/ghidra-reverse/scripts"

# 导入 + 全量分析 + 一键分诊 → out/<名>.triage.json
"$PY" "$SK/driver.py" import /path/to/binary

# 批量导出函数伪码 → @out 指向的 .json 及其同名 .c
"$PY" "$SK/driver.py" exec /path/to/binary decompile_all.py \
    "@C:/Users/you/.dsh/ghidra-workspace/out/app.json"

# 写操作（重命名、注释、打补丁）要落盘时用 exec-w
"$PY" "$SK/driver.py" exec-w /path/to/binary rename_symbol.py 0x401000 check_flag
```

子命令：`import [--force]` / `exec` / `exec-w`（存盘）/ `list`。
项目名按二进制 SHA-256 前 16 位固定为 `dsh_<hash>`，与二进制路径无关。

需要 GUI 深挖（图形化 CFG、手动 patch 导出）时跑 `ghidraRun.bat`，打开 `~/.dsh/ghidra-workspace/projects/` 里的同名项目——headless 标注全部已保存。

## 3. 工作流（四阶段）

### 阶段 1 — Triage（5~15 分钟，强制起点）
`driver.py import` 自动执行 `triage_scan.py`，产出：元数据、按库分组的 imports/exports/entry points、可疑 API 命中（反调试/注入/加密/网络/持久化/动态加载六组）、干净 IAT 警告、字符串快赢（flag|pass|correct…）、语言启发（Go/Rust/.NET/Python/UPX）。

手工补充（详情 `references/triage.md`）：`file` / `checksec` / DIE 查壳；`strings -el` 补宽字符；PE 查 TLS 回调目录（先于 main 执行）。

### 阶段 2 — Recon（静态锚点）
- `search_strings.py "@out" 4 "flag|correct"`：字符串 + 引用者 xref 反查
- `get_symbols.py "@out" imports|exports|all`；`get_memory_map.py "@out"`
- `list_functions.py "@out" [regex] [limit:N] [offset:N]`：分页列函数
- 从可疑字符串/API 的 xref 反查调用者 → 锁定 `main` / check 函数

### 阶段 3 — Analysis
- `decompile_function.py "@out" <函数名|0x地址>`；大函数/批量用 `decompile_all.py`
- `get_xrefs.py "@out" <目标> both` / `get_call_graph.py "@out" <函数> recursive 3` 追数据流
- `search_bytes.py "@out" "48 8d ?? ??"`：字节模式搜索（支持 `??` 与半字节 `4?` 通配）
- 命中具体模式 → 查 `references/ctf-patterns.md`（已知明文 XOR、.rodata 期望值、比较函数即 oracle、自定义 VM 五步法、魔数表…）
- 命中反调试/混淆 → 查 `references/anti-analysis.md`（识别清单、Check→Bypass 对照、OLLVM 分层）
- 自定义解密 stub 不想脱壳 → EmulatorHelper 仿真模板见 `references/scripting.md` §仿真
- 反编译结果看不懂 → 换视角（dogbolt.org 多反编译器对比）或直接看 `get_disassembly.py` 汇编

### 阶段 4 — Annotate / Patch / 交付
- 写操作落盘用 `exec-w`：`driver.py exec-w <bin> rename_symbol.py 0x401000 check_flag`
  （`add_comment.py` 类型：eol/pre/post/plate/repeatable；`set_function_signature.py` 改原型）
- `patch_bytes.py "@out" 0x401050 "74"`（JZ↔JNZ 类 patch）；**导出 patched 二进制走 GUI**：File → Export Program → Original File
- 交付纪律：报告含 范围 / 证据（地址+复现命令）/ 结论 / 产物路径+SHA256。未经证据支撑的否定结论（"无网络能力"）禁止出现。

## 4. 裸命令模板（排障时才需要；日常用 `driver.py`）

```bash
PY="C:/Users/Lenovo/Desktop/src/ghidra-bridge/pyghidra-venv/Scripts/python.exe"
GH="C:/t001s/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC"
WS="$HOME/dsh-ghidra-workspace"   # junction → ~/.dsh/ghidra-workspace；Ghidra 拒绝含 . 的路径元素，必须用 junction

export GHIDRA_INSTALL_DIR="$GH"
export JAVA_HOME="C:/Java"

# 首次：导入 + 全量分析 + 分诊（项目名 dsh_<sha256前16>）
"$PY" -m pyghidra --project-path "$WS/projects" --project-name dsh_<hash> \
  "C:/abs/path/binary.exe" "$SK/triage_scan.py" "@$WS/out/binary.exe.triage.json"

# 注意：pyghidra CLI 只接受 **一个** 脚本位置参数，脚本参数必须紧跟其后；
# 再多一个位置参数会被当成第二个脚本路径。复杂调用请直接用 driver.py，
# 它走 pyghidra.ghidra_script(path, project, program, script_args=[...]) 这个稳定 API。
```

`analyzeHeadless.bat` 仍然可用，但**只能跑 `@runtime` 不是 PyGhidra 的脚本（即 `.java`）**；对 `.py` 会报 Jython 缺失。全部参数细节与 Windows 坑 → `references/headless.md`。

## 5. 脚本清单（`scripts/`，PyGhidra，Ghidra 进程内运行）

通用约定：`[@out文件]` 恒为第一个参数；函数定位支持 `0x地址` / 精确名 / 模糊子串三级查找。

| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `triage_scan.py` | 一键分诊报告（本 skill 入口） | — |
| `analyze_binary.py` | 程序元数据握手 | — |
| `decompile_all.py` | 批量导出全函数伪码到 `.c` | `[regex] [超时秒]` |
| `decompile_function.py` | 单函数伪码 + 局部变量 | 函数 |
| `get_disassembly.py` | 反汇编（函数/地址范围） | 起点, [终点], [上限500] |
| `list_functions.py` | 列函数（过滤+分页） | [regex], limit:N, offset:N |
| `search_strings.py` | 字符串 + 引用者 | [最小长], [regex] |
| `search_bytes.py` | 字节模式搜索（通配符） | pattern, [上限], [起], [止] |
| `get_xrefs.py` | 交叉引用 to/from/both | 地址/函数, [方向] |
| `get_call_graph.py` | caller/callee 树 | 函数, [recursive], [深度2] |
| `get_basic_blocks.py` | 函数 CFG 基本块 | 函数 |
| `get_memory_map.py` | 内存段/地址空间 | — |
| `get_data_at_address.py` | 按类型读内存 | 地址, 长度/类型, [格式] |
| `get_symbols.py` | 导入/导出/入口点 | imports/exports/all |
| `list_classes.py` | C++ 类/vtable 启发式 | [过滤子串] |
| `emulate_function.py` | P-code 仿真执行 | 函数, 寄存器JSON, 内存JSON, [步数] |
| `rename_symbol.py` ✎ | 重命名 | 地址/旧名, 新名 |
| `add_comment.py` ✎ | 加注释 | 地址, 文本, [类型] |
| `set_function_signature.py` ✎ | 改函数签名 | 函数, 签名… |
| `patch_bytes.py` ✎ | 写内存字节 | 地址, hex串 |
| `set_analysis_options.py` | preScript：关重型分析器（⚠ PyGhidra 流程下不生效，见 §7.9） | minimal |

✎ = 写操作：用 `exec-w`（不带 `-readOnly`）才会保存。写自定义脚本看 `references/scripting.md`。

## 6. 语言/平台路由（识别到就换打法，别硬上通用流程）

| 识别特征（triage_scan 自动报） | 走向 |
|---|---|
| `go.buildid` / `runtime.gopanic` / 巨大静态二进制 | 先跑 GoReSym 恢复符号（stripped 也行）→ 只看 `main.*` 包函数；Go string 是 {ptr,len} 非 NUL 结尾，Ghidra 默认字符串分析会漏，装 golang-loader 插件或靠 xref |
| `panicked at` / `_ZN` mangling / `.rustc` section | `strings \| grep panicked` 先挖源码路径行号；`rustfilt`  demangle；泛型单态化 → 从字符串 xref 入手而非逐个函数 |
| `mscoree.dll` / `_CorExeMain` | **离开 Ghidra**：dnSpyEx + de4dot；例外：NativeAOT / IL2CPP 是 native，留在 Ghidra |
| PyInstaller / Pyarmor 特征 | 先解包（pyinstxtractor / Pyarmor-Static-Unpack）再分析 pyc；opcode 重映射时 decompiler 报错即信号 |
| UPX 节名 | `upx -d`；失败说明元数据被篡改，按 UPX 源码手工修头再解 |
| 自定义壳 / 熵高 | 断 unpack stub 后 dump，或不脱壳用 EmulatorHelper 仿真解密（模板见 scripting.md） |
| APK 里的 .so | 优先选 x86_64 版本，Ghidra 反编译质量最好；JNI 找不到符号 → 查 `JNI_OnLoad` 的 `RegisterNatives` 方法表 |
| WASM / pyc / Mach-O / 内核 .ko / 固件 | 见 `references/triage.md` §平台速查 |
| PE DOS stub 异常大 | 查 DOS stub 藏代码（`int 16h`），Windows 题常见 |

## 7. PyGhidra 移植须知（踩过的坑，2026-09 实测）

移植把 21 个脚本从 `@runtime Jython` 改成 `@runtime PyGhidra`。语法层面几乎零成本（实测无 `xrange`/`iteritems`/`has_key`/`except X, e`，仅 `search_bytes.py` 用了 Jython 独有模块）。真正的坑都在**启动方式**和**API 形状**上：

1. **`.py` 脚本不能交给 `analyzeHeadless`**：那会起普通 JVM，报 `JythonStubScriptProvider` 缺 Jython。必须通过 PyGhidra 启动器。
2. **`pyghidra.start()` 必须在任何 `ghidra.*` import 之前**：否则 `ModuleNotFoundError: No module named 'ghidra'`。`driver.py` 的 `main()` 里处理。
3. **`pyghidra` CLI 的位置参数很窄**：`binary_path script_path script_args...`，且只接受**一个**脚本位置参数；多给一个会被当第二个脚本路径。传 `@out` 这类参数要用 `driver.py`（走 `pyghidra.ghidra_script(..., script_args=[...])`）。
4. **`program_loader().load()` 返回的是 `LoadResults` 而不是 `Program`**：要 `results.getPrimaryDomainObject()`，并且 `LoadResults` 是 `AutoCloseable`，用 `close()` 释放。
5. **`walk_programs(project, callback, ...)` 是回调式**，不是可迭代对象。它会在**自己的 program 上下文里**打开每个程序，所以不要在回调里长期持有 `program`。
6. **`open_project(path, name, create)`**：path 是**父目录**，不是 `.gpr` 文件；`ProjectLocator` 拒绝含 `.` 的路径元素（所以走 junction）。
7. **`currentProgram` / `getScriptArgs()` 仍然可用**：PyGhidra 的脚本 globals 用 `__missing__` 从 `GhidraScript` 实例懒取属性，所以老脚本不用改成显式 `getCurrentProgram()`。
8. **字符串类型更友好**：Java String 到 Python 是真正的 `str`（实测 `type(...).__name__ == 'str'`），`json.dumps` 不需要手动转换。构 Java `byte[]` 用 `jpype.JArray(jpype.JByte)`（Jython 的 `from jarray import array` 不存在）。
9. **Jython 的 `-preScript` 没有对应物**：`set_analysis_options.py` 设计上在分析**前**运行；PyGhidra 的 `analyze()` 不接受预脚本，所以该脚本当前**无法在 driver 流程里生效**（它本身也不产生 `@out` marker，属预期）。要关重型分析器请在 GUI Project Settings 里改，或直接调 `pyghidra.analysis_properties(program)`。

### 实测覆盖（对 AegisTrace 的 stripped ELF，96 函数）

**可直接用**：`triage_scan` `analyze_binary` `get_memory_map` `get_symbols` `list_functions` `decompile_function` `decompile_all` `get_disassembly` `get_xrefs` `get_call_graph` `get_basic_blocks` `search_strings` `get_data_at_address` `list_classes` `emulate_function` `add_comment` `set_function_signature` `search_bytes`（用地址或符号名目标）

**两个已知限制**（都不是移植问题）：
- `patch_bytes.py` → `Memory block is not writable: .text`。PyGhidra 下程序以只读方式打开，写内存需要先取得可写事务/权限。
- `rename_symbol.py` → 需要**符号名或函数入口**，传裸函数地址会报 `Symbol not found`。先 `list_functions.py` 拿名字，或用入口地址。

## 8. References（按需加载，别一次全读）

| 文件 | 何时读 |
|---|---|
| `references/headless.md` | 要调参数、排障、理解项目缓存机制时 |
| `references/scripting.md` | 要写自定义 Ghidra 脚本（Jython/PyGhidra 惯用法、事务、仿真模板） |
| `references/triage.md` | 分诊细节：语言识别特征、壳检测、高危 API 组合、平台速查 |
| `references/anti-analysis.md` | 命中反调试/反混淆/自校验时的识别与绕过对照表 |
| `references/ctf-patterns.md` | CTF 模式库与 flag 狩猎启发式（XOR/期望值/oracle/自定义 VM/魔数） |
