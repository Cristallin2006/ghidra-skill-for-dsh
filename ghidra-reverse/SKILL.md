---
name: ghidra-reverse
description: 用 Ghidra 12.x headless 自动化做二进制逆向 —— CTF 逆向题、crackme、恶意样本分诊、固件分析。触发场景：逆向/反编译/反汇编/二进制分析/脱壳后分析/patch 二进制/批量分析/无 IDA 可用。覆盖 PE/ELF/Mach-O/raw 固件。
whenToUse: 收到未知二进制需要分诊、反编译、提取算法、批量 headless 分析或 patch 时；用户提到 Ghidra、逆向、crackme、CTF reverse 时
---

# Ghidra Reverse（dsh 版）

融合自三个来源，取长补短适配 dsh + Windows：
- `zhaoxuya520/reverse-skill`：阶段门闩方法论、证据纪律、Windows 工具链实战坑
- `wgpsec/AboutSecurity ctf-reverse`：CTF 知识库（语言识别、反分析、模式库）
- `und3rf10w/ai-ghidra-tools`：19 个 headless 脚本与调用模型（已移植 PyGhidra 并修 Windows/12.x 兼容性）；本 skill 另新增 6 个：`triage_scan`/`decompile_all`/`exec_code`/`export_binary`/`apply_c_types`/`apply_data_type`

## 0. 环境（本机已配好）

- `GHIDRA_HOME = C:\t001s\ghidra_12.1.3_PUBLIC_20260817\ghidra_12.1.3_PUBLIC`（含 `support/` 的内层目录）
- 运行方式：**PyGhidra**（`scripts/driver.py`）。GUI：`%GHIDRA_HOME%\ghidraRun.bat`
- **JDK 21+**（本机 `C:\Java`，Java 25），且必须是 JDK 而非 JRE——PyGhidra 通过 JPype 起 JVM
- **Python 环境**：`$HOME/Desktop/src/ghidra-bridge/pyghidra-venv`（pyghidra 3.1.0 + JPype1 1.5.2，从 Ghidra 自带 wheel 离线装好）。调用时用该 venv 的 `Scripts/python.exe`
- 工作区：`~/.dsh/ghidra-workspace/`（`projects/` 项目缓存、`out/` 产物、`logs/` 日志）
- **传给 Ghidra 的路径必须走 junction `~/dsh-ghidra-workspace`**：Ghidra 的 `ProjectLocator` 拒绝任何以 `.` 开头的路径元素（`~/.dsh/...` 会 abort）。`driver.py` 的 `project_root()` 自动建/复用该 junction，物理位置不变

### 为什么不是 Jython / analyzeHeadless（重要：原设计其实没错）

**Jython 扩展本身是装好的**，就在 `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\Jython`（内含 `jython-2.7.4\Lib`）。用 GUI（`ghidraRun.bat`，不重定向 APPDATA）跑，原本的 `@runtime Jython` 脚本是能用的。

真正的坑是 **APPDATA 重定向**：为了满足 DSH 的文件沙箱（只允许写工作区），插件和 driver 都把 `APPDATA`/`LOCALAPPDATA`/`USERPROFILE`/`TMP` 指到工作区内的 settings 目录。Ghidra 于是去 `<被重定向的 settings>\ghidra\ghidra_12.1.3_PUBLIC\Extensions\` 找扩展——**那里没有 Jython**，于是报：

```
ghidra.app.script.JythonStubScriptProvider$JythonStubException:
  In order to use Jython based scripts, you must install the Jython Ghidra Extension,
  or (recommended) port your script to PyGhidra or Java.
```

一句话：**不是 skill 的脚本有问题，是重定向把一个已装好的扩展藏起来了**。两个可选解法：

- **想用 Jython**：在被重定向的 settings 目录下建 junction 指到真实扩展
  `mklink /J <redirected>\...\Extensions\Jython %APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\Jython`
  （实测可行；但 PyGhidra 流程下仍不建议回退，见下）
- **继续用 PyGhidra**（当前选择）：不依赖扩展、脚本是真正的 Python 3、错误信息更清楚。代价是要过下面的启动/API 关口。

另外注意：**PyGhidra 启动器下 `analyzeHeadless` 完全不可用**——把 `.py` 交给它会得到 `Ghidra was not started with PyGhidra. Python is not available`。所以一旦选 PyGhidra，就必须整条链走 `driver.py`。

上游 19 个 + 本 skill 早期的 `triage_scan`/`decompile_all` 共 21 个脚本已全部移植为 `@runtime PyGhidra` 并统一由 `driver.py` 启动（原 `run-headless.sh` 入口已废弃并删除，见 §2），此后又新增 4 个，**脚本目录现有 25 个任务脚本**（+ `driver.py` + `analysis_config.py`，共 27 个 `.py`），实测全部可用（移植期间修的三个问题见 §7）。

## 1. 六条铁律（先读这个再动手）

1. **一次调用，批量做事**：每次启动 = JVM 冷启动 + 项目加载（10~60 秒）。禁止"一个函数一次调用"的交互式节奏——用 `triage_scan.py` / `decompile_all.py` 一把出，或写一个组合脚本一次完成 N 件事。
2. **导入分析一次做足**：`driver.py import` 只做一次全量分析；之后一律 `driver.py exec`（PyGhidra 无 `-noanalysis` 概念，脚本阶段不会重跑分析）。
3. **大输出落文件**：所有脚本约定首个参数 `@绝对路径` = 完整结果写该文件（JSON/文本），stdout 只留状态行。agent 用 Read 读文件，不要从 stdout 抠大输出。
4. **Triage 硬门**：未记录 imports（DLL/SYS 还要 exports）+ 语言/壳判定之前，MUST NOT 进入深挖或动态分析。导入表只有 kernel32/ntdll 且极少 → 高度怀疑 `LoadLibrary`+`GetProcAddress` 动态加载，禁止宣称"无网络/无文件能力"。
5. **确认即标注**：搞清一个函数立即 `rename_symbol.py` 改成语义名 + `add_comment.py` 写 plate comment（地址/作用/依据）。结论必须带地址和可复现命令。写操作后需 `exec-w` 才会存盘。
6. **时间盒**：静态深挖 ~15 分钟无关键路径 → 转动态（Frida/GDB/Qiling/angr，选型见 `references/ctf-patterns.md`）；同一路径失败 2 次 → 换工具，禁止空转。

## 2. 快速上手（3 行）

```bash
PY="$HOME/Desktop/src/ghidra-bridge/pyghidra-venv/Scripts/python.exe"
SK="$HOME/.dsh/skills/ghidra-reverse/scripts"

# 1) 建可复用项目（走 Ghidra 自带 headless 导入器；PyGhidra 自己存不下来，见 §7「持久化限制」）
"$PY" "$SK/driver.py" export /path/to/binary

# 2) 导入 + 全量分析 + 一键分诊 → out/<名>.triage.json（进程内，不落盘）
"$PY" "$SK/driver.py" import /path/to/binary

# 3) 批量导出函数伪码 → @out 指向的 .json 及其同名 .c
"$PY" "$SK/driver.py" exec /path/to/binary decompile_all.py \
    "@C:/Users/you/.dsh/ghidra-workspace/out/app.json"

# 4) 写操作（重命名、注释、打补丁）要落盘时用 exec-w
"$PY" "$SK/driver.py" exec-w /path/to/binary rename_symbol.py 0x401000 check_flag
```

子命令：`list` / `export [--force] [--overwrite] [--max-cpu N] [--analysis <超时秒>]` / `import [--force] [--analysis minimal|default]` / `exec` / `exec-w`（存盘）/ 全局 `-v`（verbose JVM 输出）。
⚠ import 与 export 的 `--analysis` **撞名不同义**：import 的是分析器档位，export 的是单文件分析超时秒数。
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
- `decompile_function.py "@out" <函数名|0x地址>`；**多个目标用逗号或空格一次传入**，一次 JVM 出全部结果（16 个函数从 16 次冷启动降到 1 次）：
  `driver.py exec <bin> decompile_function.py "@out/multi.json" 0x101300,0x101bf0,0x1020a0`
  输出多了 `functions[]` 与 `decompiled_count`；单目标时旧字段（`c_code`/`local_variables`）原样保留
- `decompile_all.py "@out"`：真·全量；`--limit` 控制
- `get_xrefs.py "@out" <目标> both` / `get_call_graph.py "@out" <函数> recursive 3` 追数据流
- `search_bytes.py "@out" "48 8d ?? ??"`：字节模式搜索（支持 `??` 与半字节 `4?` 通配）
- 命中具体模式 → 查 `references/ctf-patterns.md`（已知明文 XOR、.rodata 期望值、比较函数即 oracle、自定义 VM 五步法、魔数表…）
- 命中反调试/混淆 → 查 `references/anti-analysis.md`（识别清单、Check→Bypass 对照、OLLVM 分层）
- 自定义解密 stub 不想脱壳 → EmulatorHelper 仿真模板见 `references/scripting.md` §仿真
- 反编译结果看不懂 → 换视角（dogbolt.org 多反编译器对比）或直接看 `get_disassembly.py` 汇编
- **字段序、结构体偏移、常量比对这类问题，一律看汇编不要看伪码**：反编译器的栈槽命名（`local_XXXX`/`uStack_XXXX`）会给出**错误**的字段序。要精确对齐时用 `get_disassembly.py`（带 `bytes` 原始字节）；若装了外部 reverse-ghidra 插件，也可用其 `ghidra_query mode=disassembly`（`offset` 翻页、`hasMore` 判断）

### 阶段 4 — Annotate / Patch / 交付
- 写操作落盘用 `exec-w`：`driver.py exec-w <bin> rename_symbol.py 0x401000 check_flag`
  （`add_comment.py` 类型：eol/pre/post/plate/repeatable；`set_function_signature.py` 改原型）
- `patch_bytes.py "@out" 0x401050 "74"`（JZ↔JNZ 类 patch）；导出 patched 二进制用 `export_binary.py "@out" <导出路径>`（headless 直接导出 Original File 格式，不用开 GUI；多 FileBytes 来源的固件镜像除外，见 §7）
- 交付纪律：报告含 范围 / 证据（地址+复现命令）/ 结论 / 产物路径+SHA256。未经证据支撑的否定结论（"无网络能力"）禁止出现。

## 4. 裸命令模板（排障时才需要；日常用 `driver.py`）

```bash
PY="$HOME/Desktop/src/ghidra-bridge/pyghidra-venv/Scripts/python.exe"
GH="C:/t001s/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC"
WS="$HOME/dsh-ghidra-workspace"   # junction → ~/.dsh/ghidra-workspace；Ghidra 拒绝含 . 的路径元素，必须用 junction

export GHIDRA_INSTALL_DIR="$GH"
export JAVA_HOME="C:/Java"

# 首次：导入 + 全量分析 + 分诊（项目名 dsh_<sha256前16>）
"$PY" -m pyghidra --project-path "$WS/projects" --project-name dsh_<hash> \
  "C:/abs/path/binary.exe" "$SK/triage_scan.py" "@$WS/out/binary.exe.triage.json"

# 注意：pyghidra 3.1.0 已支持脚本参数透传（脚本路径后的参数全部进 script_args）。
# 但日常仍推荐 driver.py：脚本名解析（skill 目录/cwd/ws scripts）、exec-w 存盘、日志落盘。
```

`analyzeHeadless.bat` 仍然可用，但**只能跑 `@runtime` 不是 PyGhidra 的脚本（即 `.java`）**；对 `.py` 会报 Jython 缺失。全部参数细节与 Windows 坑 → `references/headless.md`。

## 5. 脚本清单（`scripts/`，PyGhidra，Ghidra 进程内运行）

通用约定：`[@out文件]` 恒为第一个参数；函数定位支持 `0x地址` / 精确名 / 模糊子串三级查找。

| 脚本 | 用途 | 关键参数 |
|---|---|---|
| `triage_scan.py` | 一键分诊报告（本 skill 入口） | — |
| `analyze_binary.py` | 程序元数据握手 | — |
| `decompile_all.py` | 批量导出全函数伪码到 `.c` | `[regex] [超时秒] [--limit N]` |
| `decompile_function.py` | 函数伪码 + 局部变量；**支持一次多个目标** | 函数[,函数…] |
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
| `set_analysis_options.py` | ⚠ 已被 `analysis_config.py` + `driver.py import --analysis` 取代（§7.9） | minimal |
| `exec_code.py` ⚠ | **任意 Ghidra API**：exec 一个 Python 代码文件，预置 program/find_function/output_json 等 | [@out], 代码文件 |
| `export_binary.py` | headless 导出 patched 二进制（Original File 格式） | [@out], 导出路径 |
| `apply_c_types.py` ✎ | C 语法定义 struct/enum 进类型库（自动补 stdint typedef） | [@out], C声明文件 |
| `apply_data_type.py` ✎ | 把类型套到地址上（createData） | [@out], 地址, 类型名 |

✎ = 写操作：用 `exec-w` 才会保存。⚠ `exec_code.py` 是无沙箱任意代码执行——开放整个 Ghidra API 的逃生舱，清单内脚本不够用时就写个代码文件喂给它，别为此新建一次性脚本。写自定义脚本看 `references/scripting.md`。

**类型库两步走必须都用 `exec-w`**（实测踩过）：`apply_c_types.py` 在只读运行里能成功解析并返回 `types_added`（如 `["/aegis_hdr","/aegis_op", …]`），**但类型不会落盘**，下一次 `apply_data_type.py` 立刻报
`{"status":"error","error":"Data type not found: aegis_hdr"}`。正确顺序：

```bash
driver.py exec-w <bin> apply_c_types.py  "@out/types.json" mytypes.h   # 定义并保存
driver.py exec-w <bin> apply_data_type.py "@out/applied.json" 0x101300 aegis_hdr
```
不想落盘就两步合并进一个 `exec_code.py` 代码文件，一次运行内完成定义+套用。

### 执行模型（两条路，driver 自动分流）
- **`.py`（PyGhidra 脚本）** → 走 `pyghidra.ghidra_script()`。要用**绝对路径**给 `-scriptPath` 之外的脚本；脚本名解析顺序是 skill 目录 → 当前目录 → `<ws>/scripts`
- **`.java`（GhidraScript）** → 自动改走 `analyzeHeadless -scriptPath <脚本目录> -process <程序> -noanalysis -postScript <脚本> <参数…>`。原因是 PyGhidra 跑不了注册目录之外的 `.java`：`JavaScriptProvider` 直接抛 `Failed to find source bundle containing script`
- `analyzeHeadless` 的参数走 **Java property parser**：路径必须用**正斜杠**，反斜杠会被当转义 → `Bad argument: C:\Users\...`（项目目录也一样）

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

1. **`.py` 不能交给 `analyzeHeadless`**（在 PyGhidra 流程下）：那会起普通 JVM，报 Jython 缺失。注意这条与 §0 的 APPDATA 重定向是**两个独立原因**——即使装上 Jython 扩展，PyGhidra 启动器也不认 `analyzeHeadless`。
2. **`pyghidra.start()` 必须在任何 `ghidra.*` import 之前**：否则 `ModuleNotFoundError: No module named 'ghidra'`。`driver.py` 的 `main()` 里处理。
3. **（旧版认知，已过期）`pyghidra` CLI 参数透传**：早期记录称 CLI 只接受一个脚本位置参数；实测 pyghidra 3.1.0 已把脚本后的参数全部传入 `script_args`，裸 CLI 可用。driver.py 仍走 `pyghidra.ghidra_script(..., script_args=[...])` 这个稳定 API，多一层脚本名解析和 exec-w 存盘。
4. **`program_loader().load()` 返回的是 `LoadResults` 而不是 `Program`**：要 `results.getPrimaryDomainObject()`，并且 `LoadResults` 是 `AutoCloseable`，用 `close()` 释放。
5. **`walk_programs(project, callback, ...)` 是回调式**，不是可迭代对象。它会在**自己的 program 上下文里**打开每个程序，所以不要在回调里长期持有 `program`。
6. **`open_project(path, name, create)`**：path 是**父目录**，不是 `.gpr` 文件；`ProjectLocator` 拒绝含 `.` 的路径元素（所以走 junction）。
7. **`currentProgram` / `getScriptArgs()` 仍然可用**：PyGhidra 的脚本 globals 用 `__missing__` 从 `GhidraScript` 实例懒取属性，所以老脚本不用改成显式 `getCurrentProgram()`。
8. **字符串类型更友好**：Java String 到 Python 是真正的 `str`（实测 `type(...).__name__ == 'str'`），`json.dumps` 不需要手动转换。构 Java `byte[]` 用 `jpype.JArray(jpype.JByte)`（Jython 的 `from jarray import array` 不存在）。
9. **Jython 的 `-preScript` 没有对应物**，但功效可以等价实现：分析选项必须在程序**已加载、`analyze()` 尚未运行**之间设置。这是 `analysis_config.py` 的职责，`driver.py import` 已内置；旧的 `set_analysis_options.py` 因此降级为参考实现（它作为独立脚本在 PyGhidra 流程里没有钩子可挂）。

### 三个「遗留问题」已修复（2026-09 实测）

都是**脚本自身的 bug**，不是 Ghidra/PyGhidra 的限制：

- **`patch_bytes.py` 现在能打补丁**。原来的 `if not block.isWrite(): return` 拒绝一切代码段写入——但那个 flag 是**权限位不是保护**（`.text` 的字节本来就是可写的）。现在流程是：`block.setWrite(True)` → `clearCodeUnits()` 清掉与补丁区重叠的反汇编 → `setByte()`（**必须传有符号 byte**，`>127` 的 Python int 会 `OverflowError`）→ `finally` 里恢复 `setWrite(False)`。实测把 `.init` 的 `74 02`(JZ) 改成 `75 02`(JNZ)，**新进程读回仍是 `75 02`**，且 `write:false` 已复位。
  ⚠️ 代价：被覆盖的指令会变成 `undefined`，**需要重新分析**才恢复反汇编视图（脚本结果里用 `instructions_cleared` 报告）。
- **`rename_symbol.py` 现在接受裸地址**。原来只认 `0x` 前缀，传 Ghidra 自己打印的 `00102ae0` 会掉进「按符号名查找」分支必然失败。现在裸十六进制也走地址路径，并且地址落在函数体内时会取**包含它的函数**。实测 `00102ae0` 与 `0x1029f0` 都成功，名字在**新进程里仍然存在**。
- **分析配置可用**：`driver.py import --analysis minimal|default`。`minimal` 关闭重型分析器（实测关掉 Decompiler Switch Analysis / DWARF / Demangler GNU / Function ID / Stack / Create Address Tables），`default` 重新打开（实测打开 Aggressive Instruction Finder / Decompiler Parameter ID）。
  注：`setBoolean` 必须在事务内调用，否则 `db.NoTransactionException`。

### 实测覆盖（对 AegisTrace 的 stripped ELF，96 函数）

**上游 21 个脚本 + `analysis_config` 均可用**：`triage_scan` `analyze_binary` `get_memory_map` `get_symbols` `list_functions` `decompile_function` `decompile_all` `get_disassembly` `get_xrefs` `get_call_graph` `get_basic_blocks` `search_strings` `search_bytes` `get_data_at_address` `list_classes` `emulate_function` `add_comment` `set_function_signature` `rename_symbol`（地址或名字）`patch_bytes`（含写权限授予）`set_analysis_options`（已被 `analysis_config.py` 取代，保留仅作参考）

**本 skill 新增 4 个，同样实测通过**（同一 stripped ELF）：`exec_code` `export_binary` `apply_c_types` `apply_data_type`
- `exec_code.py` —— 文档承诺的名字空间逐个验证存在：`program`/`listing`/`memory`/`fm`/`toAddr`/`find_function`/`output_json` 全部可用（`fm.getFunctionCount() == 96`）
- `export_binary.py` —— 导出 18576 字节，与原文件 **SHA256 完全一致**；同时返回 `md5`/`original_md5` 便于确认补丁是否生效
- `apply_c_types.py` —— 解析出 14 个类型（`/aegis_hdr`、`/aegis_op` + 12 个 stdint typedef）
- `apply_data_type.py` —— 需前一步**已落盘**，见 §5 类型库两步走

**脚本目录 = 25 个任务 `.py` + `driver.py` + `analysis_config.py`（共 27 个），无 shell 脚本**。`run-headless.sh` 曾在目录里，现已删除；`analyzeHeadless` 只由 `driver.py` 的 `.java` 分支调用，不要直接用它跑 `.py`。`__pycache__` 不必提交。

### PyGhidra 持久化限制：存不下自己加载的程序（已用 `export` 绕过）

`driver.py import` **不能把项目落盘**：`program_loader().load()` 返回的程序在一个报告只读的 `DomainFileProxy` 后面，而
`DomainFile.setReadOnly()` 在 proxy 上抛 `UnsupportedOperationException`、`ProgramDB` 又没有 `setChanged`，
所以 `program.save()` 必然 `ghidra.util.ReadOnlyException`。该进程结束后项目里就没有程序了。

**绕法（已实测）**：需要可复用项目时先跑一次 `driver.py export`，它把导入交给 Ghidra 自带的
`analyzeHeadless -import`（参数表里没有脚本，因此不触发 Jython/PyGhidra 的任何 provider 问题），
产出的扁平项目结构正是 `exec`/`exec-w` 能打开的。

```bash
driver.py export ./aegis_service      # 建项目（一次性）
driver.py list   ./aegis_service      # -> /aegis_service (x86:LE:64:default)
driver.py exec   ./aegis_service get_xrefs.py "@out/xrefs.json" 0x102ae0 both
```

实测三段全通，`get_xrefs` 返回 3 条。分工是：**export 负责持久化，import 负责一次性的进程内分析+分诊**。

## 8. 能力边界（什么不做、去哪补）

| 能力 | 状态 |
|---|---|
| 动态调试（Ghidra Debugger/TraceRmi） | **不做**。动态分析外包给 Frida/GDB/Qiling/angr，选型见 `references/ctf-patterns.md` §6 |
| 二进制比对 / Version Tracking | **用 ghidriff**（基于 Ghidra headless 的现成 diff 工具）：`pip install ghidriff` 后 `ghidriff old.exe new.exe -o out/ --json-format`，输出 Markdown/JSON/GhidraProject；大文件加 `--max-section-funcs-analyze 8000 --threaded` 防 OOM。详见 `references/headless.md` §8 |
| Function ID / FIDB | 分析器本身由 `driver.py import --analysis default` 开启（minimal 档会关掉）；FIDB 签名库的制作是低频 GUI 操作（File → Batch Import 到 FIDB），不在本 skill 范围 |
| 数据类型深度操作 | `apply_c_types.py` + `apply_data_type.py` 覆盖 struct/enum 定义与套用；type archive 管理走 GUI |
| 协作式项目（shared repository） | **不做**。Ghidra Server 运维范畴，与单机 agent 场景无关 |
| 导出 patched 二进制 | `export_binary.py`（多 FileBytes 的固件镜像未测，可能按目录导出） |
| 分析器选项调优 | `driver.py import --analysis minimal|default`（`analysis_config.py`）；旧 `set_analysis_options.py` 在 PyGhidra 流程无钩子可挂，仅作参考 |
| 清单外 API 调用 | `exec_code.py` 逃生舱 |
| `@out`/导出/输入文件路径无白名单 | **已接受风险**（本地单机威胁模型）。`exec_code.py` 是无沙箱 exec、`@out` 可写任意路径——不要把本 skill 暴露给不可信调用方 |

## 9. References（按需加载，别一次全读）

| 文件 | 何时读 |
|---|---|
| `references/headless.md` | 要调参数、排障、理解项目缓存机制时 |
| `references/scripting.md` | 要写自定义 Ghidra 脚本（Jython/PyGhidra 惯用法、事务、仿真模板） |
| `references/triage.md` | 分诊细节：语言识别特征、壳检测、高危 API 组合、平台速查 |
| `references/anti-analysis.md` | 命中反调试/反混淆/自校验时的识别与绕过对照表 |
| `references/ctf-patterns.md` | CTF 模式库与 flag 狩猎启发式（XOR/期望值/oracle/自定义 VM/魔数） |
