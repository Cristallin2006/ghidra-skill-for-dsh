# Headless 调用详解（analyzeHeadless · Windows · Ghidra 12.1.3）

## 1. 两条命令模板

### 命令 A：导入 + 全量分析（每个二进制只做一次）

```bash
"$GHIDRA_HOME/support/analyzeHeadless.bat" <projects目录> <项目名> \
  -import "<binary绝对路径>" \
  [-loader <loader名>] \                      # raw 固件时指定，如 -loader BinaryLoader
  [-baseAddress 0x...] \                      # raw 二进制指定基址
  -scriptPath "<scripts目录>" \
  [-preScript set_analysis_options.py minimal] \
  [-postScript triage_scan.py "@<输出.json>"] \
  [-analysisTimeoutPerFile 600] [-max-cpu 4] \
  [-overwrite] [-log "<日志路径>"]
```

### 命令 B：对已分析程序执行脚本（其他所有操作）

```bash
"$GHIDRA_HOME/support/analyzeHeadless.bat" <projects目录> <项目名> \
  -process "<program名>" \                    # = 导入时的文件名（basename），不是路径
  -noanalysis \                               # 不重分析，直接加载已分析结果
  [-readOnly] \                               # 读操作必加；写操作省略（退出时自动保存）
  -scriptPath "<scripts目录>" \
  -postScript <脚本.py> [脚本参数...]          # 脚本参数必须紧跟脚本名
  [-log "<日志路径>"]
```

**参数顺序坑**：`-postScript xxx.py arg1 arg2` 的参数必须紧跟脚本名；`-noanalysis`、`-readOnly`、`-log` 这些 flag 放参数后面。

## 2. 项目生命周期与缓存

- 项目 = `<projects目录>/<项目名>.gpr` + 同名目录。约定项目名 `dsh_<sha256(binary)前16>`。
- `.gpr` 存在 → 跳过 `-import`，直接走命令 B。
- 要重分析：命令 A 加 `-overwrite`（或删 `.gpr` 与同名目录）。
- `-deleteProject`：**别用**（用完即删项目，标注全丢）。项目留着，GUI 打开继续手工分析。
- 批量多样本：对每个二进制循环命令 A（项目名各自独立），不要塞进一个项目除非你明确要版本追踪。

## 3. 脚本参数与输出协议

- 脚本内 `getScriptArgs()` 拿到 `-postScript` 后的参数列表（字符串数组）。
- **本 skill 约定**：首个参数 `@绝对路径` = 完整结果写该文件；stdout 只打印 `===JSON_START===` / `===JSON_END===` 包的简短状态。
- 为什么落文件：Ghidra 的 INFO 日志混在 stdout；Windows 控制台编码会毁非 ASCII；大输出被管道截断。文件 + Read 工具最稳。
- JSON 一律 `json.dumps(data)` 默认 `ensure_ascii=True`（纯 ASCII，无编码坑）；伪代码等文本用 `codecs.open(path,'w','utf-8','replace')`。

## 4. Windows 专属坑（实测）

1. **`.bat` 启动器**：Windows 只有 `analyzeHeadless.bat`（无无后缀版本）。Git Bash 里直接 `"$GH/support/analyzeHeadless.bat" args` 可执行；Python `subprocess.run(list)` 不经 shell 跑不了 .bat，需 `cmd /c` 前缀。
2. **路径含空格**：全程引号。`GHIDRA_HOME` 指向**含 support/ 的内层目录**（本机是 `C:\t001s\ghidra_12.1.3_PUBLIC_20260817\ghidra_12.1.3_PUBLIC`，两层同名目录取内层）。
3. **JDK**：Ghidra 12.x 要求 JDK 21+（64-bit）。找不到 Java 时设 `JAVA_HOME`；`analyzeHeadless.bat` 用 `support/launch.properties` 也可指定。
4. **内存**：JVM 堆由环境变量 `MAXMEM` 控制（默认 4G 左右）。大二进制 OOM 时 `set MAXMEM=8G` 再调用（cmd）或 `export MAXMEM=8G`（bash）。注意：网上教程里的 `GHIDRA_HEADLESS_MAXMEM` 是某插件的自定义变量，**Ghidra 原生不读它**。
5. **日志**：`-log` 指定文件；Ghidra 自身用户日志在 `%USERPROFILE%\.ghidra\.ghidra_12.1.3_PUBLIC\application.log`。
4. **工作区路径不能含 `.` 开头的元素**：Ghidra 的 `ProjectLocator` 会 abort。`~/.dsh/ghidra-workspace` 不能直接传给 JVM——使用 junction `~/dsh-ghidra-workspace`（指向同一物理目录，run-headless.sh 已自动建）。cmd/PowerShell 下同理。
5. **Jython 扩展**：Ghidra 12.1 移除了内置 Jython，报 `JythonStubScriptProvider$JythonStubException` 时：把 `<GHIDRA_HOME>\Extensions\Ghidra\*_Jython.zip` 解压安装到**用户设置目录** `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\`（解到安装目录的 `Extensions\Ghidra` 不生效，那只是 archive 目录）。本机已装好。
6. **analyzeHeadless abort 时退出码仍为 0**：不要信退出码，以输出文件是否存在判定成败。
7. **超时**：headless 无内置总超时（`-analysisTimeoutPerFile` 只管分析阶段）。调用方（run-headless.sh / agent Bash 工具）给超时：小样本 300s，大样本 600s+。
8. **并发**：同一项目同时只能一个 headless 进程打开（项目锁）。批量跑多样本没问题，同一样本别并行。

## 5. 常用 flag 速查

| flag | 作用 |
|---|---|
| `-import <file>` | 导入并分析新二进制 |
| `-process <name>` | 处理项目里已有程序（配合 -noanalysis） |
| `-noanalysis` | 跳过自动分析 |
| `-readOnly` | 只读打开；省略则退出时保存修改 |
| `-overwrite` | 导入时覆盖已存在的同名程序 |
| `-scriptPath <dir>` | 脚本搜索目录（可重复） |
| `-preScript` / `-postScript` | 分析前/后跑的脚本（参数紧跟其后） |
| `-analysisTimeoutPerFile <秒>` | 单文件分析超时 |
| `-max-cpu <N>` | 分析并行度 |
| `-log <file>` | 日志文件 |
| `-loader <名>` / `-baseAddress` | raw 二进制/固件加载控制 |
| `-scriptlog <file>` | 脚本 stdout 额外落文件（排障用） |

## 6. raw 固件 / dump 内存段导入

```bash
# raw binary：指定 loader 与基址（架构交互不了时用 -processor）
"$GH/support/analyzeHeadless.bat" "$WS/projects" dsh_fw \
  -import "dump.bin" -loader BinaryLoader -baseAddress 0x08000000 \
  -processor "ARM:LE:32:Cortex" \
  -postScript triage_scan.py "@$WS/out/fw.triage.json"
```

脱壳 dump 的内存段同理：`-loader BinaryLoader -baseAddress <dump时基址>`，导入后手动/脚本在入口点 Create Function + 重新分析。

## 7. 排障顺序

1. `-log` 文件末尾 + stdout 的 `ERROR` 行
2. 脚本没跑？→ 确认 `-scriptPath` 指向 scripts 目录、脚本名拼写、`# @runtime Jython` 头
3. `currentProgram is None` → 命令 B 的 `-process` 名字不对（必须是导入时的文件名）
4. 改了没保存 → 写操作误加了 `-readOnly`
5. 找不到 Java/JDK 版本错 → 设 `JAVA_HOME`
