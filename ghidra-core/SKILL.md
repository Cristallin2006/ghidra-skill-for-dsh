---
name: ghidra-core
description: Ghidra headless 执行底座——rpc_driver/ghidra-rpc 命令、脚本清单、环境自检、engine 说明。当需要实际运行任何 Ghidra 命令、环境排障、或其他逆向 skill 里的操作不知道具体命令时加载。不含分析方法论。
whenToUse: 需要执行 Ghidra 命令、查命令参数、daemon 起停/排障、环境自检（doctor）、拉起 Ghidra GUI 时；re-triage/ghidra-static/vuln-audit 里的操作步骤缺少具体命令时
---

# Ghidra Core（执行底座）

唯一的代码与命令知识层。场景 skill（re-triage / ghidra-static / vuln-audit）只含方法论，具体命令一律回本文件查。

- 场景路由：未知样本分诊 → `~/.dsh/skills/re-triage`；脱壳与验证 → `~/.dsh/skills/re-unpack`；静态深挖/patch/交付 → `~/.dsh/skills/ghidra-static`；漏洞模式排查 → `~/.dsh/skills/vuln-audit`
- 本 skill 内容：§0 环境 / §1 七条铁律 / §2 快速上手（含长任务、GUI、doctor）/ §4 legacy 裸命令 / §5 能力清单（三层）/ §7 移植坑 / §8 能力边界
- engine 内部补丁细节不在本文件：见 `engine/VENDOR.md`

## 0. 环境（本机已配好）

- `GHIDRA_HOME = C:\t001s\ghidra_12.1.3_PUBLIC_20260817\ghidra_12.1.3_PUBLIC`（含 `support/` 的内层目录）
- 执行引擎：**ghidra-rpc 常驻 daemon**（vendor 在 `engine/ghidra-rpc/`，上游 Cellebrite Labs 0.2.0 + dsh 补丁，见 `engine/VENDOR.md`）。统一入口 `scripts/rpc_driver.py`；GUI 用 `scripts/launch_gui.py`（见 §2「GUI」节）
- **JDK 21+**（本机 `C:\Java`，Java 25），且必须是 JDK 而非 JRE——PyGhidra 通过 JPype 起 JVM
- **Python 环境 ×2**：
  - 引擎 venv：`$HOME/Desktop/src/ghidra-bridge/ghidra-rpc-venv`（Python 3.12；ghidra-rpc 0.2.0 **editable** 安装自 `engine/ghidra-rpc/`，pyghidra 3.1.0 + JPype1 1.5.2）——引擎代码改动即时生效
  - legacy venv：`$HOME/Desktop/src/ghidra-bridge/pyghidra-venv`（Python 3.10，pyghidra 3.1.0）——仅供 `driver.py` 后路使用
- 工作区：`~/.dsh/ghidra-workspace/`（`projects/` legacy 项目缓存、`projects-rpc/` daemon 项目、`out/` 产物、`logs/` 日志）
- **传给 Ghidra 的路径必须走 junction `~/dsh-ghidra-workspace`**：Ghidra 的 `ProjectLocator` 拒绝任何以 `.` 开头的路径元素（`~/.dsh/...` 会 abort）。上游 ghidra-rpc 会 `resolve()` 掉 junction——已打补丁（`engine/VENDOR.md` 补丁 2），junction 路径全程可用

### 为什么不是 Jython / analyzeHeadless（重要：原设计其实没错）

**Jython 扩展本身是装好的**，就在 `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\Jython`（内含 `jython-2.7.4\Lib`）。用 GUI（`ghidraRun.bat`，不重定向 APPDATA）跑，原本的 `@runtime Jython` 脚本是能用的。

真正的坑是 **APPDATA 重定向**：为了满足 DSH 的文件沙箱（只允许写工作区），driver 把 `APPDATA`/`LOCALAPPDATA`/`USERPROFILE`/`TMP` 指到工作区内的 settings 目录。Ghidra 于是去 `<被重定向的 settings>\ghidra\ghidra_12.1.3_PUBLIC\Extensions\` 找扩展——**那里没有 Jython**，于是报：

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

上游 19 个 + 本 skill 早期的 `triage_scan`/`decompile_all` 共 21 个脚本已全部移植为 `@runtime PyGhidra` 并统一由 `driver.py` 启动（原 `run-headless.sh` 入口已废弃并删除，见 §2），此后又新增 4 个。**2026-09-15 起执行引擎迁移为 ghidra-rpc 常驻 daemon，这 25 个脚本冻结为 legacy 备查**（见 §5 第 3 层），`driver.py` 保留为 daemon 挂掉时的后路。

## 1. 八条铁律（先读这个再动手）

1. **开工先 ensure；批量场景用批量工具**：daemon 温热后单次命令 ~0.2s，"一个函数一次调用"不再是罪。但全量反编译/全文搜索仍优先 `decompile-all` / `search-decompiled` 这类服务端批量工具——别 for 循环 1000 次单条 `decompile`（每条都要序列化过锁）。
2. **导入分析一次做足**：`rpc_driver.py ensure` 的 load 只做一次全量分析；之后所有查询/写操作都打在同一个已分析程序上，不会重跑分析。
3. **大输出落文件**：所有脚本约定首个参数 `@绝对路径` = 完整结果写该文件（JSON/文本），stdout 只留状态行。agent 用 Read 读文件，不要从 stdout 抠大输出。
4. **Triage 硬门**：未记录 imports（DLL/SYS 还要 exports）+ 语言/壳判定之前，MUST NOT 进入深挖或动态分析。导入表只有 kernel32/ntdll 且极少 → 高度怀疑 `LoadLibrary`+`GetProcAddress` 动态加载，禁止宣称"无网络/无文件能力"。
5. **确认即标注**：搞清一个函数立即 `rename-function` 改成语义名 + `set-comment --type plate` 写 plate comment（地址/作用/依据）。结论必须带地址和可复现命令。daemon 写操作即刻生效并自动存盘。
6. **时间盒**：静态深挖 ~15 分钟无关键路径 → 转动态（Frida/GDB/Qiling/angr，选型见 ghidra-static `references/ctf-patterns.md` §6）；同一路径失败 2 次 → 换工具，禁止空转。
7. **死循环断路器（机械触发，不靠自觉）**：循环签名 = 第二次回到同一字节区域/同一假设继续分析。执行载体是 `scripts/ledger.py`：每个区域级观察 MUST 走 `ledger.py observe` 落账——同一区域第二次 observe 时脚本**拒绝入账（exit 2）**，除非 `--delta` 回答"这次观测和上次差在哪"；答不出 = 断路器触发，按脚本打印的菜单升级：换工具 / 转动态 / 问用户，并用 `ledger.py stuck` 留痕——禁止换第 3 种方式重试同一路径。字节只能通过工具解读（反汇编、反编译、脚本输出）；肉眼/裸 hex 仅用于验证工具输出，脚本对同一区域只放行 2 次，第 3 次直接拒绝。packed/加密字节在信息论上是噪声，内容级死磕一律禁止——先脱壳（re-unpack）或仿真（`emulate-function`）。

铁律 6 管时间（多久没进展就换路），铁律 7 管循环签名（ledger.py 机械拦截原地打转）——先命中哪条执行哪条。台账 = `<ws>/out/<名>.ledger.jsonl`（机器真相，append-only）+ 每次入账自动重建的 `<名>.ledger.md`（人读视图）：权威结论写入即锁定（同 id 覆盖必须 `--overturn`+新证据）、先查后析（`ledger.py query`）、推翻留痕——机制细节见 `references/evidence-ledger.md`。

8. **读数纪律（第一嫌疑人是读数，不是程序）**：关键常量（密文/密钥/换表/魔数）的唯一权威读数 = `scripts/read_views.py` 三视图（hexdump + 带字节数的 fromhex-ready hex + cstr），读到立即 `ledger.py conclude` 锁定（注明地址+长度+工具）；**禁止从终端手工转录 hex**（可信度最低的通道不能承载最关键的事实）。反编译器/IDA 的字符串与 hex 渲染只是视图——会把 `0x01`/`0x0E` 渲染成 `1`/`E` 吞掉前导 0——凡要引用渲染文本，先 `read_views.py --expect-hex "<渲染文本>"` 与真实字节对照。观测矛盾（伪码声明长度 vs 实测处理长度、同一事实两次读出不同值、`strcmp` 对任何输入都不等）→ **先怀疑读数**：任何"这段逻辑是坏的/反的"的结论，必须先排除读数错误才允许提出；同一事实第二次读出不同结果 = 熔断信号，立即停止推断、用 read_views 建立权威读数。**求逆之前先正向验证**：拿到疑似密钥/密文后，先用已知输入把完整流水线正向跑一遍（`oracle.py` / `emulate-function`）确认模型能复现已知输出，再求逆——直接求逆错了也不知道错在哪。

## 2. 快速上手（3 行）

```bash
RD="$HOME/.dsh/skills/ghidra-core/scripts/rpc_driver.py"

# 1) 开工：daemon 没起就起、二进制没 load 就 load（幂等），含全量分析
python "$RD" ensure /path/to/binary

# 2) 一键分诊 → @out 落盘；之后所有命令直接跟二进制路径，key 自动映射
python "$RD" "@$HOME/.dsh/ghidra-workspace/out/app.triage.json" triage /path/to/binary
python "$RD" decompile /path/to/binary main
python "$RD" xrefs-to /path/to/binary check_flag

# 3) 写操作（重命名/注释/patch）即刻生效并自动存盘，无需 exec-w
python "$RD" rename-function /path/to/binary FUN_00401000 check_flag
```

`rpc_driver.py` 做的事：项目映射（`~/dsh-ghidra-workspace/projects-rpc/dsh_<sha256前16>.gpr`，junction 路径）、binary key 自动替换（不用记 `/name-hash6` 后缀）、`--project` 注入、`@out` 落盘、环境变量自给（GHIDRA_INSTALL_DIR/JAVA_HOME/LOCALAPPDATA 重定向/USERNAME=dsh）。
子命令：`ensure|status|stop <binary>` + 其余全部透传给 `ghidra-rpc` CLI（`decompile`/`functions`/`strings`/`disassemble`/`assemble`/`write-bytes`/`triage`/`exec-code`/`export-binary`/`emulate-function`/`version-track`…，全量见 `ghidra-rpc --help`）。
二进制比对：`version-track <A> <B>` / `function-diff <A> <f1> <B> <f2>` 会自动把 B 也 load 进 A 的项目（VT 要求同项目）。

### 长任务（后台执行）

daemon 常驻后日常命令都是亚秒级，真正的长任务只剩 **`load`（大文件导入+分析）和 `version-track`（全函数关联）**——这类用 dsh Bash 工具的 `run_in_background` 跑，靠 `@out` 落盘拿结果：

```bash
# 后台跑 version-track（大样本对），结果落 @out 文件
python "$RD" "@$HOME/.dsh/ghidra-workspace/out/vt.json" version-track old.exe new.exe --changed-only
# → 拿到 task_id 后继续干别的；完成通知到达后 Read 该 json
```

判断完成的信号是 `@out` 文件出现且 JSON 有效；stdout 摘要行只有几行，不要从前台输出抠大结果。

### GUI（launch_gui.py）

```bash
python "$SK/launch_gui.py"                      # 裸启动 Ghidra GUI
python "$SK/launch_gui.py" --open /path/to/bin  # 打开该二进制的 dsh_<hash> 项目
python "$SK/launch_gui.py" --project dsh_<hash> # 按项目名打开
```

detached 启动，脚本立即返回 PID，GUI 输出进 `logs/gui-launch.log`；关闭用 `taskkill //PID <pid> //F` 或 GUI 内退出。GUI 以 `USERNAME=dsh` 启动（与 headless 创建的项目的属主一致，不会 NotOwnerException），settings 用真实用户目录。

**何时该去 GUI**：交互式 CFG/函数图深挖、人工比对多个函数、type archive（FIDB）制作、plugin 类交互工具（GOOMBA 等）。**headless 已覆盖的事别去 GUI**：导出 patched 二进制（`export_binary.py`）、patch（`patch_bytes.py`）、批量反编译、分诊。

### 环境自检（doctor.py）

```bash
python "$SK/doctor.py"          # 全绿 exit 0；任一 fail exit 1
```

输出分两块：

- **Ghidra 核心 8 项**（决定 exit code，fail 即 exit 1）：安装与两个启动器、JAVA_HOME/java 版本、pyghidra-venv、ghidra-rpc-venv、ghidra-rpc 包（editable 自 engine/）、工作区可写 + junction 解析、现有项目清单、daemon 起停冒烟（`--quick` 可跳过这项慢的）
- **toolchain 三层**（独立成节，不进 exit code）：Tier A 轻量高频（checksec/GoReSym/pyinstxtractor/frida/z3/rust-demangler/upx/unpacker，缺失=warn 按 hint 补装）；Tier B 按需重装（angr/qiling/speakeasy/unipacker/ghidriff/SiMBA/strings/readelf）；Tier C GUI/手工（dnSpyEx/de4dot/DIE/x64dbg/GOOMBA/golang-loader）

**任何 skill 的路由表提到外部工具时，可用性以 doctor 的 toolchain 节为准**——那是唯一真相源。换机器/升级 Ghidra/排查"怎么又起不来"时先跑它。

**外来旧项目**：从别处拷来的项目若 `project.prp` 的 `OWNER` 不是 `dsh`，headless `open_project` 首次打开会自动改写属主；GUI 则要求属主一致，手动把 `OWNER VALUE="..."` 改成 `dsh` 即可。

## 4. 裸命令模板（legacy 排障专用；日常用 `rpc_driver.py`）

daemon 整体不可用时的后路是 `driver.py`（pyghidra-venv，每次调用一个冷启动 JVM）：

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

## 5. 能力清单（三层）

通用约定：`rpc_driver.py` 的 `[@out文件]` 恒为第一个参数；函数定位支持 `0x地址` / 精确名 / 模糊子串；写操作即刻生效并自动存盘。

### 第 1 层：rpc 命令（主力，`python rpc_driver.py <命令> <binary> [参数]`）

| 命令 | 用途 |
|---|---|
| `ensure` / `status` / `stop` | daemon 与二进制生命周期（ensure 幂等） |
| `triage` ◆ | 一键分诊报告（本 skill 入口） |
| `metadata` / `imports` / `exports` / `memory-map` / `relocations` | 程序元数据 |
| `functions` / `decompile` / `decompile-all` / `search-decompiled` | 函数与伪码 |
| `disassemble` / `assemble` ✎ / `basic-blocks` / `pcode` | 汇编/CFG/P-code |
| `strings` / `symbols` / `find-bytes` | 搜索 |
| `xrefs-to` / `xrefs-from` | 交叉引用 |
| `read-bytes` / `read-pointers` / `write-bytes` ✎ | 内存读写（write-bytes 已对齐 patch_bytes 语义） |
| `rename-function` ✎ / `rename-symbol` ✎ / `batch-rename` ✎ / `set-comment` ✎ / `batch-set-comment` ✎ / `set-signature` ✎ | 标注 |
| `create-struct` ✎ / `create-enum` ✎ / `modify-struct` ✎ / `set-data-type` ✎ / `apply-data-type-range` ✎ / `set-equate` ✎ | 数据类型 |
| `retype-variable` ✎ / `rename-variable` ✎ / `batch-edit-variables` ✎ / `set-calling-convention` ✎ / `set-thunk` ✎ / `create-function` ✎ / `create-label` ✎ | 深度修改 |
| `version-track` / `function-diff` / `match-function` | 二进制比对（Auto VT + BSim） |
| `list-vtable` / `get-processor-context` / `set-processor-context` ✎ | C++/ISA 上下文 |
| `tag-function` ✎ / `list-tags` / `functions-by-tag` / `set-bookmark` ✎ / `list-bookmarks` | 进度标记 |
| `exec-code` ◆⚠ | 逃生舱：daemon 内 exec Python 文件（预置 program/find_function/output_json；无沙箱） |
| `export-binary` ◆ | Original File 导出 + md5 对比 |
| `emulate-function` ◆ | EmulatorHelper P-code 仿真（寄存器/内存预置，call-depth 追踪） |

◆ = dsh 自定义工具（`engine/ghidra-rpc/ghidra_rpc/server/tools/dsh_tools.py`）。✎ = 写操作。⚠ = 无沙箱。
完整命令与参数：`~/Desktop/src/ghidra-bridge/ghidra-rpc-venv/Scripts/ghidra-rpc.exe --help`，或 `engine/ghidra-rpc/docs/` + `engine/ghidra-rpc/README.md`。

### 第 2 层：宿主工具脚本（◈ 直接 python 运行，不经 daemon/driver）

| 脚本 | 用途 |
|---|---|
| `rpc_driver.py` | 统一入口：项目映射/key 替换/@out/环境自给 |
| `ledger.py` | **铁律 7 机械断路器**：观察落账（同区回访强制 `--delta`）/权威结论锁定/卡点/render |
| `read_views.py` | **铁律 8 权威读数**：三视图读字节（hexdump/fromhex-ready hex/cstr）+ `--expect-len`/`--expect-hex` 一致性检查（失败 exit 2） |
| `launch_gui.py` | detached 拉起 Ghidra GUI，可直接打开项目 |
| `doctor.py` | 环境自检（8 项：安装/JDK/双 venv/工作区/项目/rpc 包/daemon 起停），全绿 exit 0 |

### 第 3 层：legacy（冻结备查，被 rpc 取代）

`scripts/` 下 25 个 PyGhidra 脚本 + `driver.py` + `analysis_config.py`：**冻结，仅备查**。`driver.py` 仍是两条后路——(a) daemon 整体挂掉时的直接执行通道（`driver.py export/exec/exec-w`，用 pyghidra-venv）；(b) 调试脚本行为差异时的对照组。不要在新工作流里再用它们；行为差异以 rpc 为准。

✎ 注意：legacy 时代"写操作必须 exec-w 才存盘"的纪律**已由 daemon 的自动存盘取代**——rpc 写命令每次写完即 `project.save()`，`stop` 时再全量保存。

### 执行模型（engine 内部，排障时读）
- daemon 进程 = rpc-venv 的 python + 进程内 JVM（pyghidra）；transport = 127.0.0.1 TCP + token（endpoint 文件在 `<ws>/rpc-localappdata/ghidra-rpc/`）
- session/registry 在 `<ws>/rpc-state/`（`GHIDRA_RPC_STATE_DIR`）；daemon 日志在 `<ws>/rpc-localappdata/ghidra-rpc/*.log`
- 所有 handler 由全局锁串行化——**并发客户端不会并行执行**，长命令会挡住其他命令
- daemon 崩溃后下一条命令自动按 session 重启（auto-restart）；`stop` 不干净时删 endpoint 文件再起

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
| 二进制比对 / Version Tracking | **内置**：`version-track`（Auto VT + BSim）/ `function-diff` / `match-function`。⚠ 灵敏度坑：单字节 patch 级别的差异在默认相似度下会被判 `identical`（`changed_functions: 0`）——找小改动要去掉 `--changed-only` 看 similarity 分数，或调高 `--min-similarity`；确认差异用 `function-diff` |
| 汇编级 patch | **内置**：`assemble`（SLEIGH，助记符大小写敏感，小写自动重试一次）/ `write-bytes`（自动清冲突指令+授写权限） |
| 伪码全文搜索 | **内置**：`search-decompiled`（跨函数正则） |
| P-code 分析 | **内置**：`pcode`（raw listing）/ `pcode --high`（SSA） |
| 批量变量改名/改型 | **内置**：`batch-edit-variables`（同一反编译快照上一次事务改多个局部变量） |
| Function ID / FIDB | 分析器由 daemon 的 `load` 全量分析自带；FIDB 签名库的制作是低频 GUI 操作（File → Batch Import 到 FIDB），不在本 skill 范围 |
| 数据类型深度操作 | `create-struct`/`create-enum`/`modify-struct`/`set-data-type`/`apply-data-type-range` 覆盖定义与套用；type archive 管理走 GUI |
| 协作式项目（shared repository） | **不做**。Ghidra Server 运维范畴，与单机 agent 场景无关 |
| 导出 patched 二进制 | `export-binary`（多 FileBytes 的固件镜像未测，可能按目录导出） |
| 分析器选项调优 | daemon `load` 固定全量分析；需要 minimal 档时用 legacy `driver.py import --analysis` 或改 `analysis_config.py` |
| 清单外 API 调用 | `exec-code` 逃生舱 |
| `@out`/导出/输入文件路径无白名单 | **已接受风险**（本地单机威胁模型）。`exec-code` 是无沙箱 exec、`@out` 可写任意路径——不要把本 skill 暴露给不可信调用方 |

（按需加载，别一次全读）

| 文件 | 何时读 |
|---|---|
| `references/headless.md` | 要调参数、排障、理解项目缓存机制时 |
| `references/scripting.md` | 要写自定义 Ghidra 脚本（Jython/PyGhidra 惯用法、事务、仿真模板） |
| `~/.dsh/skills/re-triage/references/triage.md` | 分诊细节：语言识别特征、壳检测、高危 API 组合、平台速查（属 re-triage） |
| `~/.dsh/skills/re-triage/references/anti-analysis.md` | 命中反调试/反混淆/自校验时的识别与绕过对照表（属 re-triage） |
| `references/evidence-ledger.md` | 铁律 7 执行机制：ledger.py 命令、断路器语义、台账格式（任何区域级分析前必读） |
| `~/.dsh/skills/ghidra-static/references/ctf-patterns.md` | CTF 模式库与 flag 狩猎启发式（XOR/期望值/oracle/自定义 VM/魔数，属 ghidra-static） |
