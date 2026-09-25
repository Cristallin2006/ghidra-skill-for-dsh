---
name: ghidra-core
description: Ghidra headless 执行底座（execution engine）——rpc_driver/ghidra-rpc 命令、daemon 起停、doctor 环境自检、脚本清单。当需要实际运行任何 Ghidra 命令（import/decompile/disassemble/rename/patch/version-track）、环境排障、或其他逆向 skill 里的操作不知道具体命令时加载。不含分析方法论。动手前必须先用 skill 工具加载本 skill 全文并遵守其流程；一切观察/结论用 ledger.py 落账。
whenToUse: 需要执行 Ghidra 命令、查命令参数、daemon 起停/排障、环境自检（doctor）、拉起 Ghidra GUI 时；re-triage/ghidra-static/vuln-audit 里的操作步骤缺少具体命令时
---

# Ghidra Core（执行底座）

唯一的代码与命令知识层。场景 skill（re-triage / ghidra-static / vuln-audit）只含方法论，具体命令一律回本文件查。

- 场景路由：未知样本分诊 → `~/.dsh/skills/re-triage`；脱壳与验证 → `~/.dsh/skills/re-unpack`；静态深挖/patch/交付 → `~/.dsh/skills/ghidra-static`；漏洞模式排查 → `~/.dsh/skills/vuln-audit`
- 本 skill 内容：§0 环境 / §1 十三条铁律 / §2 快速上手（含长任务、GUI、doctor）/ §4 legacy 裸命令 / §5 能力清单（三层）/ §7 移植坑 / §8 能力边界
- engine 内部补丁细节不在本文件：见 `engine/VENDOR.md`

## 0. 环境（本机已配好）

> **WSL/Linux 部署的路径映射**（当 `uname` 是 Linux 时，本节常量按下表替换；脚本内部已自动按平台分支，此处供人工/排障参考）：
> - `GHIDRA_HOME = /opt/ghidra`，JDK = `/usr/lib/jvm/java-21-openjdk-amd64`（apt openjdk-21）
> - 引擎 venv = `~/ghidra-rpc-venv`（bin/python，无 .exe），legacy venv = `~/pyghidra-venv`
> - re-tools venv = `~/re-tools-venv`，unpacker venv = `~/unpacker-venv`，pwn venv = `~/re-pwn-venv`
> - 工具目录 = `~/tools/`（goresym、jadx、pyinstxtractor）；系统工具（file/upx/gdb/tshark/pycdc…）全在 PATH，直接裸名调用
> - junction 在 Linux 是 symlink `~/dsh-ghidra-workspace`，语义相同
> - `win_gui_drive.py`、pywin32、Android SDK/emulator 为 Windows-only，Linux 下不可用

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

## 1. 十三条铁律（先读这个再动手）

1. **开工先 ensure；批量场景用批量工具**：daemon 温热后单次命令 ~0.2s，"一个函数一次调用"不再是罪。但全量反编译/全文搜索仍优先 `decompile-all` / `search-decompiled` 这类服务端批量工具——别 for 循环 1000 次单条 `decompile`（每条都要序列化过锁）。
2. **导入分析一次做足**：`rpc_driver.py ensure` 的 load 只做一次全量分析；之后所有查询/写操作都打在同一个已分析程序上，不会重跑分析。
3. **大输出落文件**：所有脚本约定首个参数 `@绝对路径` = 完整结果写该文件（JSON/文本），stdout 只留状态行。agent 用 Read 读文件，不要从 stdout 抠大输出。
4. **Triage 硬门**：未记录 imports（DLL/SYS 还要 exports）+ 语言/壳判定之前，MUST NOT 进入深挖或动态分析。导入表只有 kernel32/ntdll 且极少 → 高度怀疑 `LoadLibrary`+`GetProcAddress` 动态加载，禁止宣称"无网络/无文件能力"。
5. **确认即标注**：搞清一个函数立即 `rename-function` 改成语义名 + `set-comment --type plate` 写 plate comment（地址/作用/依据）。结论必须带地址和可复现命令。daemon 写操作即刻生效并自动存盘。
6. **时间盒**：静态深挖 ~15 分钟无关键路径 → 转动态（Frida/GDB/Qiling/angr，选型见 ghidra-static `references/ctf-patterns.md` §6）；同一路径失败 2 次 → 换工具，禁止空转。**量化判据（什么算"卡住"）**：同一假设上连续 3 次工具调用没有产出新观测（新地址/新常量/新结构），即判定卡住——不许靠"再试一次"拖延，立即按铁律 7 的菜单升级；给同一思路"换措辞重试"（改脚本变量名/换种写法跑同一模型）计入失败次数，不重置计数。
7. **死循环断路器（机械触发，不靠自觉）**：循环签名 = 第二次回到同一字节区域/同一假设继续分析。执行载体是 `scripts/ledger.py`：每个区域级观察 MUST 走 `ledger.py observe` 落账——同一区域第二次 observe 时脚本**拒绝入账（exit 2）**，除非 `--delta` 回答"这次观测和上次差在哪"；答不出 = 断路器触发，按脚本打印的菜单升级：换工具 / 转动态 / 问用户，并用 `ledger.py stuck` 留痕——禁止换第 3 种方式重试同一路径。字节只能通过工具解读（反汇编、反编译、脚本输出）；肉眼/裸 hex 仅用于验证工具输出，脚本对同一区域只放行 2 次，第 3 次直接拒绝。packed/加密字节在信息论上是噪声，内容级死磕一律禁止——先脱壳（re-unpack）或仿真（`emulate-function`）。

铁律 6 管时间（多久没进展就换路），铁律 7 管循环签名（ledger.py 机械拦截原地打转）——先命中哪条执行哪条。台账 = `<ws>/out/<名>.ledger.jsonl`（机器真相，append-only）+ 每次入账自动重建的 `<名>.ledger.md`（人读视图）：权威结论写入即锁定（同 id 覆盖必须 `--overturn`+新证据）、先查后析（`ledger.py query`）、推翻留痕——机制细节见 `references/evidence-ledger.md`。

8. **读数纪律（第一嫌疑人是读数，不是程序）**：关键常量（密文/密钥/换表/魔数）的唯一权威读数 = `scripts/read_views.py` 三视图（hexdump + 带字节数的 fromhex-ready hex + cstr），读到立即 `ledger.py conclude` 锁定（注明地址+长度+工具）；**禁止从终端手工转录 hex**（可信度最低的通道不能承载最关键的事实）。反编译器/IDA 的字符串与 hex 渲染只是视图——会把 `0x01`/`0x0E` 渲染成 `1`/`E` 吞掉前导 0——凡要引用渲染文本，先 `read_views.py --expect-hex "<渲染文本>"` 与真实字节对照。观测矛盾（伪码声明长度 vs 实测处理长度、同一事实两次读出不同值、`strcmp` 对任何输入都不等）→ **先怀疑读数**：任何"这段逻辑是坏的/反的"的结论，必须先排除读数错误才允许提出；同一事实第二次读出不同结果 = 熔断信号，立即停止推断、用 read_views 建立权威读数。**求逆之前先正向验证**：拿到疑似密钥/密文后，先用已知输入把完整流水线正向跑一遍（`oracle.py` / `emulate-function`）确认模型能复现已知输出，再求逆——直接求逆错了也不知道错在哪。字段/读数冲突时，在宣称"题目设计有矛盾"之前，必须先排除"该值是多字段复合函数"（如 tsval ^ payload ^ seq 片段）这一可能——同键冲突恰恰证明单字段不是明文。
9. **缓冲区归属（字节是谁的）**：从 `MOV [EBP+disp], imm` 序列重建栈上字符串时，必须**按 disp 区间归属变量**，禁止按指令出现顺序拼接——相邻变量的写入区间相接（`end_A + 1 == start_B`）时极易把别人的字节拼进自己的常量（encode 复盘 E1：28 字节密文被读成 49 字符）。拼接结果 MUST `read_views.py --expect-len` 与该变量声明长度核对。任何常量长度不符合其用途（hex 必须偶数、base64 必须 4 的倍数、XOR/RC4 密文必须等于明文长度）→ **以「读数可疑」中止，禁止进入求逆**。机械门 = `scripts/crypto_sanity.py`：求逆前 MUST 过 `check`，求逆后 MUST 过 `check-result`——49 字符的 base64、28≠21 的密文、不可打印的反推结果都会被它 exit 2 拦下。
10. **验证独立性（同源验证 = 没验证）**：用自己 patch 的进程、自己写的 harness、自己算的偏移来验证自己对程序的理解，三者一致不构成任何证据（encode 复盘 E2/E3）。① **被 patch 过的运行态只能用于探索控制流，禁止用于验证数据模型**——验证数据模型要求进程未修改（或修改点与测量点无数据依赖）+ 至少一个独立来源（静态常量/第二输入/已知明文）交叉印证；被迫在 patch 后测量的结论必须 `conclude --independent no` 标注。② **自建 harness（投喂/读数脚本）在支撑结论前必须用已知答案的输入自检**；自检失败或结果不稳定 → 该 harness 全部输出作废；「偶发命中」必须复跑 ≥100 次确认可复现才算发现。**凡「由观测反推中间量」的脚本（白化/搬运公式、角色字反推、偏移表）无已知答案自检 ⇒ 其输出标 ⚠UNVERIFIED 且不得用于否定模型**——「模型像坏的」时第一嫌疑人永远是 harness 自己：差异呈现规律（如低半字全对、高半字共用一个常数）是"接口/搬运写错"的典型指纹，不是"程序少了运算"。③ `ledger.py conclude` 强制标注 `--source`/`--independent`（self-script 必须给 `--harness` 路径），无独立来源的结论在 render 里标 ⚠UNVERIFIED，禁止原样交付。④ **否定性结论门槛更高**：说「不可满足/程序是坏的」之前，必须先用已知输入正向复现成功（铁律 8），且结论必须能指认一个「如果它错了，结论就崩」的外部事实——指认不出就不许交付。**「这是诱饵/假 check/作者逻辑坏了」同属否定性结论**：判某分支为假之前，必须先做判定性实验——钉随机源为不同值看输出是否变（判 mask vs target）、读校验涉及的状态量（`dir()`/`__dict__`/hook 目标函数）并用已知输入拟合其表达式；实验做不了就不许判。细则见 re-dynamic §4。
11. **手写解析器必须双源验证（工具缺失 ≠ 自造轮子的许可证）**：自行实现的格式/字节码解析器（opcode 表、结构体偏移、指令解码、文件格式 parser），在据此下任何结论前，MUST 与第二个独立实现逐条比对至少一次——官方实现优先（SDK 自带工具），其次成熟第三方库；比对不上就装工具，装不了就标 ⚠UNVERIFIED（铁律 10③）禁止交付。**「输出看起来合理」不构成正确性证据**——表偏移类错误恰恰只产生语法合法、语义自洽、看似合理的输出（五题复盘：DEX opcode 表在 0x2d 多塞一个条目，`if-lt` 被读成 `if-ne`，标准 ROT13 显示成残废实现，差点自信交付）。已知的静默偏移陷阱（手写同类代码前先当自检清单过一遍）：`scripts/pe_info.py` 的 **PE32 ImageBase**（PE32 在 opt+28，opt+24 是 BaseOfData；PE32+ 才在 opt+24）与 **PE32+ 导入 thunk 宽度**（8 字节 QWORD——按 4 字节读会撞上全零高半部，把导入列表静默截断成「每 DLL 1 个函数」）、AXML 字符串池偏移、DEX opcode 表条目数。配套纪律：**oracle 必须成对**（证明「正确输入被接受」之外，必须给出「近似错值被拒绝」的负对照，否则无法排除「凡输入皆通过」）；**解空间可枚举时穷举优先于公式**（穷举同时产出答案与唯一性证明）。
12. **异常即约束**：观测到的不一致（重复键冲突、伪码长度 vs 实测、同一事实两次读数不同）必须 `ledger.py anomaly --consequence "..."` 转成可检验假设落账，禁止降级为"噪声/歧义待枚举"；存在 open anomaly 时 stuck 必须 `--ack` 引用或先 `resolve --waive`；工具缺失导致的客观不可查走 waive，不许硬卡。
13. **轴必须交叉（限枚举类解码/搜索任务）**：仅适用于候选空间可枚举的解码/搜索任务（隐信道解码、爆破类）——开跑前先出轴矩阵+候选预算（候选数 = Σ C（字段数，k) × 算子数 × 顺序源 × 打包 × 后变换）；预算算得出却仍剪轴必须写明理由；任一轴恒为 identity/常量 = 未覆盖，不得声称"试过"。与铁律 6 时间盒联动：预算 > 时间盒承受能力时升级方法（找 oracle/换数学洞察）而不是硬跑。**不适用于需要数学洞察的密码题——那里穷举是最后手段。**

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
| `exec-code` + `scripts/unreferenced_funcs.py` ◆ | 零调用方函数清单（藏 flag 的第二函数）：`python rpc_driver.py [@out] exec-code <binary> "$SK/unreferenced_funcs.py"`；`--reachable-from <root>` 做可达性过滤——daemon 下脚本参数走 `DSH_UNREF_ARGS` 环境变量（须在 ensure/启动 daemon 前导出）；排除 thunk/external/entry-export 根 |
| `exec-code` + `scripts/unreferenced_data.py` ◆ | 零引用数据块清单 + 置换/密钥材料分类 + 相邻块跨度合并（藏置换表/S-box）：`python rpc_driver.py exec-code <binary> "$SK/unreferenced_data.py"`；daemon 下脚本参数走 `DSH_UNREF_DATA_ARGS` 环境变量（须在 ensure/启动 daemon 前导出）；`--min-size <n>` 调阈值，`--include-referenced` 全量 |

◆ = dsh 自定义工具（`engine/ghidra-rpc/ghidra_rpc/server/tools/dsh_tools.py`）。✎ = 写操作。⚠ = 无沙箱。
完整命令与参数：`~/Desktop/src/ghidra-bridge/ghidra-rpc-venv/Scripts/ghidra-rpc.exe --help`，或 `engine/ghidra-rpc/docs/` + `engine/ghidra-rpc/README.md`。

### 第 2 层：宿主工具脚本（◈ 直接 python 运行，不经 daemon/driver）

| 脚本 | 用途 |
|---|---|
| `rpc_driver.py` | 统一入口：项目映射/key 替换/@out/环境自给 |
| `ledger.py` | **铁律 7 机械断路器**：观察落账（同区回访强制 `--delta`）/权威结论锁定（`conclude` 强制 `--source`/`--independent` 来源标注，无独立来源标 ⚠UNVERIFIED）/卡点/render；`validate` 机器校验台账最小 schema（CI 判据用，违规 exit 2）；`status` 在 ≥5 观察 0 异常时打印铁律 12 提示 |
| `read_views.py` | **铁律 8 权威读数**：三视图读字节（hexdump/fromhex-ready hex/cstr）+ `--expect-len`/`--expect-hex` 一致性检查（失败 exit 2） |
| `crypto_sanity.py` | **铁律 9 求逆闸门**：`check`（常量长度/格式合法性：hex 偶数、base64 %4、流密码等长）+ `check-result`（反推结果可打印性/格式），违规 exit 2 禁止求逆 |
| `launch_gui.py` | detached 拉起 Ghidra GUI，可直接打开项目 |
| `doctor.py` | 环境自检（8 项：安装/JDK/双 venv/工作区/项目/rpc 包/daemon 起停），全绿 exit 0 |
| `pe_info.py` ◈ | PE 分诊：头/节表/熵/导入表/资源；PE32 与 PE32+ 双路径（ImageBase 与导入 thunk 宽度都按位数分派）。`python pe_info.py <exe>` |
| `decomp_lint.py` | **伪码体检（读伪码之前先跑）**：输入 decompile-all 的 @out JSON，输出 fatal 函数清单（跳转表未恢复等，这些函数禁止读伪码）+ 危险渲染计数；有 fatal exit 2 |
| `call_histogram.py` | CALL/JMP 目标直方图：从反汇编里数出"重复调用点"（≥3 次高亮 = 疑似分发器/校验体骨架），Rust/内联 main 场景的开工第一个动作（ctf-patterns §4） |
| `emulate_blob.py` | 裸 blob Unicorn 仿真骨架：`--base/--entry/--rsp/--max-insns/--reg/--map-file/--dump-dir`，停止原因分类 + dirty 页 dump；unicorn 缺失 exit 3 提示进 re-tools-venv（多层载荷题用，ctf-patterns §10） |
| `const_scan.py` | Cython/C 常量重建：扫反编译 C（或 decompile-all @out JSON）的 `PyList_New(n)`/`PyTuple_New(n)` + 随后常量写入，直接重建 Python 字面量；小整数聚集自动告警"疑似字节级常量表"（chal 复盘 T3：L 表 48 项实测重建） |
| `xor_scan.py` | blob 变换搜索：单字节 XOR 全扫 + 可选滚动密钥/ADD/SUB，按可打印率+magic（MZ/ELF/PK/UPX!）+flag 正则综合评分排 Top N；`--dump <key>` 落地解密产物（fakePE 复盘缺口 4，不要再现场手写第 5 版） |

### 第 3 层：legacy（冻结备查，被 rpc 取代）

`scripts/` 下 25 个 PyGhidra 脚本 + `driver.py` + `analysis_config.py`：**冻结，仅备查**。`driver.py` 仍是两条后路——(a) daemon 整体挂掉时的直接执行通道（`driver.py export/exec/exec-w`，用 pyghidra-venv）；(b) 调试脚本行为差异时的对照组。不要在新工作流里再用它们；行为差异以 rpc 为准。

✎ 注意：legacy 时代"写操作必须 exec-w 才存盘"的纪律**已由 daemon 的自动存盘取代**——rpc 写命令每次写完即 `project.save()`，`stop` 时再全量保存。

### 执行模型（engine 内部，排障时读）
- daemon 进程 = rpc-venv 的 python + 进程内 JVM（pyghidra）；transport = 127.0.0.1 TCP + token（endpoint 文件在 `<ws>/rpc-localappdata/ghidra-rpc/`）
- session/registry 在 `<ws>/rpc-state/`（`GHIDRA_RPC_STATE_DIR`）；daemon 日志在 `<ws>/rpc-localappdata/ghidra-rpc/*.log`
- 所有 handler 由全局锁串行化——**并发客户端不会并行执行**，长命令会挡住其他命令
- daemon 崩溃后下一条命令自动按 session 重启（auto-restart）；`stop` 不干净时删 endpoint 文件再起

## 7. PyGhidra 移植须知

写新脚本、移植旧 Jython 脚本、排障启动/API 形状问题时读 `references/pyghidra-migration.md`（启动顺序、`LoadResults`、回调式 `walk_programs`、持久化限制与 `export` 绕法、实测覆盖表）。

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
| `references/pyghidra-migration.md` | 写新脚本/移植 Jython 脚本/排障启动与 API 形状时（PyGhidra 坑全集+实测覆盖表） |
| `references/crypto-ident.md` | 求逆前先认算法：常量指纹（AES S-Box/ChaCha20/MD5/SHA 初值）、CryptoAPI/CNG/OpenSSL 对照表、弱点清单（铁律 9 的上游） |
| `references/unicorn-harness.md` | 要跑"整程序级"仿真时（映 PE/ELF 进 Unicorn、填 IAT 桩、喂 stdin）：可套用骨架 + Win32 ABI 陷阱清单（IO_STATUS_BLOCK/NtReadFile/HeapReAlloc） |
| `~/.dsh/skills/ghidra-static/references/ctf-patterns.md` | CTF 模式库与 flag 狩猎启发式（XOR/期望值/oracle/自定义 VM/魔数，属 ghidra-static） |
