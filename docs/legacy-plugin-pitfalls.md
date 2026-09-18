# AegisTrace 推进日志 + 坑记录

两条线分开记，因为归属不同、修复动作也不同：

- **【插件】** = `~/.dsh/plugins/reverse-ghidra`（11 个 ghidra_* 工具）
- **【Skill】** = `~/.dsh/skills/ghidra-reverse`（SKILL.md + 24 个 PyGhidra 脚本）
- **【环境】** = Ghidra / Java / PyGhidra / 沙箱 本身的行为

格式：`症状` → `根因` → `修法` → `状态`

---

## 一、本轮之前已定位（归档，供回溯）

### P-01【插件】`ctx.tools.register` 收下的 schema 原样下发，不编译简写 DSL
- **症状**：11 个工具全部 `Invalid schema: type: null`，工具注册了但模型侧不可用。
- **根因**：简写 DSL（`{name:'string'}` 这种）只在 `harness.defineTool()` 里编译；`ctx.tools.register` 直接存 verbatim，于是 `properties.x.type` 是 `undefined` → 序列化成 `null`。
- **修法**：插件内自带 `parameterSchema()`，把简写编译成 `{type:'object',properties,required}`。
- **状态**：已修，smoke.mjs 断言覆盖。

### P-02【插件】`childEnv` 透传了宿主 `USERNAME=Lenovo`，与项目 owner 冲突
- **症状**：`NotOwnerException: Project is owned by dsh`，import 后无法保存。
- **根因**：宿主进程的 `USERNAME` 被原样塞进子进程环境；Ghidra 用 `USERNAME` 判定 `ProjectLocator` 归属。项目由 `dsh` 创建 → 所有者是 `dsh` → 以 `Lenovo` 重新打开被拒。
- **修法**：`projectOwner()` 读 `<project>.rep/project.prp` 的 `OWNER`，`childEnv()` 强制覆盖。**通用教训**：不要在子进程里污染身份相关的环境变量。
- **状态**：已修，smoke.mjs 断言 `USERNAME==='dsh'`。

### P-03【插件】`BridgeQuery` 的 xref 只解析函数入口，解析不了数据地址
- **症状**：查 `FLAG_PATH@0010304c` 这类字符串/数据地址的交叉引用返回空。
- **根因**：实现里拿 `getFunctionAt(addr)` → `null` → 直接放弃。
- **修法**：加 `dataTarget` 回退分支，`kind: function|address`，`xrefTarget = f != null ? f.getEntryPoint() : dataTarget`。
- **状态**：已修，javac 编译通过。

### P-04【插件】我凭想象发明了一批动态插件 API
- **症状/根因**（一次性四个，都是幻觉 API）：
  - `require is not available in the dynamic package sandbox` —— 用了 CJS `require`
  - `setTimeout is not available in the dynamic package sandbox` —— 用了宿主全局定时器
  - `SubprocessHandle has no pid` —— 我假定它能拿 pid
  - `'succeeded'` 不是合法终态 —— 我编了个状态名
- **修法**：全部回到 Cordis service（`fs`/`subprocess`/`timer`）；`ctx.timeout` 与 `handle.done` 竞速并在 `finally` dispose；spawn 只判 `handle === undefined`；终态用 `completed|failed|orphaned`。
- **状态**：已修。**教训**：用 Inspect Provider 查真实签名，不要凭记忆写。

### P-05【插件】作业日志被截断
- **症状**：长作业的 job journal 只有开头一段。
- **根因**：完成时立刻 `stopPump()`，管道里还没读出来的尾部丢了。
- **修法**：完成前先 `drain()` 再 `stopPump()`；改用基于 offset 的增量读取。
- **状态**：已修。

### P-06【环境】`ProjectLocator` 拒绝路径中任何以 `.` 开头的目录
- **症状**：`~/.dsh/ghidra-workspace` 无法作为 Ghidra 工作区。
- **修法**：`C:\Users\Lenovo\dsh-ghidra-workspace` 目录联接指向真身。驱动脚本自动建。
- **状态**：已修（`driver.py: project_root()`）。

### P-07【环境】`analyzeHeadless` 的 `-import` 与 `-process` 互斥
- **症状**：`Must use either -process or -import parameters, but not both`。
- **修法**：只要 import 就够（默认自动分析 + postScript + 保存）。**这正是 SKILL.md 原本就写对的用法**，是我把它改错了。
- **状态**：已修；SKILL.md §7.10 已写明边界。

### P-08【环境】Jython 扩展其实装了，是被我重定向 APPDATA 打掉的
- **症状**：`JythonStubScriptProvider$JythonStubException: ... you must install the Jython Ghidra Extension, or (recommended) port your script to PyGhidra or Java.`
- **根因**：我为了隔离把 `APPDATA`/`LOCALAPPDATA`/`USERPROFILE` 重定向到工作区内的 `settings\`，Ghidra 于是在那里找扩展 → 找不到。真身在 `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\Jython`（含 `data\jython-2.7.4\Lib`）。
- **修法**：两条路 —— ① 把扩展目录联接进去；② 全部脚本迁 PyGhidra（已选 ②）。
- **状态**：已修。**教训/Skill 侧更正**：SKILL.md §0 原本的设计是对的，不该改。

---

## 二、本轮已修（工具补齐）

### P-09【插件 + Skill】缺原始反汇编入口
- **症状**：`ghidra_decompile` 只给 C。我要确认 12 字节头的字段序时，反编译器的栈槽命名（`local_1058`/`iStack_1054`/`uStack_1050`）**给出了错误的结论**，我据此推了 3 轮错的 keystream。
- **修法**：`BridgeQuery.java` 加 `mode=disassembly|count`（`target` 为函数名则止于函数体，为裸地址则一路往下读；带 `bytes` 字段；`offset`+`hasMore` 支持翻页），`ghidra_query` 暴露该 mode。
- **验证**：`001013d3  MOV EBX,dword ptr [RSP + 0x10d4]` —— 这就是推翻错误结论的那条指令。
- **状态**：已修，javac rc=0 + 实测通过。

### P-10【Skill】`decompile_function.py` 一次只吃一个函数
- **症状**：16 个函数 = 16 次 JVM 冷启动。`BridgeDecompile.java` 本来就支持逗号/空格分隔的列表，是 skill 侧的 Python 脚本只取了 `args[0]`。
- **修法**：`split_identifiers()` 按 `[,;\s]+` 切分；`DecompInterface` 只开一次；输出加 `functions[]`/`decompiled_count`，单函数时保持旧字段不变（向后兼容）。
- **验证**：5 个函数一次调用，**29 秒**，`decompiled=5`。
- **状态**：已修。

### P-11【Skill】driver 跑不了 skill 目录外的 `.java` 脚本
- **症状**：`pyghidra.ghidra_script(path=<abs>.java)` → `ClassNotFoundException: Failed to find source bundle containing script`。`JavaScriptProvider` 需要脚本目录已注册为 source bundle，pyghidra 这条路径不注册。
- **修法**：`driver.py` 的 `cmd_exec` 对 `.java` 走 `analyzeHeadless -scriptPath ... -process ... -noanalysis -postScript`（与插件同一条路）。脚本名解析也加上了 `<ws>/scripts`。
- **状态**：已修。

### P-12【环境】`analyzeHeadless` 的 `-scriptPath` 要正斜杠
- **症状**：`InvalidInputException: Bad argument: C:\Users\Lenovo\.dsh\ghidra-workspace\scripts`。
- **根因**：analyzeHeadless 用 **Java property parser** 读自己的参数，`\.` 被当成转义序列。**项目目录也一样**（`-scriptPath` 之外的位置参数走同一条解析）。
- **修法**：加 `_as_posix()`，项目目录和 scriptPath 全部转正斜杠。
- **状态**：已修。

### P-13【插件】编译期才暴露的 Ghidra API 误用
- **症状**：我写的 `ins.getDefaultOperandRepresentation()` 和 `getDefaultOperandRepresentationList()` 都缺参数。
- **根因**：这两个方法都要 operand index；`getDefaultOperandRepresentationList()` 也不是"取全部操作数"。
- **修法**：改用 `getNumOperands() > 0 ? ins.getDefaultOperandRepresentation(0) : ""`，加 `bytesOf(ins)` 给原始字节，完整操作数交给 `text`。
- **状态**：已修。**教训**：往 `String.raw` 模板里写 Java 等于盲写，必须抽出源码用 javac 编一遍——见 `tmp/validate_tools.py`。

### P-14【插件 + 我】验证脚本自身的分析器 bug（不是被测代码的）
- **症状**：抽取嵌入式 Java 的贪婪正则 `String\.raw\`(.*?)\`,\n` 把下一个条目的结尾吞进上一个捕获，`BridgeProjects.java` 里混进了一段 JavaScript，javac 报了一屏"非法字符"。
- **修法**：改用 `([^\`]*)\`(?=,?\n)` 前瞻，不消费终止符。
- **教训**：**一次误报会掩盖真 bug**——修完贪婪匹配后，才露出真正的 `getDefaultOperandRepresentation` 参数错误（P-13）。

---

## 三、本轮我自己的分析错误（不属工具，但代价最大）

### A-01 把 PIE 当成 image base `0x100000`
- 所有地址多算了 `0x100000`：常量真值在 `0x3320`，我一直读 `0x103320` 且"读到了"看似合理的字节。**根因**：没读 program header 就先假设基址。

### A-02 hex 字面量里的空格被 `bytes.fromhex` 静默吞掉
- 隐式字符串拼接处混进一个空格 → `bytes.fromhex` **跳过空白不报错** → 68 字节变 67 字节、从错位处整体偏移。
- **代价**：产出"keystream 周期 12"这个**完全虚假**的结论，基于它推了好几轮。
- **修法**：`assert len(BLOB) == 68`。**教训**：`bytes.fromhex` 必须配长度断言。

### A-03 脚本里 XOR 了明文而不是 keystream
- `seg[i] ^ HDR[i]` 应为 `seg[i] ^ KS[i]`，造出"header 解不出来"的假矛盾，我甚至据此写了一段"framing test"。

### A-04 用"周期性"结论时没让脚本自己打印反例
- 周期性检查写成 `all(...)`，通过与否都只打印一行，没打印**在每个偏移上是否成立**。改成逐偏移输出后，一眼就看出 12 不是周期。

**共同教训**：一次性密码学脚本必须自证——长度断言、逐项反例、以及"这个结论如果是错的，脚本会怎么表现"。三处错误都是**静默**的。

---

## 四、自检轮（skill 专项）

### P-15【Skill】`apply_c_types.py` 定义的类型不落盘，下一步就找不到
- **症状**：`apply_c_types.py` 返回 `status:success`、`types_added_count:14`（`/aegis_hdr`、`/aegis_op` + 12 个 stdint typedef），紧接着 `apply_data_type.py 0x101300 aegis_hdr` 报
  `{"status":"error","error":"Data type not found: aegis_hdr","hint":"define it first with apply_c_types.py"}`。
- **根因**：`driver.py exec`（非 `exec-w`）是**只读运行**，类型库不保存。脚本本身没错，错在操作顺序没写清。
- **修法**：SKILL.md §5 加了「类型库两步走必须都用 `exec-w`」并给出可直接复制的两条命令；不想落盘就把定义+套用合并进一个 `exec_code.py` 文件，一次运行内完成。
- **状态**：已修（文档）。

### P-16【Skill】文档指向一个已被删除的文件
- **症状**：SKILL.md 两处说 `run-headless.sh`「已废弃」「仅存档在目录里」，但该文件**已从 scripts 目录删除**（被一次清理带走，同批清掉了 `__pycache__`）。
- **修法**：改成「曾在目录里，现已删除」，并从目录清单里移除；同时明确 `analyzeHeadless` 只由 `driver.py` 的 `.java` 分支调用，不要直接拿它跑 `.py`。
- **状态**：已修。

### P-17【Skill】三处计数互相矛盾
- **症状**：`L12` 说「另新增 6 个」，`L44`/`L212`/`L214` 说「21 个」，而磁盘上是 **25 个任务脚本 + 2 个 helper = 27 个 `.py`**；清单还漏了新增的 4 个。
- **根因**：上游 21 个的计数在新增 4 个后没同步更新（部分被并发写入方改了一半）。
- **修法**：统一成「上游 21 个 + 本 skill 新增 4 个 = 25 个任务脚本（共 27 个 `.py`）」，清单补全为 25 个。
- **状态**：已修。

### 并发生成的 4 个脚本（我做了独立验收）
时间戳 12:13–12:15，不是我写的，但用的是同一套约定（`@category DSH.Reverse` + `@runtime PyGhidra` + `@out`）。逐个实测：
- `exec_code.py` —— 文档承诺的名字空间**全部存在**：`program`/`listing`/`memory`/`fm`/`toAddr`/`find_function`/`output_json`（`fm.getFunctionCount()==96`）
- `export_binary.py` —— 导出 18576 字节，与原文件 **SHA256 完全一致**
- `apply_c_types.py` —— 解析 14 个类型成功（见 P-15）
- `apply_data_type.py` —— 依赖 P-15 的落盘前提

## 五、我自己的检查工具 bug（比被测对象的 bug 还多）

这一轮「自检」里，**我写错的检查比真缺陷多**：

| # | 我断言的 | 真相 | 教训 |
|---|---|---|---|
| V-01 | `--write` 应是 argparse 开关 | 它是 `p.set_defaults(func=cmd_exec, write=write)`，不是开关 | 别按别的 CLI 的习惯假设参数形态 |
| V-02 | `run-headless.sh` 应「存档在盘上」 | 它已被删除；我把「废弃」和「保留文件」混为一谈 | 断言前先确认文件存在性 |
| V-03 | 用 `md.split("裸命令模板")[0]` 判「有无裸命令回退」 | 正则跨小节误匹配，与意图无关 | 跨节匹配要结构化定位，别用 split |
| V-04 | 文档写的是 `25 个任务脚本` | 实际是 ``25 个任务 `.py` ``（带反引号） | 断言字符串要照抄，不要转述 |
| V-05 | 清单正则覆盖两句话 | 正则吞掉末尾的 `apply_data_type`，连报两轮假 FAIL | 两轮还不过 → 换成不需要正则的写法 |

**共同教训**（与 A-01~A-04 同源）：**检查代码本身也会静默错**。反复失败时先怀疑检查，而不是改被测对象——我前两轮就在改文档去迎合一个错的检查。

还有一次**真实的自伤**：`tmp/selfcheck.py` 第一版按 40 条一页翻 1568 条指令 = **约 40 次 `driver.py exec`**，每次冷启 JVM ≈ 25 秒，跑 10 分钟没结果，还和并发写入方抢 Ghidra 项目锁。改成 500 条一页（2 页）+ 单独探一次中段，就足以验证「无缝无重无漏」。

---

## 五、缺口验证轮（对着「还差什么」实测）

### P-18【架构】插件跑不了 skill 的任何一个 `.py` 脚本 —— 已确证，且有可行修法
- **症状**：插件走 `analyzeHeadless.bat`（**普通 JVM**），skill 的 27 个脚本全是 `@runtime PyGhidra`。把 skill 脚本交给插件的启动方式实测：
  ```
  ERROR REPORT SCRIPT ERROR: apply_data_type.py :
    Ghidra was not started with PyGhidra. Python is not available
  at ghidra.pyghidra.PyGhidraScriptProvider.getScriptInstance(PyGhidraScriptProvider.java:75)
  ```
  而且 `-postScript` 加载失败时 analyzeHeadless **仍返回 rc=0**，只在日志里留一行 ERROR —— 又一处静默失败。
- **影响**：插件只能跑它自带的 4 个 Java Bridge 脚本；`ghidra_script` 的 `scriptPath` 参数形同虚设。模型经插件拿到的是 9 个通用 mode，而不是 skill 那套针对性工具。
- **修法（已实测可行）**：插件改调 venv 里的 **`pyghidra.exe`**（它就是 PyGhidra 启动器）：
  ```
  pyghidra.exe --project-path <无点路径> --project-name <项目名> <二进制> <脚本.py> <脚本参数…>
  ```
  实测 `get_disassembly.py` 返回 `status=success, instruction_count=4`，含 `bytes` 与 `flows_to`。
- **三个硬约束**（都踩过）：
  1. `--project-path` **与二进制路径**都不得含以 `.` 开头的路径元素，否则 `IllegalArgumentException: Path element starting with '.' is not permitted`（老坑 P-06 在新入口重现；捕获包目录名 `AegisTrace_<hash>` 里的 `.` 也算）
  2. CLI **只接受一个脚本位置参数**，多给会被当成第二个脚本路径
  3. `--skip-analysis` 会吞掉其后的位置参数，别用
- **状态**：未修（改插件需重启进程才能验证，本会话会失效）。

### P-19【验证】我的探测器把 P-02 又犯了一次
- 写 `gap_probe.py` 时我用 `USERNAME=dsh` 起进程，撞回 `NotOwnerException: Project is owned by Lenovo` → **整轮探测返回假 rc=1**，差点得出"插件路径完全跑不通"的错误结论。
- **修法**：从 `<project>.rep/project.prp` 读 `OWNER` 再设环境变量。
- **教训**：同一个坑可以在「我已经写进文档」之后**再踩一次**——文档不会自动生效，检查清单才会。

### P-20【工具】Ghidra 项目锁是**独占**的
- 两个分析进程不能同时打开同一项目。我的自检作业与并发写入方互抢，自检被卡死 10 分钟（日志为空、进程挂起）。
- **应对**：同一项目串行；长任务放后台且只留一个在跑。

---

## 六、仍然存在的缺口

| 缺口 | 影响 | 归属 |
|---|---|---|
| **插件与 skill 互不相通** | 插件不知道 skill 存在（`index.js` 里对 `skills`/`driver.py`/`pyghidra` 零引用），跑不了那 27 个脚本；见 P-18 | 架构，**最高优先** |
| 插件改动**不热重载** | `lib/index.js` 的编辑在下次 DSH 进程启动才生效；本会话新工具尚不可用 | 平台行为，非 bug |
| `ghidra_decompile` 的「多程序」批量 | `processAll` 时每程序写同一个 out 文件会互相覆盖 | 插件，低优先 |
| Ghidra 项目锁是**独占**的 | 两个分析进程不能同时用同一项目；并发会话会互相卡住 | 环境，需避免并发 |
| 两处 Ghidra 工作区 | 插件默认 `~/Desktop/src/ghidra-bridge`，skill 默认 `~/.dsh/ghidra-workspace`（经 junction）。同一二进制会得到两个项目 | 配置，需统一 |
| Keystream 求解仍是一次性脚本 | `tmp/solve_ks.py` 未产品化 | 可选 |


