# CTF 模式库与 Flag 狩猎启发式

## 1. 解题模式 → 打法映射

| 模式 | 识别特征 | 打法 |
|---|---|---|
| 逐字符校验 | 循环里逐字节 cmp | 逐字节爆破 / 约束求解 / 侧信道 oracle |
| 矩阵/线性变换 | .rodata 大矩阵 + XOR 行操作 | Z3 / numpy 逆运算 / GF(2^8) 高斯消元（常量 `0x1b` 是信号；flag 长度 = sqrt(矩阵大小)） |
| 自定义 VM | 取指-译码-执行循环 | 五步法（见 §4）；经常"爆破比完整逆向更快" |
| 不可逆变换 | 1000 轮迭代/哈希 | OpenMP 逐块爆破就是 intended solution |
| 迷宫/路径 | 二维数组 + 方向判定 | BFS/DFS 自动求解 |
| 渲染型 flag | 像素/位图比较 | 提取期望位图 + OCR（whitelist 含 `{}_`）；`.rdata` 里 XOR 存期望像素 |
| 时间锁 | 大整数常量比较 | faketime / patch |
| 逐字节均匀变换 | 改输入一字节只影响输出一字节（零扩散） | 建 0..255 映射表直接反查 |
| 前缀独立哈希 | 每个前缀独立 hash（Hashinator 型） | 逐字符恢复；`subprocess.run(timeout=2)` 防挂 |

## 2. Flag 狩猎启发式

- **已知前缀即钥匙**：flag 格式（`flag{`/`HTB{`/`dice{`…）用于 known-plaintext XOR、约束传播、候选筛选。变体 `cipher[i] = plain[i] ^ key[i%k] ^ i`——先剥离 index。
- **期望值在 .rodata/.rdata**：大小 ≈ flag 长度、紧邻比较指令的数据块；named data symbols（`EMBEDDED_*`）直接离线提取。`objdump -s -j .rodata binary`。
- **比较函数即 oracle**：hook strcmp/memcmp（Frida/LD_PRELOAD）抓期望值；替换 memcmp 返回匹配字节数 → 逐字节 oracle。
- **堆栈字符串/stack strings**：.rodata XOR blob + 循环态魔数（`0x9E3779B9` 等）→ 找 decode 例程 xref，解密后 dump 回注。
- **假 flag 干扰**：搜 `n0t_th3_r34l` 类模式；多个 decoy 在前时**断点下在最终比较点**；输入正确长度任意值让程序自己算答案再 dump。
- **main 平凡时查析构**：`__cxa_atexit`/`.fini_array` 藏校验。
- **提示语进 flag**：题目 hint 经常原样出现在 flag 正文。
- **比较方向**：分清 `transform(input)==stored`（要逆变换）与 `transform(stored)==input`（直接变换）。

## 3. XOR 与加密速查

- Known-plaintext：重复 key XOR 用 flag 前缀恢复 key 前 N 字节。
- 自修改代码：块起始的已知 opcode 暴露 XOR key。
- 魔数库：Xorshift32 移位 13/17/5；Xorshift64 移位 12/25/27；TEA `0x9E3779B9`；xxHash `0x9E3779B97F4A7C15`、`0x85EBCA6B`；DJB2 5381；FNV `0xcbf29ce484222325`；ROR13（API 哈希）；GF(2^8) `0x1b`。
- API 哈希解析别逆哈希：hook 目标 API 抓解析结果。
- 混合运算逆向：逆序 + 逆操作交换（`add↔sub`、`rol↔ror`、xor 自逆）。
- **S-box 识别先对指纹，禁止猜标签**（chal 复盘 F2：SM4 S-box 被误标 "AES inverse S-box"，台账结论被推翻过一次）。按前 16 字节比对；对不上就写"未知 256 字节置换"，**不许**写具体算法名：

  | S-box | 前 16 字节（hex） | 校验点 |
  |---|---|---|
  | AES forward | `63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76` | 末字节 `0x16` |
  | AES inverse | `52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb` | 末字节 `0x7e` |
  | SM4 | `d6 90 e9 fe cc e1 3d b7 16 b6 14 c2 28 fb 2c 05` | 末字节 `0x48` |
  | DES S1（32→6bit，64 项） | `e 4 d 1 2 f b 8 3 a 6 c 5 9 0 7`（十进制） | 共 8 盒 512 项 |

## 4. 自定义 VM 五步法

1. 识别 VM 结构：寄存器组 / 内存 / 指令指针
2. 逆 `executeIns` 分发器，提取 opcode 表
3. 写反汇编器把字节码转可读形式
4. **经常爆破比完整逆向更快**——评估两条路的成本再选（这是开工第一个动作，不是卡住后的退路）
5. 找命令行参数/文件加载的字节码（可能独立成文件）

`printf %hhn` 型 VM → 直接翻译成 Z3 方程。

**重复调用点判据（把第 4 条落成机械动作）**：若校验体是 N 个重复调用点（`main` 内联几百上千行伪码时，停止阅读，改对反汇编跑 `call_histogram.py` 统计 CALL 目标直方图）→ 先探每个调用点的输入槽是否独立（逐位翻转输入，看失败计数器是否只动一位）→ **独立就逐槽枚举，别读 VM 语义**。实测：22 调用点 × 2 槽 = 44 槽独立，逐槽枚举 62 秒出解，完整读语义花了整场 1/3 时间且非必要（happyVm 复盘）。Rust 重度内联场景同理：`main` 上千行伪码 = 信号不是挑战，先数直方图。

## 5. 侧信道 Oracle（静态走不通时的兜底）

| 信道 | 做法 |
|---|---|
| 信号计数 | `strace -e signal=SIGFPE` 计数逐字符爆破（信号处理 = 静态不可见的隐式控制流） |
| 指令计数 | Pin inscount0：正确字符 → 指令数多 ~1000+；对 movfuscator 有效；失败时只数特定分支地址 |
| timing | pwntools 爆破模板：正确前缀 → 响应慢 |
| memcmp 替换 | hook memcmp 返回匹配字节数 → 逐字节 |
| INT3+coredump | `printf '\xcc' \| dd of=binary bs=1 seek=$((off)) conv=notrunc` → core 里 strings 提结果 |
| strace 抓 patch | `strace -f -e trace=process_vm_writev -e write=all`：父进程 patch 子进程 .text 对 strace 透明 |

通则：**正确性推进必产生可测量信号**——找到那个信号就赢了一半。

## 6. 动态工具选型（超出 Ghidra 范围时）

> 本机已装状态（2026-09-16 实测，doctor toolchain 节为实时真相源）：Frida ✅（re-tools-venv `Scripts/frida.exe`）；gdb+pwndbg ✅（WSL：`wsl -d Ubuntu -u root -- gdb`）；Qiling ✅（WSL `/root/re-pwn-venv`，Windows rootfs `/root/qiling-rootfs`）；angr ✅（re-tools-venv import）；x64dbg ✅（`~/Desktop/src/tools/x64dbg/release/x64/x64dbg.exe`）；pwntools/ROPgadget/ropper/one_gadget/seccomp-tools ✅（均在 WSL）。strace/LD_PRELOAD 类命令需在 WSL 里跑。

| 需求 | 工具 |
|---|---|
| hook 比较函数抓期望值 | Frida：`frida -f ./binary -l hook.js --no-pause`；`Interceptor.replace` 直接替换校验函数；Stalker 指令 trace；`Memory.scan` 扫 `flag{` |
| 自动探路 | angr：`simgr.explore(find=, avoid=)`；可打印 ASCII + 已知前缀约束；hook 掉 crypto/IO 防路径爆炸 |
| 免疫反调试 | Qiling：`ql.os.set_syscall("ptrace", hook)`，无调试器痕迹 |
| 不解壳跑单函数 | Ghidra EmulatorHelper（scripting.md §仿真；rpc `emulate-function` 命令见 ghidra-core §5） |
| 反编译看不懂 | dogbolt.org 多反编译器 side-by-side 对比 |
| Windows GUI crackme | x64dbg 断 `GetWindowTextA`/`MessageBoxA`；Scylla 修 IAT |
| 冻结随机性 | LD_PRELOAD 冻结 time()/rand() → VM 变确定性 oracle（WSL 内执行） |

## 7. 提取类技巧（不用跑二进制）

- 嵌入资源：`PK\x03\x04` 嵌入 ZIP；`readelf -s` 找 named symbols → dd 提取 → 纯离线解（readelf/objdump 在 WSL 里跑，见 §6 注）。
- 批量立即数提取：`objdump -M intel -d binary | grep -P "cmp\s+rdi" | grep -oP "0x\w{1,2}" | xxd -r -p`——**Ghidra 侧等价物就是 headless 脚本**（scripting.md §8 决策树/XOR 提取模板）。
- 补丁速查（pwntools）：`elf.asm(elf.symbols.ptrace, 'ret')`、`'nop'`、`'xor eax, eax; ret'`、`'mov eax, 1; ret'`；Ghidra 内 patch 用 `assemble`/`write-bytes`，导出用 `export-binary`（Original File 格式，不用开 GUI；命令见 ghidra-core §5）。
- JNZ(0x75)↔JZ(0x74) 互翻是最常见单字节 patch。

## 8. 流水线求逆纪律（先正向，后求逆）

`flag → 变换A → 变换B → 比较目标` 类题目的标准死法：直接求逆，模型错了也不知道错在哪。纪律：

-1. **先认出算法**（认不出算法时）：常量指纹（AES S-Box/ChaCha20 常量/MD5/SHA 初值）与 CryptoAPI/OpenSSL 对照表 → ghidra-core `references/crypto-ident.md`。认出标准算法后，求逆降级为"找密钥 + 调标准库"；认不出再按未知变换走下面流程。

0. **求逆前后各过一道机械门**（ghidra-core `scripts/crypto_sanity.py`，铁律 9）：求逆前 `check --algo hex|base64|xor|rc4 --constant ... [--plain-len N]`——常量长度不符合用途（hex 奇数、base64 非 4 倍数、流密码密文≠明文长度）一律 exit 2，此时第一嫌疑人是**读数**（跨缓冲区误读/吞前导 0），回第 3 条重取数，禁止带病求逆；求逆后 `check-result --text/--hex [--expect-regex]`——反推出不可打印字节 = 模型错的高置信信号，禁止据此宣布「校验不可满足」。
1. **先正向跑通**：拿到疑似密钥/密文后，先用已知输入（WP 答案、或任意输入+运行时抓的期望值）把完整流水线**正向**跑一遍——oracle.py 调真实函数、或 Python 重实现——确认模型能**复现已知输出**，再动手求逆。复现不了 = 模型错，回去修模型，禁止直接求逆。
2. **逐级对照中间态**：每个变换的输入/输出缓冲区用 `oracle.py --break <变换后PC> --dump <缓冲区>:<len>` 抓真实值，与模型预测逐级比对——第一级不符就停，后面全是垃圾。
3. **比较目标的读数只信 read_views**：CTF 题的比较目标常是内嵌二进制（IDA/反编译器渲染成 hex 文本时吞前导 0，`0x01`→`1`），`bytes.fromhex` 位数对不上就是信号。`read_views.py --expect-hex "<渲染文本>"` 一步对照，不符则以真实字节整体作废渲染文本。
4. **垃圾输入反推不出门槛**：`read()` 不补 NUL 时 strlen 会读到栈残留——门槛判定要用**已知能通过的输入**逼近，不要用垃圾输入的诡异行为反推。

## 9. 随机源分类表（mask / key / target，未分类禁止写入模型）

发现 `random.*` / `os.urandom` / `rand()` 调用后，**禁止直接预设它是掩码**——随机流有三种角色，判错角色 = 目标搞错（chal 复盘：把比对累加器的随机流当成输出掩码钉成 0，等于把比对项从模型里删除，整场方向判反）。

对每个随机调用做一次**钉值判别实验**：

| 钉成不同值后… | 分类 | 含义 |
|---|---|---|
| 输出变、校验涉及的状态量不变 | **mask**（掩码） | 只混淆返回值，可安全钉 0 拿"去掩码 oracle" |
| 输出不变、状态量变 | **target**（比对项） | 它是校验目标的一部分，钉 0 = 删除比对，绝对不能钉 |
| 输出与状态量都变 | **key**（密钥流） | 参与加密本身，要复现种子逻辑 |

配套实验：读校验路径写的所有状态量（Python 层 `dir()`/`__dict__` 免费可读；native 层 hook 目标函数前后 dump 状态区），用已知输入拟合其表达式（如 `tips = Σ(cipher ^ gb8)`）。**随机流抽取次数 == 密文长度**是 target 的强信号。

## 10. 多层载荷与"指令流解码器"模式

**识别指纹**（fakePE 复盘，差点被统计判型当填充丢掉）：载荷入口 `POP RBX`（或等价 call/pop）取自身基址，随后是成千上万条对 `[rbx+disp]` 的原地改写指令（`ADD/SUB/XOR/ROR/ROL/NOT/NEG`），**没有分支、没有调用**——这是一个用指令流本身当解码程序的存储式自解码器。

纪律：

- **命中即仿真**：直接 `emulate_blob.py`（或等价 Unicorn harness）跑完，dump 改动页——禁止对这段做直方图/余弦相似度等统计判型（它既不是代码也不是数据的统计画像，会得出"是填充"的错误结论）
- 高熵大块 + Ghidra xref 0 命中 ≠ 死数据：找注入式 stub 里的**绝对指针槽**（`LEA reg,[rip+disp]` / `movabs` 立即数落在该区域）——直接 xref 扫描看不到"运行时计算基址+偏移"的访问路径
- 多段解密产物按 `<ws>/out/<sample>.stageN.*` 命名（stage1=XOR 层、stage2=指令流层、stage3=内嵌 PE……），ledger 引用产物路径，禁止散放无名中间件
- 单字节 XOR 搜索固化在 `xor_scan.py`（可打印率 + magic + flag 正则综合评分），不要现场手写第 5 版

## 11. fp16/half 自检向量（手写 half 运算前先过这组）

half（IEEE 754 binary16：1 符号 / 5 指数 / 10 尾数，bias 15）没有顺手的主机工具时极易写错——
RNE 舍入、subnormal 边界、溢出→inf 三处是高频坑（DEFCON26 复盘：手写两遍 RNE、
subnormal 指数 off-by-one 卡一轮）。**手写 half 运算/转换的 harness 在支撑任何结论之前，
先拿这组向量自检**（铁律 10②：未通过已知答案自检的 harness 输出是零证据）。
全部期望值已用 `struct.pack('>e', x)` + numpy `float16` 双源实算核对（2026-09）。

**① RNE 舍入（round-to-nearest-even，float→half 转换）**：中点舍向**偶数尾数**，不是四舍五入。

| float 输入 | 含义 | half 期望 |
|---|---|---|
| `1 + 2^-11`（1.00048828125） | 0x3C00 与 0x3C01 的中点 → 舍向偶 | `0x3C00`（1.0） |
| `1 + 3×2^-11`（1.00146484375） | 0x3C01 与 0x3C02 的中点 → 舍向偶 | `0x3C02` |
| `1 + 5×2^-11`（1.00244140625） | 0x3C02 与 0x3C03 的中点 → 舍向偶 | `0x3C02` |
| `1 + 2^-11 + 2^-20` | 中点偏上一丝 → 正常入 | `0x3C01` |

（对应整数域的经典记忆锚点：0.5→0、1.5→2、2.5→2——中点总是去偶数。）

**② subnormal 边界（指数 off-by-one 陷阱全在这里）**：

| 值 | half 期望 | 备注 |
|---|---|---|
| `2^-24`（5.960464477539063e-08） | `0x0001` | **最小 subnormal** |
| `(1-2^-10)×2^-14`（6.097555160522461e-05） | `0x03FF` | **最大 subnormal**（尾数全 1） |
| `2^-14`（6.103515625e-05） | `0x0400` | **最小 normal**（指数域=1，隐含前导 1 从这里才开始） |
| `2^-14 - 2^-25`（最大 subnormal 与最小 normal 的中点） | `0x0400` | RNE 舍向偶尾数 → **向上**进成 normal，不是留在 subnormal |
| `2^-25`（0 与最小 subnormal 的中点） | `0x0000` | tie 舍向偶 → 0，不是 0x0001 |
| `2^-25 + 2^-30` | `0x0001` | 中点偏上才入 |

陷阱：subnormal 的隐含前导是 **0**（值 = 尾数 × 2^-24），normal 是 **1**（值 = (1+尾数/1024) × 2^(exp-15)）——
指数域从 0 变 1 时公式切换，off-by-one 就在这个接缝上；用 0x03FF/0x0400 这一对验收接缝两侧。

**③ inf/nan 编码与 float→half 溢出**：

| 输入 | half 期望 | 备注 |
|---|---|---|
| `inf` / `-inf` | `0x7C00` / `0xFC00` | 指数全 1、尾数 0 |
| `nan` | `0x7E00` | 指数全 1、尾数非 0（canonical quiet NaN；任何尾数≠0 的 0x7C01..0x7FFF 都是 NaN） |
| `65504.0` | `0x7BFF` | **最大有限值** |
| `65519.0` | `0x7BFF` | 中点（65520）之下，仍舍回最大有限值 |
| `65520.0` | `0x7C00`（inf） | 中点 tie 舍向偶 → 进位溢出成 inf，**不是**饱和到 0x7BFF |
| `70000.0` / `-70000.0` | `0x7C00` / `0xFC00` | 明确溢出 → ±inf |

注意 CPython `struct.pack('>e', x)` 对溢出输入**抛 OverflowError** 而不是给 inf（本组溢出向量用
numpy float16 核对）——harness 用 struct 时要自己 catch 并映到 ±inf，别把异常当题目行为。

**④ half→float 无损**：每个 half 位型转 float 都精确（binary16 ⊂ binary32），往返 half→float→half
必须恒等。抽查向量：`0x3C00`→1.0；`0x3C01`→1.0009765625；`0x0001`→5.960464477539063e-08；
`0x03FF`→6.097555160522461e-05；`0x0400`→6.103515625e-05；`0x7BFF`→65504.0。
harness 的 half→float 方向错一个都不该有——错 = 指数/尾数拼接逻辑本身就错了。

## 12. Cython / CPython 扩展模块元数据速查（先取元数据，再谈建模）

> 触发：triage `lang_hints.python_ext=true`（exports 有 `PyInit_*` / imports 引 `Py_Initialize` /
> 字符串含 `__Pyx_`）。出处：chal 复盘 §7.1——官方 WP 的元数据手法比纯读反编译 C 省一半时间；
> 若先取 `co_varnames`，`plVar8`/`local_198` 的角色之谜当场就解。
> **作用域**：仅限 Cython/手写 CPython 扩展；pyc 走 `pyc-bytecode.md`，PyInstaller 走 pyinstxtractor。

### 12.1 四个元数据源（按杠杆排序）

| 元数据 | 在哪 | 给出什么 |
|---|---|---|
| **`_Pyx_PyCode_New*(…, varnames=(...), 'chal.py', '_p1', 19, …)`** | 模块 init 函数里的 code object 构造调用 | **每个 Python 函数的局部变量名 + 源码文件名 + 行号**——`x1,x2,tmp,low,high,ans` 这类名字直接说明谁是谁 |
| `__Pyx_CreateStringTabAndInitStrings` 里的 `__Pyx_StringTabEntry` 数组 | 数据段（每项 = 指针+长度+编码标志） | 全部 interned 字符串：属性名/变量名/常量串 |
| `PyLong_FromLong` / `PyLong_FromString(s, 0, base)` | init 函数 / 常量区 | 大整数常量（如 `2654435769`），FromString 能给出超出 C int 的值 |
| `_Pyx_InitCachedConstants` 里的 `PyTuple_Pack(n, …)` | init 函数 | 常量元组（如 `(2654435769, 3337565984)` = randint 范围对） |

配套：列表常量（`PyList_New(n)` + 槽写）走 `const_scan.py`；槽写全是 `<DAT_…>` 缓存对象时
加 `--binary` 直接还原成 Python 值（CPython 布局自动投票）。行号也有用：Cython 生成的 C 里
`uVar34` 之类的行号标记可以把反编译语句**分组回源码行**，先按行分组再读。

### 12.2 本机可 import → 立刻升级为可编程 oracle

CPython 扩展且本机 Python 版本兼容时，`import` 它就完了——之后所有结论用"跑一遍看输出"判定，
不靠读 C 猜（chal：10 分钟确证 check 语义）。两张技巧卡：

- **Spy 子类拦截属性写入**：`class Spy(mod.Cls): def __setattr__(self,k,v): ...`——直接看到
  `__init__` 里每个状态单元写几次、真 check 读哪个量；配合 `dir()`/`__dict__` 读全状态。
- **差分读出累加器**：校验是 `acc == 0` 且 `acc += f(内部字节, 随机抽样)` 时，**强制第 k 个抽样为
  0/0xFF 看 acc 差值**，逐字节把内部操作数读出来——把"逆整个密码"归约为"已知目标流，求逆 E"。
  这是"先确定什么算对，再考虑怎么算"的机械形态。
- **退化配置解耦**：把未知量分成"结构"与"密钥"两组时，先注入退化配置（p1=identity / p2→0 /
  K 表注入）解耦结构，再用"有特征密钥"解下标——两次实验各解决一半，不要搅在一起。
- 随机流角色先按 §9 分类（mask/key/target），**未分类禁止写入模型**。

### 12.3 真值被宿主层遮住时

文本模型与 oracle 连续两轮对不上 → 走 re-dynamic「机器真值路线」（gdb 帧槽位取数，
CPython 3.12 `lv_tag` vs pre-3.12 `ob_size` 布局判别与 `const_scan --binary` 同源）。
**编译产物里的变量名一律无权威性**（decompiler-pitfalls：Cython 临时槽位会被复用，
`plVar8` 在不同语句里不是同一个量）——角色用元数据（12.1）或扰动实验（铁律 14）钉，不用名字猜。
