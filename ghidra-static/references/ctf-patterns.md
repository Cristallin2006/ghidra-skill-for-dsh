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

## 4. 自定义 VM 五步法

1. 识别 VM 结构：寄存器组 / 内存 / 指令指针
2. 逆 `executeIns` 分发器，提取 opcode 表
3. 写反汇编器把字节码转可读形式
4. **经常爆破比完整逆向更快**——评估两条路的成本再选
5. 找命令行参数/文件加载的字节码（可能独立成文件）

`printf %hhn` 型 VM → 直接翻译成 Z3 方程。

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
