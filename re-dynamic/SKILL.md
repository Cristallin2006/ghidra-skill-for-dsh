---
name: re-dynamic
description: 让二进制跑起来观察行为：直接运行（ELF 走 WSL、PE 走本机）、函数级 Oracle（单函数调用+观察输入输出）、动态插桩入口。触发：静态看不懂/需要验证函数行为/拿到 check 函数要试输入/想"先跑起来看看"。不做静态分析——那是 ghidra-static。
whenToUse: 静态分析卡住要运行时事实时；验证 check 函数/算法猜想（喂输入看返回）；样本行为观察（先跑起来看）；需要 Frida/gdb/qiling 动态手段的入口指引
---

# RE Dynamic（场景 4：跑起来看）

前置：静态卡住或要验证猜想 → 从 `~/.dsh/skills/ghidra-static` 来；判型不明先 `~/.dsh/skills/re-triage`／后继：拿到运行时事实后回 ghidra-static 标注进台账

> **先跑起来看**：对可执行样本，静态深挖前先花 2 分钟跑一遍观察 I/O——运行行为常常直接告诉你程序结构（菜单、校验提示、魔数），省掉半小时静态。（铁律全文见 ghidra-core §1）

## 路径约定

```bash
ORACLE="$HOME/.dsh/skills/re-dynamic/scripts/oracle.py"
# 后端：WSL Ubuntu qiling（/root/re-pwn-venv，rootfs /root/qiling-rootfs，均已装）
```

## 1. 直接运行（第一选择，最便宜）

```bash
wsl -d Ubuntu -- /mnt/c/.../sample          # ELF（含加壳判断后的产物）
./sample.exe                                 # PE 本机直接跑
```

来源不明/疑似恶意的样本先评估再跑（快照 VM 更佳）；程序等输入就给输入，看输出猜结构。**观察到的每一个行为事实都用 ghidra-core `scripts/ledger.py observe` 回写台账**（机制见 ghidra-core references/evidence-ledger.md）。

## 2. 函数级 Oracle（oracle.py）

给定二进制 + 函数地址（Ghidra listing 里的地址）+ 参数，真实调用该函数并返回 JSON（retval/stdout/regs/stop_reason）。CTF check 函数验证的标准动作：喂候选输入，看返回 0/1。

```bash
python "$ORACLE" <binary> 0x101064 1 0x20              # 整参（SysV 前 6 / Win64 前 4）
python "$ORACLE" <binary> 0x1020a0 str:flag{guess}     # 字符串参数（自动写内存传指针）
python "$ORACLE" <binary> 0x1020a0 str:test @out.json  # @out 落盘约定
```

**能力与边界（v2，实测）**：

| 场景 | 状态 |
|---|---|
| 静态链接 ELF，任意函数（含 libc 调用） | ✅ 加 `--init-until <main 的 Ghidra 地址>` 先跑 CRT 初始化 |
| 动态链接 ELF，**leaf 函数**（不调 libc：XOR/比较/数学） | ✅ 直接调（PIE/非 PIE 地址自动换算） |
| 动态链接 ELF，调 libc 的函数 | ⚠️ `--init-until` 供使用，但 glibc 版本与 rootfs 不符时初始化可能崩（UC_ERR_FETCH_UNMAPPED）→ 升 Frida/gdb |
| **i386 ELF（32 位）** | ✅ v2 已支持（参数按 cdecl 压栈；rootfs x86_linux） |
| PE（qiling windows rootfs） | 实验性：leaf 函数可调；复杂 PE 可能撞 API stub 缺失 → 升 Frida |
| 浮点参数 / 结构体参数 | 未支持（整型+字符串） |

**中间态取证（`--break` + `--dump`，v2 新增）**：在指定 PC 停下 dump 内存表达式，不用手写 gdb 脚本抓流水线中间态（base64 产物、XOR 中间值、比较前的密文缓冲区）：

```bash
python "$ORACLE" ./encode 0x804887c --init-until 0x804887c \
    --break 0x8048a10 --dump ebp-0x8c:28 --dump 0x804a020:32 --dump eax
```

dump 表达式：`reg+/-0xoff:len`（寄存器相对）、`0x地址:len`（Ghidra 地址，自动换算运行时）、裸 `reg`（只读寄存器值）。`--max-hits N` 控制断点命中几次后停录（默认 1）。断在函数入口时 prologue 尚未执行——`ebp` 还是调用者的，栈参数用 `esp+4:8`（32 位）/寄存器（64 位）读。

已知行为：libc stdout 全缓冲——oracle 的 `stdout` 可能为空但 retval 正确，需要输出证据时在函数里找 write/puts 直接调用或看 retval。

## 3. 升级阶梯（oracle 不够用时）

① **Frida**（re-tools-venv 已装）：真实进程 hook——反仿真/复杂 API/要看中间状态时用；`frida`/`frida-trace` 入口见 ghidra-static references/ctf-patterns.md §6
② **gdb + pwndbg**（WSL 已装）：断点单步、内存断点；`wsl -d Ubuntu -- gdb /mnt/c/.../sample`
③ **angr**（re-tools-venv 已装）：符号执行求输入——"什么输入能让 check 返回 1"的直接求法，路径爆炸时慎用

## 防死循环

oracle 搭不起来（缺 stub/反仿真/地址算不对）→ 按阶梯升，**每级 ≤15 分钟**；禁止反复重试同一层（铁律 6/7，全文见 ghidra-core §1；卡点写台账）。
