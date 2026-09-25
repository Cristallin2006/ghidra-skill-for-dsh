# Unicorn 整程序仿真 harness（PE/ELF 映进 Unicorn，跑 main，喂 stdin）

工具谱系的中间层：`emulate-function`（P-code 一次性仿真，只跑纯叶子函数）与 re-dynamic（Frida/gdb/angr 真机）之间的空档——**把 PE/ELF 映进 Unicorn、填 IAT 桩、挂 Win32/libc 导入桩、把 main 当函数跑、喂 stdin、在成功/失败点下断**。Rust/Go 重度内联、"main 即校验体"这类 CTF 逆向题的实际解法就在这里。

## 1. 何时用（决策边界）

| 场景 | 手段 |
|---|---|
| 纯叶子函数，给定输入要输出 | `emulate-function`（ghidra-core §5） |
| 整程序带 I/O（stdin / 堆 / 同步），不解壳跑 main | **本文** |
| 裸 blob / shellcode / 指令流解码器（无导入、无 I/O） | `scripts/emulate_blob.py`（见 §4） |
| 需要真实 Win32/libc API 行为、最终交付验证 | Wine / 真机（re-dynamic） |

**独立验证引擎排序**（re-dynamic §4⑤ 独立性排序）：**Wine > 真机 > 第二套自写实现 ≫ 另一个 Unicorn harness**——Qiling 底层也是 Unicorn，不构成独立引擎；自写 harness + Qiling 交叉 ≠ 铁律 10 要求的两个独立来源。没有 Wine 时的正确兜底是按汇编用纯 Python 重实现第二套模型交叉比对，不是再套一个 Unicorn。

## 2. 可套用骨架（伪代码级，结构完整）

```python
uc = Uc(UC_ARCH_X86, UC_MODE_64)

# ① 映射镜像：按节区 mem_map + mem_write（PE 按 VirtualAddress/VirtualSize 对齐到页）
for sec in sections:
    uc.mem_map(align_down(sec.va), align_up(sec.size))
    uc.mem_write(sec.va, sec.data)

# ② 映射栈/堆：栈自顶向下预留，堆用 bump allocator（heap_top 自记）
uc.mem_map(STACK_BASE, STACK_SIZE); uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)
uc.mem_map(HEAP_BASE,  HEAP_SIZE)  # heap_top = HEAP_BASE

# ③ 填 IAT 桩：每个导入槽写一个唯一桩地址（STUB_BASE + i*0x10），建 桩地址→导入名 反查表
for i, (dll, name) in enumerate(imports):
    uc.mem_write(iat_slot(name), p64(STUB_BASE + i * 0x10))

# ④ 挂导入 handler：hook_code 命中桩地址 → 查表分发 Python 实现 → ret
def on_code(uc, addr, size, _):
    if addr in stub_table: handlers[stub_table[addr]](uc)   # 实现里读参数、写返回、pop 返回地址跳回
uc.hook_add(UC_HOOK_CODE, on_code)

# ⑤ 喂 stdin + 跑 + 断点判定
stdin_queue.append(input_bytes)
uc.emu_start(entry, until=0, count=INSN_BUDGET)
# 判定：到达 SUCCESS_ADDR / FAIL_ADDR，或校验计数器终值
```

要点：指令预算（`count=`）必给，防死循环挂死；`on_bad_mem` 钩子只管 guest 越界，**Python handler 侧越界不触发它**（见 §3 第 3 条）；每次运行落 `@out`，单次目标 ≤0.1s 才有当 oracle 用的价值。

## 3. ABI 陷阱清单（每条都真实咬过人）

| # | 陷阱 | 正确做法 | 错误的表现形式 |
|---|---|---|---|
| 1 | `IO_STATUS_BLOCK.Information` 布局 | x64 下是**偏移 8 的 `ULONG_PTR`**，不是偏移 4 的 `ULONG` | 写错 → `read()` 永远返回 0，表现为"数据没进来"，第一嫌疑人会被误判成程序逻辑（Rust std 路径） |
| 2 | `NtReadFile` 签名 | 4 个寄存器参数 `(h, event, apc, apcctx)` + **5 个栈参数**，返回 `NTSTATUS` | 按 `ReadFile` 签名处理 → IAT 槽指向自桩，"成功返回但什么也没干"——**静默错误**，无异常 |
| 3 | `HeapReAlloc` 参数序 | 大小是**第 4 个参数（R9）**，不是 R8（旧指针） | 拿错参数 → 堆顶跳跃式假分配（实测一次跳 ~0x30000000、累计"分配"12.8 GB），错误在 **Python handler 侧**抛出 `UC_ERR_WRITE_UNMAPPED` 且 `crash=None`——看起来像 guest 炸了 |
| 4 | `core::fmt::Arguments` 布局 | `{pieces: &[&str], fmt, args}`，不是 `{ptr, len}` 的 `&str` | 当 `&str` 读会读出描述符首字节（如 `b'8'`）——**铁律 8 的"读数可疑"信号，第一眼别信** |
| 5 | `uc.mem_read` 返回类型 | 转 `bytes()` 再 `mem_write` | 直接喂回 → ArgumentError |

**总纪律**：自建 handler 从第一行就带边界检查和显式诊断（出事之后再补的代价是按小时计）；harness 必须当被测对象对待——**正负对照 + 已知答案自检 + 独立引擎复验**（铁律 10②），缺已知答案就做分件自检（编码器模型 vs 仿真观测、S 盒模型 vs 独立 RC4 实现），失败的自检线程**不许遗弃**。

## 4. 与 `scripts/emulate_blob.py` 的分工

| 需求 | 工具 |
|---|---|
| 裸 blob：无导入、无 I/O 的 shellcode、多层壳的指令流解码器（`POP RBX` 取基址 + 上万条 `[rbx+disp]` 原地改写） | `emulate_blob.py`：`--base/--entry/--rsp/--reg`，跑完自动 dump 改动页 |
| 整程序：有 IAT、调 Win32/libc、吃 stdin 的 main | **本文骨架** |

裸 blob 场景禁止先做直方图/余弦等统计判型（它既不是代码也不是数据的统计画像，会被判成"填充"）——**命中即仿真**（ghidra-static `ctf-patterns.md` §10）。

## 5. 判据：什么时候这层是答案本身

校验体 = N 个重复调用点、输入槽可探得相互独立时（`call_histogram.py` 数 CALL 直方图 + 逐位翻转探独立性），**逐槽枚举即可出解，VM 内部语义完全不需要读**——此时 harness 不是辅助手段，是解法本体（实测：44 独立槽 × 2816 次运行 = 62 秒出解）。

---

*素材来源：`Desktop/fupan/happyVm逆向复盘.md` §5（ABI 陷阱 5.9–5.13）、§6.1（谱系空档），`load-fakePE-逆向复盘.md` §4 缺口 1（裸 blob 仿真分工）。*
