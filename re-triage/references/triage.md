# Triage 分诊（未知二进制的强制起点）

顺序：**Hash → 文件类型 → 壳/熵 → 语言/编译器 → imports 锚点 → 字符串快赢 → 反分析扫描**。
`triage` 命令（ghidra-core §5）自动完成 3~7 的 Ghidra 侧部分；1~2 用系统工具。

## 1. 硬门（不过门禁止深挖）

- **imports 锚点**：PE 看 IAT；DLL/SYS 的 exports 与 imports 并列必查；解析失败也要把失败输出记进证据，不得跳过。
- **干净导入表警告**：仅 kernel32/ntdll 且导入 < 15 → 高度怀疑 `LoadLibrary`+`GetProcAddress` 动态加载或 API 哈希。triage 的 `clean_iat_warning` 置 true 时，禁止凭静态 IAT 宣称"无网络/无文件能力"——去 bp `GetProcAddress` 或搜哈希常量（ROR13、DJB2 5381、FNV `0xcbf29ce484222325`）。
- **.NET 无 IAT 不算空**：走 dnSpy/元数据等价路径，不许空过硬门。

## 2. 高危 API 组合聚类（命中组合才有意义，单点可能是噪声）

| 组合 | 判断 |
|---|---|
| `FindWindowA/W` + `WriteProcessMemory` + `CreateRemoteThread` | 进程注入 |
| `CryptEncrypt`/`CryptAcquireContext` + 大量 `FindFirstFile`/`DeleteFile` | 勒索行为 |
| `InternetOpen`/`WinHttp`/`URLDownloadToFile` + `RegSetValue`/`CreateService` | 下载 + 持久化 |
| `VirtualAllocEx` + `QueueUserAPC` / `NtMapViewOfSection` | APC/映射注入 |
| `IsDebuggerPresent` + `NtQueryInformationProcess` + `rdtsc` | 反调试套件 → anti-analysis.md |

## 3. 语言/运行时识别（决定后续打法）

| 特征 | 语言 | 走向 |
|---|---|---|
| `go.buildid`、`runtime.gopanic`、hello world 都 ~2MB | Go | GoReSym 先跑（stripped 也能恢复 90%+ 符号）→ 只看 `main.*`；string={ptr,len} 非 NUL 结尾，默认字符串分析会漏 |
| `panicked at`、`_ZN` mangling、`.rustc` section | Rust | `strings \| grep panicked` 先挖（含源码路径/行号/变量名）；`rustfilt` demangle；泛型单态化代码膨胀，从字符串 xref 入手 |
| `mscoree.dll`、`_CorExeMain` | .NET | dnSpyEx + de4dot，**离开 Ghidra** |
| 无 CLR 头但有 `System.Private.CoreLib` | NativeAOT | native，留在 Ghidra |
| `global-metadata.dat` + libil2cpp | IL2CPP | native 部分在 Ghidra；元数据加密时 key=`SHA256(companyName+"\n"+productName)` |
| `PYINSTALLER`、`PY`+六位数字 | Python 打包 | pyinstxtractor 解包 → pyc 反编译；Pyarmor 8/9 用 Pyarmor-Static-Unpack-1shot |
| 节名 `UPX0/UPX1` | UPX | `upx -d`；失败 = 元数据被篡改，对照 UPX 源码修头 |
| 熵 > 7.5 + `.vmp0`/`.themida` | VMProtect/Themida | 不硬逆虚拟化：trace + 断点抓关键输入输出 |
| WASM magic `\0asm` | WASM | wasm-decompile / wasm2wat，离开 Ghidra |

## 4. 字符串快赢（triage 期必扫）

> **Git Bash 无 binutils**：`strings`/`readelf`/`nm`/`objdump` 一律加 `wsl -d Ubuntu -u root --` 前缀在 Ubuntu 里跑，Windows 路径写 `/mnt/c/...`。例：
> `wsl -d Ubuntu -u root -- strings -n 6 /mnt/c/path/to/binary | grep -iE "flag|pass"`
> `wsl -d Ubuntu -u root -- readelf -S /mnt/c/path/to/binary | head -20`
> （纯字符串提取也可用 Python 等价物：`re.findall(rb"[ -~]{4,}", open(f,"rb").read())`）

```bash
strings -n 6 binary | grep -iE "flag|pass|correct|wrong|usage|key"
strings binary | grep "/home/"          # 未 strip 泄漏编译路径
strings binary | grep -iE "^[a-z_][a-z0-9_]*::"   # Rust/C++ 符号
strings -el binary                      # Windows 宽字符（UTF-16），strings 空时必补
```

Ghidra 侧：`strings <bin> "(?i)flag|correct"`（命令见 ghidra-core §5）配合 `xrefs-to` 拿引用者地址。

## 5. 结构侦察清单

- **PE**：TLS Directory `AddressOfCallBacks`（回调先于 main 执行，反调试常藏这里）；导入/导出表；`.rdata` 期望值表；DOS stub 异常大 → 查藏代码（`int 16h`）；Rich 头泄露编译器版本。
- **ELF**：`readelf -S` 节表；`nm`/`readelf -s` 找 named data symbols（`EMBEDDED_*`、`ENCRYPTED_*` 直接离线提取）；`.init_array`/`.fini_array` + `__cxa_atexit`（main 看起来平凡时查析构函数藏校验）；`checksec` 缓解措施。
- **入口点 ≠ main**：PE 入口是 CRT 启动（`__scrt_common_main_seh` → main）；Go 入口找 `main.main`； stripped ELF 入口 `entry` 第一个参数即 main 地址。

## 6. 壳处理与 IAT 修复铁律

- x86 → ImportREC；x64 → Scylla（**禁止 64 位样本死磕 ImportREC**）。
- 修复工具报错或修复后全乱码（VMP/加密壳）→ **立即停止静态死磕**，转动态：对敏感 API 下断点抓真实导入。
- 脱壳后闪退/蓝屏 = 自校验（CRC over .text）→ 对 `CreateFile`/`GetFileSize`/哈希 API 下断。
- 自定义壳通用模式：`入口 → 少量初始化 → 解压函数 → mmap(RW) → 解压 → mprotect(RX) → 跳转`。自定义压缩算法可用 Python 重写解压器。
- 不想脱壳：EmulatorHelper 仿真解密 stub（scripting.md §仿真）。
- dump 出的内存段重导入 Ghidra：`-loader BinaryLoader -baseAddress <基址>`（headless.md §6）。
- ARM64 注意：位操作密集代码反编译器输出差，直接看汇编。

## 7. 平台速查

| 平台 | 要点 |
|---|---|
| 内核 .ko | Language 选 `x86:LE:64:default`；找 `file_operations` 结构体定位 ioctl handler |
| AArch64 | 返回地址在 x30(lr)；ADRP+ADD 地址对；NOP=`0xD503201F`；定长 4 字节指令 |
| MBR/引导扇区 | `qemu-system-x86_64 -fda disk.img -s -S` + gdb `set architecture i8086`，断 `*0x7c00` |
| KVM guest 题 | 链接 `-lkvm` 或开 `/dev/kvm` → 放弃常规流程直接 `strace -v -e ioctl`；HLT = 基本块边界 |
| Xtensa/ESP32 | radare2 或 Ghidra（支持 Xtensa），IDA 不支持 |
| APK native | 选 x86_64 的 .so 反编译质量最好；`JNI_OnLoad` → `RegisterNatives` 方法表追 fnPtr |
| 硬件 AES（MMIO/CP2） | `dmtc2`/`dmfc2` 是伪装的寄存器写，实际驱动硬件加密引擎 |

## 8. Triage 报告模板（交付时照填）

```
样本: <路径>  SHA256: <...>  大小: <...>
类型: PE64/ELF/...  语言/编译器: <...>  壳: 无/UPX/自定义
入口: 0x...  基址: 0x...  函数数: N
imports 锚点: <关键导入分组摘要；DLL 加 exports>
可疑命中: <组合>  干净IAT警告: 是/否
字符串快赢: <地址+内容 或 无>
语言路由决定: <本 skill 继续 / 换 dnSpy / 先脱壳 ...>
```
