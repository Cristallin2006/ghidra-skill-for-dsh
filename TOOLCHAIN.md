# TOOLCHAIN.md — skill 家族全部工具清单

机器可读探测的唯一真相源：`ghidra-core/scripts/doctor.py` 的 toolchain 注册表（`python doctor.py` 实时重测）。本文件是人可读的清单与安装原因，内容与注册表对齐。分 Tier：A=轻量高频已装 / B=重 pip 或 WSL / C=GUI 或插件。

## Ghidra 引擎栈（ghidra-core）

| 工具 | 路径 | 介绍 | 安装原因 |
|---|---|---|---|
| Ghidra 12.1.3 | `C:\t001s\ghidra_12.1.3_PUBLIC_20260817\ghidra_12.1.3_PUBLIC` | NSA 逆向框架 | skill 的分析引擎本体 |
| JDK（Java 25） | `C:\Java` | PyGhidra 起 JVM 用（必须 JDK） | 引擎运行依赖 |
| ghidra-rpc 0.2.0 + dsh 补丁 | editable 自 `~/.dsh/skills/ghidra-core/engine/ghidra-rpc`（装进 ghidra-rpc-venv） | 常驻 daemon 执行引擎 | 温热后每条命令 ~0.2s，替代一次性 JVM |
| ghidra-rpc-venv（Py3.12） | `~/Desktop/src/ghidra-bridge/ghidra-rpc-venv` | 引擎运行环境（pyghidra 3.1.0/JPype 1.5.2） | 引擎依赖 |
| pyghidra-venv（Py3.10） | `~/Desktop/src/ghidra-bridge/pyghidra-venv` | legacy driver.py 后路环境 | daemon 整体挂掉时的直接执行通道 |

## Windows CLI — re-tools-venv（`~/Desktop/src/re-tools-venv`，Py3.12）

| 工具 | 路径 | 介绍 | 安装原因（引用方） |
|---|---|---|---|
| frida 17.18.0（frida-tools 14.10.4） | `Scripts/frida.exe` | 动态插桩/hook | re-triage 转动态、ghidra-static §6、vuln-audit 动态验证、re-unpack 失败阶梯 ④ |
| z3-solver 4.13.0 | import `z3` | SMT 约束求解 | ghidra-static 约束求解/矩阵题（ctf-patterns）、anti-analysis 符号执行 |
| checksec.py 0.7.5 | `Scripts/checksec.exe` | PE/ELF 保护机制检查（NX/Canary/ASLR/CFG） | re-triage 判型补充；⚠ GBK 控制台需 `PYTHONUTF8=1` |
| rust-demangler | import `rust_demangler` | Rust `_ZN` legacy demangle（纯 wheel） | re-triage Rust 样本（无 cargo，rustfilt 的 pip 替代） |
| angr 9.3.4 | import `angr` | 符号执行/自动探路 | ghidra-static `simgr.explore`、vuln-audit 可达性、re-triage 静态死路兜底 |
| speakeasy-emulator 1.5.11 | `Scripts/speakeasy.exe` | Windows 用户态仿真 | 仿真备选（壳/恶意样本快速行为预览）；Py3.12 需 setuptools<81 的 distutils shim |
| ghidriff 1.0.0 | `Scripts/ghidriff.exe` | Ghidra headless 二进制 diff | ghidra-core headless.md §8 二进制比对补充（rpc 已内置 version-track） |
| simba-simplifier 0.0.1 | import `simba_simplifier` | MBA 混淆化简（Ghidra 集成） | re-triage anti-analysis.md 的 MBA 对策 |

注意：angr 把 z3-solver 钉到 4.13（从 5.1 降级，angr 的硬依赖约束）——两者共存无冲突。

## Windows CLI — tools/（绿色软件）

| 工具 | 路径 | 介绍 | 安装原因（引用方） |
|---|---|---|---|
| UPX 5.2.1 | `~/Desktop/src/tools/upx/upx.exe` | 加/脱 UPX 壳 | re-unpack Tier A 主力、re-triage UPX 节名路由 |
| GoReSym v3.4.1 | `~/Desktop/src/tools/goresym/GoReSym.exe` | Go 二进制符号/类型恢复 | re-triage Go 样本（go.buildid 路由） |
| pyinstxtractor 2.0 | `~/Desktop/src/tools/pyinstxtractor/pyinstxtractor.py` | PyInstaller 解包 | re-triage PyInstaller 路由 |
| dnSpyEx 6.6.0 | `~/Desktop/src/tools/dnSpyEx/dnSpy.exe` | .NET 反编译/调试 GUI | re-triage .NET 路由（离开 Ghidra 的那条） |
| de4dot-cex 4.0.0 | `~/Desktop/src/tools/de4dot/de4dot.exe` | .NET 反混淆 CLI | re-triage .NET 混淆（与 dnSpyEx 组合） |
| DIE 3.21 | `~/Desktop/src/tools/die/die/diec.exe` | 查壳/文件识别（diec=CLI） | re-triage 手工补充查壳 |
| x64dbg snapshot 2026-05-27 | `~/Desktop/src/tools/x64dbg/release/x64/x64dbg.exe` | Windows GUI 调试器 | ghidra-static Windows GUI crackme 动态分析 |

## WSL Ubuntu 24.04（`wsl -d Ubuntu`，root 直进；代理走宿主网关 `$(ip route default):7890`）

| 工具 | 路径 | 介绍 | 安装原因（引用方） |
|---|---|---|---|
| binutils 2.42（strings/readelf/nm/objdump） | `/usr/bin/` | ELF 分析基础件 | re-triage strings -el/readelf；**Git Bash 无 binutils**，这是唯一来源 |
| gdb 15.1 | `/usr/bin/gdb` | 调试器 | ghidra-static 转动态 |
| pwndbg 2026.9.15 | `/root/pwndbg`（.gdbinit 已接线） | gdb 增强（heap/context/telescope） | ghidra-static gdb 工作流 |
| pwntools 4.15.0 | `/root/re-pwn-venv/bin/pwn` | pwn 脚本框架 | ghidra-static pwn 题；pwn checksec 是 ELF 侧 checksec |
| ROPgadget 7.7 | `/root/re-pwn-venv/bin/ROPgadget` | ROP gadget 搜索 | ghidra-static ROP 链 |
| ropper 1.13.13 | `/root/re-pwn-venv/bin/ropper` | ROP gadget 备选（语义搜索） | 同上 |
| qiling 1.4.6 | `/root/re-pwn-venv`（import） | 全系统仿真 | re-unpack VMProtect64 档、re-triage 免疫反调试仿真 |
| qiling rootfs | `/root/qiling-rootfs`（sparse：x86_windows+x8664_windows；registry=python-registry 样本 hive 复刻，System32 DLL 49 个从宿主拷入） | Windows 仿真根文件系统 | qiling Windows 仿真必需 |
| one_gadget 1.10.0 | `/usr/local/bin/one_gadget` | libc 一把梭 gadget | ghidra-static pwn |
| seccomp-tools 1.7.1 | `/usr/local/bin/seccomp-tools` | seccomp 规则 dump/分析 | ghidra-static 沙箱题 |
| qemu-system-x86 8.2.2 | `/usr/bin/qemu-system-x86_64` | 整机仿真 | re-triage 固件/异架构 |
| upx-ucl 4.2.2 | `/usr/bin/upx` | Linux 侧 UPX（ELF 壳） | re-unpack ELF 样本 |
| ruby-full 3.x | apt | one_gadget/seccomp-tools 的运行时 | 依赖 |
| file 5.45 | `/usr/bin/file` | 判型 | re-triage（WSL 侧备选；Git Bash 也有） |

WSL 用法：`wsl -d Ubuntu -u root -- <cmd>`；Windows 文件在 `/mnt/c/...`。

## traffic-analysis 域（pcap/流量分析）

本域脚本（`traffic-analysis/scripts/`）**全零依赖**（Python stdlib），下列工具均为增强而非必需；可用性以 doctor.py toolchain 节为准。

| 工具 | 状态 | 用途 | 安装 |
|---|---|---|---|
| tshark / editcap（Wireshark 组件） | 未装（Tier C） | 协议分层统计、`--export-objects` 文件提取、pcapng→pcap 转换 | Wireshark 安装包勾选 TShark；无它走 `pcap_triage.py` 保底 |
| scapy | 未装（Tier B） | pcap 脚本化解析进阶备手 | `pip install scapy`（进 re-tools-venv） |
| aircrack-ng | 未装（Tier B, WSL） | WPA 握手破解、airdecap-ng 二次分析 | WSL `apt install aircrack-ng` |
| hashcat | 未装（Tier B, WSL） | NTLMv2（-m 5600）、WPA（-m 22000） | WSL `apt install hashcat`；GPU 场景用 Windows 官网 zip |

## Android 工具链（android-re）

多数零成本已装（Android SDK 自带），doctor.py toolchain 节已全部注册。

| 工具 | 路径 | 用途 | 状态 |
|---|---|---|---|
| jadx 1.5.6 | `~/Desktop/src/tools/jadx/bin/jadx.bat` | Java 层反编译第一源（消除自写 DEX 解析器的动因） | 已装 |
| apkanalyzer | `%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest\bin\` | 官方 smali 反汇编（带行号/局部变量），双源验证第二来源 | 已装（SDK 自带） |
| adb | `…\platform-tools\adb.exe` | 安装/驱动/uiautomator/screencap | 已装（SDK 自带） |
| emulator + system-image android-33 x86_64 | `…\emulator\`、`…\system-images\` | 无头真机 oracle（WHPX 加速可用） | 已装 |
| aapt2 / apksigner / dexdump | `…\build-tools\37.0.0\` | 资源解析/重签/dexdump 验证路径 | 已装（SDK 自带） |
| sdkmanager / avdmanager | `…\cmdline-tools\latest\bin\` | 装镜像/建 AVD（长耗时走后台） | 已装（SDK 自带） |
| androguard 4.1.4 | `~/Desktop/src/re-tools-venv`（import） | DEX 解析 + DAD，交叉验证 | 已装 |
| javac / java（JDK 25） | `C:\Program Files\Common Files\Oracle\Java\javapath\` | 反编译结果编译执行 = 执行级 oracle | 已装 |
| uncompyle6 / decompyle3 / xdis | re-tools-venv（import） | PyInstaller pyc 反编译 | 已装 |
| capstone / unicorn / lief | re-tools-venv（import） | 反汇编/仿真/格式解析库 | 已装 |
| pywin32 | — | Windows GUI 消息驱动（re-dynamic） | **未装**：`pip install pywin32` |
| apktool / baksmali | — | 资源完整还原+回编译 / smali 回汇编 | 未装（Tier C，jadx+apkanalyzer 已覆盖主场景） |
| frida-server（android） | — | 模拟器 Java 层 hook | 未装；版本必须与 host frida 17.18.0 严格一致 |

## Ghidra 插件（`%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\Extensions\`，launch_gui 用真实 profile 生效）

当前无新增插件。Jython 扩展（`Extensions\Jython`）是上一轮所装，保留（GUI 下可用 `@runtime Jython` 脚本）。

## 未装项及原因

| 工具 | 原因 | 替代 |
|---|---|---|
| GOOMBA | 实为 **Hex-Rays IDA 插件**（HexRaysSA/goomba），不是 Ghidra 插件；本机无 IDA 许可 | SiMBA（Tier B 已装）覆盖 MBA 化简 |
| golang-loader | 上游仅 Jython 时代脚本源码、无 release、Ghidra 12.1 未验证 | GoReSym（Tier A）覆盖 Go 符号/字符串主场景 |
| unipacker 64 位支持 | Unipacker 仅 PE32（架构限制） | 64 位 Themida 走 qiling 档 |
