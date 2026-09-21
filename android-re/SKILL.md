---
name: android-re
description: Android/APK 逆向（纯 DEX / Java 层，APK reversing）：APK 分诊（结构/签名/Manifest/多 dex 自有类统计/flag 全扫）、反编译与校验点定位（jadx/smali）、adb 动态驱动与真机 oracle、v1 未签名 APK 改写重签。触发：APK/Android/DEX/安卓/逆向 APK/smali/jadx。不分析原生 so——APK 内含 lib/ 的 .so 走 ghidra-static；不做流量分析——抓包/隐信道走 traffic-analysis。
whenToUse: 拿到 .apk/.dex 样本时；re-triage 判定"APK 不含 lib/（纯 DEX）"后的主线；多 dex 分诊、签名/Manifest 分诊、flag 形态字面量全扫、const-string→equals 校验点定位、adb/am/input/uiautomator/screencap 动态驱动、真机 oracle 验证候选答案、v1 未签名 APK 改写后 apksigner 重签
---

# Android RE（场景 7：纯 DEX APK 找校验点）

前置：re-triage（路由：APK 含 lib/ → 按 ABI 选 so 走 ghidra-static；纯 DEX → 本 skill）／后继：抠出的 so → ghidra-static；抓到的流量 → traffic-analysis；flag 候选必须过真机 oracle 正负对照后交付

> **纪律**：jadx 已装，**禁止从零自写 DEX/AXML 解析器**；万不得已自写时，结论必须与 apkanalyzer 或 androguard 逐条比对（铁律 11，全文见 ghidra-core §1）——"输出看起来合理"不构成正确性证据。同一路径失败 2 次换工具，单方向 ≤15 分钟（铁律 6，同上）。每个观察/结论走 ghidra-core `scripts/ledger.py` 落账，机制见 ghidra-core `references/evidence-ledger.md`。

## 路径约定

```bash
# Windows:
JADX="$HOME/Desktop/src/tools/jadx/bin/jadx.bat"              # jadx 1.5.6（第一反编译源）
SDK="$LOCALAPPDATA/Android/Sdk"
CT="$SDK/cmdline-tools/latest/bin"                            # apkanalyzer.bat / sdkmanager.bat / avdmanager.bat
ADB="$SDK/platform-tools/adb.exe"
EMU="$SDK/emulator/emulator.exe"
BT="$SDK/build-tools/37.0.0"                                  # aapt2.exe / apksigner.bat / dexdump.exe
AGPY="$HOME/Desktop/src/re-tools-venv/Scripts/python.exe"     # androguard 4.1.4（第二独立解析源）
KS="$HOME/.android/debug.keystore"                            # 重签用（androiddebugkey / android，已存在）
# WSL/Linux：
# JADX="$HOME/tools/jadx/bin/jadx"; ADB="$(command -v adb)"; AGPY="$HOME/re-tools-venv/bin/python"
# SDK/CT/EMU/BT/KS 无对应（Android SDK 模拟器为 Windows-only，真机 oracle 在 Windows 侧做）
```

- system image **android-33 default x86_64 已装** → 真机 oracle 可立刻做（§3.2）
- host frida 17.18.0 已装；**frida-server（android 版）必须与 host 严格同版本，当前未装** → frida 档默认不可用，先 `python "$SK/doctor.py"` 看 toolchain 节（SK 路径见 ghidra-core），缺失按其 hint 装，不要硬试
- Windows 环境坑（`adb screencap` 禁止 `>` 重定向、PS 引号、后台超时等）→ ghidra-core `references/windows-powershell.md`，本 skill 只写命令形态

## 流程

### 1. 分诊（细则 → `references/apk-triage.md`）

```bash
"$CT/apkanalyzer.bat" files list app.apk          # 结构清单：有无 lib/、几个 dex、assets/res
"$CT/apkanalyzer.bat" manifest print app.apk      # Manifest 文本（免手写 AXML 解析）
"$CT/apkanalyzer.bat" files download app.apk out/ # 不解压整包，只取需要的条目
unzip -l app.apk | grep META-INF                  # 签名分诊：无 CERT.RSA/MANIFEST.MF = v1 未签名
```

判定表（全静态，成本极低）：

| 发现 | 含义 → 动作 |
|---|---|
| 无 `lib/` | 纯 DEX，留本 skill；有 `lib/` 且逻辑疑似在 so → ghidra-static |
| `META-INF` 无 CERT.RSA/MANIFEST.MF | **v1 未签名** → 可自由改写重签（§4）；只有 v2 signing block 则改动必破签名 |
| `debuggable=true` | 可 `run-as`、附加调试器、jdwp → 动态优先（§3） |
| `usesCleartextTraffic=true` + 网络行为 | 明文流量 → 抓包走 traffic-analysis |
| `extractNativeLibs=false` | 与"无 so / so 直接落在 apk 内"互相印证 |

**多 dex 启发式（必须逐 dex 看，别只看 classes.dex）**：大 dex 通常是打包进去的 androidx/material 库，真逻辑常在极小 dex（实测：`classes.dex` 5.1MB/3346 类**零自有类**，全部逻辑在 **3172 字节的 `classes3.dex`**，3 类 23 方法）。统计法与过滤前缀 → `references/apk-triage.md` §4。

**flag 全扫（默认动作，全 dex 都做）**：

```bash
mkdir -p /tmp/apkx && unzip -o -q app.apk -d /tmp/apkx
grep -aoE 'flag\{[^}]*\}|BJD\{[^}]*\}|CTF\{[^}]*\}|\{[0-9a-fA-F]{16,}\}' /tmp/apkx/classes*.dex | sort -u
```

命中即定位到唯一校验点；regex 全集与 strings 口径 → `references/apk-triage.md` §5。

### 2. 静态：反编译 → 校验点定位

反编译优先级（前一档可用就不用后一档）：

| 档位 | 工具 | 命令 |
|---|---|---|
| ① 首选 | jadx | `"$JADX" -d jadx-out app.apk`（Java 视角，自带 AXML/资源还原） |
| ② 交叉源 | apkanalyzer | `"$CT/apkanalyzer.bat" dex code app.apk`（官方 smali，带行号/局部变量名） |
| ③ 交叉源 | androguard + DAD | `"$AGPY"` 内 `from androguard.misc import AnalyzeAPK` |
| ④ 最后手段 | 自写解析器 | **禁止直接下结论**：必须逐条比对 ② 或 ③（铁律 11） |

校验点定位套路（在 jadx-out 或 smali 文本上 grep）：

1. **Toast 文案锚点**：先搜 `success!!!`/`wrong!!!` 一类成败文案 → 定位校验函数
2. **const-string 交叉引用**：从锚点字符串找 `const-string` 加载点 → 顺 invoke 链找到 `String.equals`/`contentEquals` 调用点
3. 比较点两侧的常量就是答案原料；smali 形态对照 → `references/dalvik-notes.md`

**算法陷阱——不信命名**：类名/字段名可故意误导（实测：类叫 `ROT14`、字段 `shift=13`，实际算法用**硬编码字面量** 13，字段从未被读取）。一律以 invoke 现场的常量与数据流为准，识别清单 → `references/dalvik-notes.md` §4。

### 3. 动态

#### 3.1 adb 驱动（真机/模拟器通用）

```bash
"$ADB" install app.apk
"$ADB" shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1   # 或 am start -n <pkg>/.MainActivity
"$ADB" shell input text 'flag{...}' && "$ADB" shell input tap 540 960
"$ADB" shell uiautomator dump /sdcard/ui.xml && "$ADB" pull /sdcard/ui.xml   # 回读校验（别信点击成功）
"$ADB" shell screencap -p /sdcard/t.png && "$ADB" pull /sdcard/t.png         # 抓 Toast；禁止 > 重定向（坑见 ghidra-core windows-powershell.md）
```

#### 3.2 真机 oracle（验证候选 flag 的标准流程，手工约 20 分钟那套）

```bash
"$CT/avdmanager.bat" list avd                       # 无 AVD 则：avdmanager create avd -n ctfd -k "system-images;android-33;default;x86_64"
"$EMU" -avd ctfd -no-window -no-audio &             # 无头启动（长耗时 → run_in_background）
"$ADB" wait-for-device && "$ADB" shell getprop sys.boot_completed   # 等到返回 1
"$ADB" install app.apk
# 对每个候选：写入 → uiautomator 回读确认写入成功 → 点击 → screencap 抓 Toast
```

**oracle 必须成对**（铁律 11 配套纪律，全文见 ghidra-core §1）：正确候选 → `success!!!` 之外，必须给**近似错值 → `wrong!!!`** 的负对照，否则无法排除"凡输入皆通过"；解空间可枚举时穷举优先于公式（同时产出答案与唯一性证明）。

#### 3.3 frida Java 层（先确认 frida-server 可用性，见路径约定）

用途：hook `String.equals` 直接吐比较双方、强制返回值、dump 运行时字符串。版本与 push/启动细节以 doctor toolchain 节为准；hook 模板不在这里展开。

### 4. 改写重签（仅 §1 判定 v1 未签名时）

```bash
# 改 jadx/apktool 产物或解包目录后重打包为 out.apk（zip 对齐可选）
"$BT/apksigner.bat" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android --out signed.apk out.apk
"$BT/apksigner.bat" verify --verbose signed.apk
"$ADB" install -r signed.apk
```

v2-only 签名的 APK 改动即破签名 → 改走 frida 动态 patch，不要重签硬刚。

### 5. 时间盒与防死循环

- 死循环签名：「jadx 读 Java → 看不懂 → 手写 smali 解析 → 又回到 jadx」。反编译器输出与 smali 是**同一事实的两个视图**，切换视图不产出新信息——卡住时换的是**方法**（动态/frida/oracle），不是换渲染器
- 同一区域第二次回访会被 ledger 拦截（强制 `--delta`）；单方向 ≤15 分钟无产出 → 回下面路由表选下一行；彻底卡住 `ledger.py stuck` 留痕并问用户
- 每个结论落账时 `--independent` 写清第二来源（jadx↔apkanalyzer 互证、oracle 正负对照）

## 路由表（按分诊发现选路）

| 分诊发现 | 去哪 |
|---|---|
| APK 含 `lib/`、校验在 so | ghidra-static（选 ABI 优先 x86_64） |
| 纯 DEX、flag 字面量直接命中 | §3.2 真机 oracle 正负对照后交付 |
| 纯 DEX、校验是字符串比较/变换 | §2 静态定位 → §3.2 验证 |
| `debuggable=true` 且静态卡住 | §3 动态优先 |
| v1 未签名且需 patch 逻辑 | §4 改写重签 |
| v2 签名 + 需 patch | §3.3 frida |
| Manifest 有网络组件/明文流量 | 流量部分交接 traffic-analysis |
| 样本不是 APK（PE/ELF/pyc…） | 回 re-triage 重新分诊 |

## References

| 文件 | 何时读 |
|---|---|
| `references/apk-triage.md` | zip 结构与关键条目、AXML/Manifest 要点、签名版本判定、多 dex 自有类统计法、flag 形态 regex 集 |
| `references/dalvik-notes.md` | smali 速查：常见 opcode 形态、const-string/invoke 模式、equals 比较点、R 类与命名误导识别 |
