---
name: re-unpack
description: 对已确认或疑似加壳的二进制执行脱壳与验证：UPX/ASPack/Themida/VMProtect/MPRESS，PE/ELF，多层。触发：triage 检出壳、熵高、节名 UPX/.aspack/.vmp、导入表异常干净。只做脱壳与脱壳成功验证——脱完回 re-triage 重新分诊，不做内容分析。
whenToUse: triage 确认或疑似加壳（节名 UPX/.aspack/.vmp、熵 >7、导入表只剩 LoadLibrary/GetProcAddress）、需要脱壳或验证脱壳产物时；多层壳、IAT 重建、脱壳失败换后路
---

# RE Unpack（场景：脱壳与验证）

前置：re-triage（检出壳才来这里）／后继：回到 re-triage（脱壳产物当新样本重新分诊）／内容分析 → ghidra-static／命令细节 → ghidra-core

> **断路器纪律**：packed/加密字节在信息论上是噪声——禁止对其做内容级肉眼/脚本分析；同一区域第二次回访会被 ghidra-core `scripts/ledger.py observe` 拦截（强制 `--delta`，答不出必须升级工具或问人，见 ghidra-core 铁律 7）。

## 路径约定

```bash
UPX="$HOME/Desktop/src/tools/upx/upx.exe"                     # Tier A 原生 UPX
UNP="$HOME/Desktop/src/unpacker-venv/Scripts"                 # Unpacker venv（Python 3.12, editable）
RUP="$HOME/.dsh/skills/re-unpack/scripts"                     # 本 skill 的脱壳域脚本
export PATH="$(dirname "$UPX"):$PATH"                          # Unpacker 靠 PATH 找原生 upx
```

本 skill 零 Ghidra 知识；脱壳产物进 Ghidra 的后续动作全部走 re-triage/ghidra-core。

## 流程

### 1. detect + unpack（一条命令）

```bash
"$UNP/unpacker.exe" <sample> -o <outdir> --max-layers 5 --timeout 300
```

输出逐层报告：`Detected: <packer> (confidence=…)` + 每层 `packer=… -> ok|fail` + `Final output: <路径>`。多层壳自动逐层剥（max 5），IAT 重建默认开。

### 2. 选型表（壳 → 工具 tier）

| 壳 | 特征 | 工具 |
|---|---|---|
| UPX | 节名 UPX0/UPX1、`UPX!` 魔数 | **Tier A**（已装）：Unpacker 自动调原生 `upx -d`；或直接 `"$UPX" -d <sample> -o <out>` |
| ASPack / Themida (PE32) | `.aspack`/`.themida` 节 | Tier B（已装）：unipacker（unpacker-venv 的 `[unipacker]` extra，Unpacker 自动调） |
| VMProtect 64 位 | `.vmp0/.vmp1` 节 | Tier B（已装）：qiling 1.4.6（WSL `~/re-pwn-venv`）+ rootfs `/root/qiling-rootfs`（x86/x8664 windows）——Unpacker 的 qiling 档在 WSL 里跑 |
| MPRESS | `.MPRESS1/2` 节 | Tier B：unipacker |
| 未知/自定义壳 | 熵高、节名正常但 IAT 干净 | 失败阶梯 ③④ |
| PyInstaller（打包而非壳） | `MEI\x0c\x0b\x0a\x0b\x0e` cookie、PYZ 归档 | `python "$RUP/pyinstaller_extract.py" <sample>`（识别版本 → pyinstxtractor 解包 → 按 pyc magic 自动选 uncompyle6/decompyle3/pycdc）；`--check` 只分诊 |

Tier 术语与 doctor toolchain 节一致（A=已装轻量 / B=按需重装 / C=GUI 手工）；任一工具是否已装以 `python "$SK/doctor.py"` 的 toolchain 节为准（SK 路径见 ghidra-core）。

### 3. 验证（强制，不验证 = 没脱开）

对脱壳产物逐项核对并**记录数字**：

1. **熵降**：packed 应 >7，unpacked 应回到 5~6（脚本：字节 Shannon 熵）
2. **大小变化**：unpacked 明显大于 packed
3. **明文出现**：ASCII 字符串数显著增多；`KERNEL32.DLL` 等 DLL 名 + 真实 API 名出现在 imports
4. **回链验证**：`python "$SK/rpc_driver.py" ensure <unpacked>` + `triage` 能正常分诊（SK 见 ghidra-core 路径约定）

**验证不过 = 没脱开** → 进入失败阶梯。禁止拿未验证的产物往下走。

## 失败阶梯（逐级时间盒，单级 ≤15 分钟）

① **UPX 元数据篡改**（`upx -d` 报 not packed/CantUnpackException）→ 先跑修头脚本（节名改回 UPX0/UPX1 + 按结构偏移重写 `UPX!` 魔数，`upx -t` 做 oracle 验证）：

```bash
"$UNP/python.exe" "$RUP/upx_repair.py" <packed.exe> --write --out <fixed.exe> && "$UPX" -d <fixed.exe> -o <out>
```

脚本修不动（l_info/p_info 字段级篡改）再手工（`references/unpack-playbook.md` §UPX 修头）
② **unipacker / qiling 仿真脱壳**（Tier B，**均已装**）：unipacker 在 unpacker-venv（Unpacker 对 PE32 自动调）；qiling 在 WSL（`/root/re-pwn-venv`，rootfs `/root/qiling-rootfs`，注意 Unpacker 的 qiling 档要在 WSL 内手动跑，不在 Windows 侧）。若 doctor toolchain 显示缺失则**明确声明"此层不可用"**并按其 hint 装回，不要硬试。
③ **Ghidra 仿真解密 stub**：`emulate-function` 跑 unpack stub 后 dump（命令与用法 → ghidra-core §5；不在这里展开）
④ **Frida 动态 dump**：跑起来后从内存抓 OEP 镜像（工具选型 → ghidra-static `references/ctf-patterns.md` §6）
⑤ **全部失败** → 显式声明"未脱壳"，交付 stub 级分析（stub 功能、IAT 线索、入口行为）并**明示置信度**

## 防死循环专节

- 死循环签名：「肉眼分析 packed 字节 → 出错 → 写脚本分析 → 又回到肉眼分析」。packed 字节是噪声，任何内容级分析（肉眼或脚本）都不可收敛
- **第二次回到同一字节区域/同一假设 = 立即停手**，按当前所在层级升级失败阶梯，或问用户
- 肉眼直读 hex 仅用于**验证工具输出**（如确认 UPX 头被篡改），预算 ≤2 次
- 每个工具调用前先在脑子里写下"这一步的产出应该长什么样"；产出不符立即换层级，不原地重试

## References

| 文件 | 何时读 |
|---|---|
| `references/unpack-playbook.md` | 多层脱壳、IAT 重建、UPX 修头、各壳特征与对策的细节 |
