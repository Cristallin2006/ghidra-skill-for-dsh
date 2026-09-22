---
name: vuln-audit
description: 按清单系统性排查二进制漏洞模式（vulnerability audit / pwn 预筛）：内存破坏、格式化字符串、整数溢出、命令注入、危险 API 组合。触发：漏洞审计、找漏洞、pwn 攻击面梳理、fuzz 前目标筛选、SRC 静态预筛。是 checklist 知识层——具体命令见 ghidra-core。动手前必须先用 skill 工具加载本 skill 全文并遵守其流程；一切观察/结论用 ledger.py 落账。
whenToUse: 对二进制做漏洞模式排查、pwn 攻击面梳理、fuzz 目标筛选、SRC/漏洞挖掘前期的静态预筛；crackme 之外的"它有没有病"类问题
---

# Vuln Audit（场景 3：它有没有病？）

前置：未知样本先分诊 → `~/.dsh/skills/re-triage`／后继：命中漏洞模式后的利用构造（pwn 方法论，超出本 skill）／执行细节（命令参数）→ `~/.dsh/skills/ghidra-core`

本 skill 是 **checklist 知识层**：方法论和判定标准在这里，命令只有用法示意，参数细节一律见 ghidra-core §5。

## 路径约定

```bash
SK="$HOME/.dsh/skills/ghidra-core/scripts"     # 唯一代码家
# Windows:
RPC="$HOME/Desktop/src/ghidra-bridge/ghidra-rpc-venv/Scripts"  # ghidra-rpc CLI
# WSL/Linux: RPC="$HOME/ghidra-rpc-venv/bin"
```

## 审计流程

1. `python "$SK/rpc_driver.py" ensure <bin>` + `triage`：拿到 imports 全貌与可疑 API 六组命中——这是第一轮粗筛
2. 按 `references/vuln-patterns.md` 的**检查项清单**逐项过：每项给出识别信号、用什么命令查、判定标准、常见误报
3. 每个命中项记录：地址 / 证据（伪码或汇编摘录）/ 可达性（用户输入能否到达）/ 严重度初判
4. **可达性优先于模式数量**：一个用户输入直达的 strcpy 胜过十个内部路径的 gets。用 `xrefs-to` 确认调用者、用 `decompile` 追输入来源（main 参数/recv/read/文件/环境变量）
5. 交付：命中清单 + 每项证据 + 建议的 fuzz/动态验证入口（动态工具是否已装以 `python "$SK/doctor.py"` 的 toolchain 节为准，未装的按 hint 装或改静态验证）

## 覆盖的检查项（细则在 references/vuln-patterns.md）

- 栈溢出（gets/strcpy/sprintf/strcat vs 边界检查版）
- 格式化字符串（printf(用户输入)）
- 堆问题（UAF / double-free 的 free 后指针未清零模式）
- 整数溢出（malloc 前算术）
- 命令注入（system/popen/ShellExecute 拼用户输入）
- 危险 API 组合（对应 triage 可疑六组）
- 不安全的随机数（rand/srand(time) 作安全用途）
- 硬编码密钥/口令特征

## 与其他 skill 的分水岭

- vs **re-triage**：分诊回答"这是什么、走哪条路"，本 skill 回答"按清单查有没有这些病"。判型/壳/语言问题去 re-triage
- vs **ghidra-static**：static 是"读懂它"（语义还原、算法提取），本 skill 是"挑毛病"（模式匹配+可达性）。深挖某个函数的实现细节去 ghidra-static

## References

| 文件 | 何时读 |
|---|---|
| `references/vuln-patterns.md` | 漏洞模式检查项清单（识别信号/命令/判定标准/误报）——审计主文档 |
| `references/patch-diff.md` | 有补丁前后两版二进制时：ghidriff/version-track 差分 → 根因反推 → PoC 思路（N-day） |
