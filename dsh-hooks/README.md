# dsh-hooks —— skill 准则强制层（hooks 机械门）

解决「AI 自由逆向时不遵守 skill 准则」：catalog 只注入 description，SKILL.md 正文和
ghidra-core §1 铁律不在上下文里，文字纪律无强制力（chal session 实证：纪律卡注入了、
skill 加载了、规则能逐条背出，仍违反 9 条）。本目录用 dsh 内置的
`@deepseek-ai/dsh-hooks-claude-code` 桥（Claude Code 格式 hooks）把关键纪律变成机械门。

## 组成

| 文件 | 事件 | 作用 |
|---|---|---|
| `session_start.py` | SessionStart / SubagentStart | 把压缩版纪律卡注入会话/子代理上下文（additionalContext），8 条 |
| `gate_sample.py` | PreToolUse（matcher `Pwsh\|pwsh\|Bash\|bash`） | 对**无台账样本**的分析类直读 + rpc 深挖子命令（decompile/exec-code/emulate/patch…）exit 2 阻断；有台账放行；pcap 豁免 |
| `gate_churn.py` | PreToolUse（matcher `Write\|write`） | 拟合熔断：目录近 24h ≥8 个 .py 且活跃台账零 stuck → 阻断，逼 stuck 落账或升级 z3/emulate |
| `gate_longrun.py` | PreToolUse（同 bash matcher） | 长任务落盘门：`timeout ≥300s` 裸跑 python 脚本 → 阻断，指引 guarded_run.py |
| `stop_check.py` | Stop | 收尾核对：12h 内活跃台账有 observe 无 conclude/stuck、或 flag 结论缺 program_accept → deny 强制核对 |
| `hooks.json` | — | Claude Code 格式挂载清单（`${CLAUDE_PLUGIN_ROOT}` = 本目录） |

## ⚠ matcher 是大小写敏感的字面量匹配（2026-09-26 事故）

dsh-hook-protocol 对纯 `[A-Za-z0-9_|]` 模式走 `split("|").includes(query)` **精确匹配**，
不做大小写折叠。WSL/Linux 的 shell 工具名是小写 `bash`、Write 工具是小写 `write`——
只写 `"Bash"` 在其上**静默失效**（chal session 的 PreToolUse 门因此从未触发，
session 里零 `hook/invoked` 记录）。matcher 必须写全：`Pwsh|pwsh|Bash|bash`、
`Write|write`。Windows 侧工具名是 `Pwsh`（大写），旧配置只在 Windows 生效过。

## 安装（Windows）

`~/.dsh/profiles/web/cordis.patch.yml` 末尾的 `[]` 替换为：

```yaml
- insert:
    - id: hooks-claude-code
      name: '@deepseek-ai/dsh-hooks-claude-code'
      config:
        configPath: 'C:\Users\Lenovo\.dsh\hooks\hooks.json'
        pluginRoot: 'C:\Users\Lenovo\.dsh\hooks'
```

WSL 侧路径改为 `/root/.dsh/hooks/...`，hooks.json 里命令的 `python` 改 `python3`。
**改 hooks.json / 挂新 hook 后必须重启 `dsh web` 才生效**（插件树在启动时加载）。

## 排障与回滚

- **整体回滚**：cordis.patch.yml 恢复为顶层 `[]`，hooks.json 留置无害
- dsh web 启动报插件树错误 → 检查 name 解析；包名解析失败时把 `name` 改成
  app 内模块绝对路径（`.../npm/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-hooks-claude-code/lib/index.js`）
- 验证 hook 是否真的跑了：session 的 jsonl 里应有 `hook/invoked` + `hook/result`
  记录（PreToolUse/Stop 在 turn 内会落这对记录）；没有 = matcher 没命中或插件没加载
- gate_sample 误伤 → 对被拦样本先跑一次 `ledger.py query <样本>` 建台账即可放行；
  长期误伤样本类型加进脚本的 EXEMPT_EXT
- gate_churn 误伤（正常多文件开发）→ 豁免根含 `.dsh`/`node_modules`/`site-packages`；
  项目目录被误拦时把该目录移出题目工作区，或在台账落一条 stuck（语义：我知道卡在哪）
- hook 脚本自身异常一律放行（exit 0），不会阻塞正常工作

## 设计边界

- 防惯性直读/惯性堆脚本，不防蓄意绕过（命令写进脚本文件即可绕过；绕过会在台账缺失上留痕）
- 不改 dsh 本体、不动 profile 的 package.json（2026-09 双拷贝崩溃事故的教训）
- gate_churn 是速度坎不是墙：落一条 stuck 即放行——目的是逼台账接触，不是禁止迭代
