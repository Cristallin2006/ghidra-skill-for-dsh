# dsh-hooks —— skill 准则强制层（hooks 机械门）

解决「AI 自由逆向时不遵守 skill 准则」：catalog 只注入 description，SKILL.md 正文和
ghidra-core §1 铁律不在上下文里，文字纪律无强制力。本目录用 dsh 内置的
`@deepseek-ai/dsh-hooks-claude-code` 桥（Claude Code 格式 hooks）把关键纪律变成机械门。

## 组成

| 文件 | 事件 | 作用 |
|---|---|---|
| `session_start.py` | SessionStart / SubagentStart | 把压缩版纪律卡注入会话/子代理上下文（additionalContext） |
| `gate_sample.py` | PreToolUse（matcher `Pwsh\|Bash`） | 对**无台账样本**的分析类直读 exit 2 阻断；有台账放行；pcap 豁免 |
| `stop_check.py` | Stop（**默认不挂载**） | 收尾时台账有 observe 无 conclude/stuck 则 deny 强制核对 |
| `hooks.json` | — | Claude Code 格式挂载清单（`${CLAUDE_PLUGIN_ROOT}` = 本目录） |

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

WSL 侧路径改为 `/root/.dsh/hooks/...`，命令里的 `python` 改 `python3`。

## 排障与回滚

- **整体回滚**：cordis.patch.yml 恢复为顶层 `[]`，hooks.json 留置无害
- dsh web 启动报插件树错误 → 检查 name 解析；包名解析失败时把 `name` 改成
  app 内模块绝对路径（`.../npm/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-hooks-claude-code/lib/index.js`）
- gate_sample 误伤 → 对被拦样本先跑一次 `ledger.py query <样本>` 建台账即可放行；
  长期误伤样本类型加进脚本的 EXEMPT_EXT
- hook 脚本自身异常一律放行（exit 0），不会阻塞正常工作

## 设计边界

- 防惯性直读，不防蓄意绕过（命令写进脚本文件即可绕过；绕过会在台账缺失上留痕）
- 不改 dsh 本体、不动 profile 的 package.json（2026-09 双拷贝崩溃事故的教训）
- L4 stop_check 启用条件：L1-L3 稳定运行一段时间后再评估
