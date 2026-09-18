# JS 混淆与反调试（浏览器/Node 侧动态对抗）

CTF web/misc 题遇到混淆 JS 时读。二进制逆向的反调试清单在 re-triage `references/anti-analysis.md`，本文件只管 JS 生态。

## 1. 混淆形态分类（先认出是哪类，再选解法）

| 形态 | 特征 | 解法 |
|---|---|---|
| hex/unicode escape | `\x41` `\u0041` 满天飞 | 正则机械替换（下面脚本） |
| 字符串数组 + rotation | 大数组 + 自执行函数移位 + getter 包装 | **不要手算偏移**：Node `vm` 沙箱跑一遍拿解后值 |
| `eval` / `Function` 链 | 多层嵌套执行 | 拦截钩子逐层脱（§3） |
| switch-case dispatcher | 控制流平坦化 | 记录 case 执行序列重建顺序 |
| `atob` / `fromCharCode` 组合 | 编码嵌套 | 机械替换脚本 |

机械解 escape/base64/fromCharCode：

```python
import re, base64
s = open("obfuscated.js", encoding="utf-8").read()
s = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
s = re.sub(r"String\.fromCharCode\(([\d,\s]+)\)",
           lambda m: "".join(chr(int(x)) for x in m.group(1).split(",")), s)
# atob("...") 字面量同理：base64.b64decode
```

## 2. JS 反调试四件套 + 中和模板

| 陷阱 | 代码形态 | 中和 |
|---|---|---|
| debugger 炸弹 | `setInterval(function(){debugger;}, 100)` | DevTools "Deactivate breakpoints" 或 override 置空 |
| console 劫持 | 重写 `console.log` 检测打开 | 恢复原生引用，或无视（纯噪音） |
| 时间差检测 | `performance.now()` 前后差 > 阈值 | hook `performance.now` 返回恒定值 |
| DevTools 尺寸检测 | `window.outerWidth - window.innerWidth > 160` | override 返回 0 |

统一中和思路：**在页面加载前注入 hook 脚本**（DevTools → Overrides / Tampermonkey），把检测函数全部改成无害返回值，而不是逐个 patch 调用点。

## 3. eval 链动态脱壳（Node `vm` 沙箱）

多层 eval 禁止手剥——用 `vm` 模块拦截执行调用，把"执行"换成"输出"：

```js
const vm = require('vm');
let layer = 0, code = require('fs').readFileSync('layer0.js', 'utf8');
while (layer < 10) {
    let captured = null;
    const sandbox = {
        eval: (c) => { captured = c; },            // 拦 eval
        Function: (...a) => { captured = a.pop(); return () => {}; },
        document: { write: (c) => { captured = c; } },
        window: {}, console,
    };
    vm.createContext(sandbox);
    try { vm.runInContext(code, sandbox); } catch (e) { /* 半程出错也常有产出 */ }
    if (!captured || captured === code) break;
    require('fs').writeFileSync(`layer${++layer}.js`, captured);
    code = captured;
}
```

元模式（可泛化到 PowerShell 等）：**把执行调用（eval/IEX/Invoke）逐层替换为输出调用（print/Write-Output），迭代到不再变化**。

## 4. 交付注意

解出的每层落盘存证（layer0/1/2...js），最终 flag/逻辑在台账 conclude 时 `--harness` 标注用的脚本路径（铁律 10：自建 harness 先自检）。
