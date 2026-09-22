# JS 补环境与本地复现（浏览器依赖 JS → Node 跑通）

**分工**：`js-antidebug.md` 管"让脚本肯跑"（反调试中和、vm 沙箱脱 eval 链）；本篇管"让脚本在 Node 里跑出**正确结果**"——把依赖浏览器环境的 JS（webpack 打包的加密/签名算法）抽出来在本地复现。抓包侧参数长什么样归 traffic-analysis；app 内嵌 JS 归 android-re。

> 原则（来自 reverse-skill 四篇参考，MIT）：只补页面证据已证明需要的对象；一次补一个最小因果单元；先补值、再补函数壳、再补返回对象契约；每次补丁后重跑，记录首个异常/分歧点是否前移。**不要一上来就猜 window/document/navigator 该怎么补，更不要一次性模拟整个浏览器。**

## 1. 入口定位（从签名参数反查调用栈）

| 步骤 | DevTools 操作 |
|---|---|
| 1 | Network → 找到带 `sign`/`token`/`_signature` 的 XHR，确认参数名与值 |
| 2 | Sources → `Ctrl+Shift+F` 全局搜参数名（`sign:`、`"sign"`、`.sign =`） |
| 3 | 搜不到 → Network 面板右键请求 → 看 **Initiator** 调用栈，向上翻到有业务名字的帧 |
| 4 | 还不行 → Sources → XHR/fetch Breakpoints 加 URL 子串断点，刷新让它断下，沿 Call Stack 上爬 |
| 5 | 定位到入口函数后立即 `ledger.py observe` 落账：站点、URL、入口函数位置、参数构成 |

定位前先在 Console 里手动调一次入口函数确认它**在当前页面上下文可调用且输出与抓包一致**——这一步就是后面 Node 复现的 oracle 来源。

## 2. 补环境清单（最小 stub，按需逐个加）

报什么错补什么，一次一个。常见缺失对象的最小 stub：

```js
// stub.js —— 在目标代码之前 require/eval
var window = globalThis;
var navigator = { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",  // 从浏览器原样抄
                  appName: "Netscape", platform: "Win32", language: "zh-CN" };
var document = {
    cookie: "",                                   // 页面里 document.cookie 抄真实值
    getElementById: () => null,
    createElement: () => ({ getContext: () => null, style: {}, setAttribute(){} }),
    addEventListener(){}, body: {}, documentElement: {},
};
var localStorage = { _d:{}, getItem(k){return this._d[k]??null},
                     setItem(k,v){this._d[k]=String(v)}, removeItem(k){delete this._d[k]} };
var location = { href: "https://target.example/page", host: "target.example", protocol: "https:" };
var screen = { width: 1920, height: 1080, colorDepth: 24 };
// canvas 指纹只在算法真用到 canvas.toDataURL 时才补：先补 () => "" 试跑，错了再抄真实 dataURL
```

报错链驱动：`ReferenceError: XXX is not defined` → 补值；`XXX.yyy is not a function` → 补函数壳；返回值参与运算出错 → 补返回对象契约（从浏览器 Console 抄真实返回值）。

**Proxy 万能补环境**（对象层级深、报错追不动时用，注意它会掩盖"算法根本没用到该属性"的信息）：

```js
function makeProxy(name) {
    const f = function(){};
    return new Proxy(f, {
        get: (t, p) => (p === Symbol.toPrimitive) ? () => "" : makeProxy(`${name}.${String(p)}`),
        apply: () => makeProxy(`${name}()`),
        construct: () => makeProxy(`new ${name}()`),
    });
}
var window = makeProxy("window");   // 调试用：配合 console.trace 看谁读了什么
```

定位期可给 Proxy 的 `get` 加 `console.log("GET", path)` 打印访问链，据此倒推真正需要补的叶子属性，再换成最小 stub。

## 3. Node 复现流程（oracle 成对，铁律 11）

1. **抽**：把入口函数及其依赖闭包整段抠进 `target.js`（webpack 站先按 §4 抠模块）
2. **补**：`node -e "require('./stub.js'); require('./target.js'); console.log(sign('known-input'))"`
3. **喂已知输入**：用浏览器里抓到的真实 (输入 → 输出) 对
4. **对照**：Node 输出 ≠ 浏览器输出 → 回到 §2 补环境，**禁止改算法逻辑去凑结果**；输出一致才算复现
5. **oracle 成对**（铁律 11 配套纪律）：除"已知输入输出一致"外，再给一个**近似错输入**确认输出确实变化（排除"凡输入皆返回同一常量"的假复现——stub 把关键依赖吞成常量时最常踩这个坑）
6. 时间/随机依赖：`Date.now`/`Math.random` 参与签名时，先在 stub 里钉成固定值对齐浏览器那次抓包，复现成功后再放活

`ledger.py conclude` 时 `--harness` 标注 stub.js/target.js 路径与版本；harness 先用已知答案自检再支撑结论（铁律 10②）。

## 4. webpack 打包站：抠模块

- 识别：源码含 `__webpack_require__`、`webpackJsonp`、`self["webpackChunk..."]`
- 定位加载器：搜 `function __webpack_require__` 或 `webpackChunk` 数组的 push 回调，第一个参数就是模块表 `{id: function(module, exports, __webpack_require__){...}}`
- 抠法（浏览器 Console 里做）：

```js
// 把加载器挂出来，按模块 id 直接取导出
let cache = {};
window.__req = null;
// 在 __webpack_require__ 函数体入口下断，断下后 Console：__req = __webpack_require__
// 然后全量抠：for (let id in 模块表) try { cache[id] = __req(id) } catch(e) {}
```

- 模块 id 不确定时：在目标函数所属模块的函数体里下断，断下后看作用域链上的 `module.id`
- 抠出的模块搬进 Node 后，模块间引用用同一个手写 `__req` 表串起来，不要整站搬运

## 5. AST 去混淆 vs 动态补环境（成本决策）

| 情况 | 选择 |
|---|---|
| 只要跑出结果（签名/加密调用） | **动态补环境**——混淆不影响执行，补环境按小时计 |
| 要读懂算法并移植/重写（如改成 Python 发请求） | 混淆浅（字符串数组+rotation）→ 先按 `js-antidebug.md` §1/§3 动态拿解后值 |
| 控制流平坦化 + 要长期维护对该站的调用 | 才值得写 babel visitor（`@babel/parser`+`traverse`+`generator`）；本机 node 可用但 babel 包未装，按需 `npm i @babel/core @babel/traverse` 到工作目录 |
| 混淆层数未知 | 先动态跑通拿到正确输出当 oracle，再决定要不要静态还原——有了 oracle，AST 还原的每一步都有对照 |

经验序：**动态补环境跑通 > 动态脱值 > AST 手工 visitor**。能跑通就不要还原，还原是读懂的手段不是目的。

## 6. 平台与工具现状

- `node` Windows 与 WSL Ubuntu 均已装（实测 v24.x）：Windows 直接 `node x.js`；WSL `wsl -d Ubuntu -- node /mnt/c/.../x.js`。**注意：node 目前未登记在 ghidra-core `scripts/doctor.py` 的 TOOL_REGISTRY/TOOL_REGISTRY_LINUX**（注册表只覆盖二进制工具链），可用性以 `node -v` 实测为准
- **JSDOM 未装**（`node -e "require('jsdom')"` 报错）——优先 §2 手写最小 stub；确需 DOM 再考虑 `npm i jsdom` 装到工作目录
- DevTools（Chrome/Edge 自带）是入口定位与 oracle 取值的标配，不算外部依赖

## 7. 落账与溯源

- 每个目标站一条线：`ledger.py observe` 记入口定位证据（URL、参数名、调用栈帧），`conclude` 记复现结论并标 `--harness`
- 补环境的每一步（补了什么、报错是否前移）值得 observe——"stub 补错了导致签名静默算错"是本站类任务最高发事故，正负对照（§3 第 5 步）就是它的保险丝
- 交付的 sign.js 头部注释写清来源站点与抓取日期——站点改版后算法失效，没有溯源信息无法区分"我写错了"和"站改了"

---
借鉴来源（结构/原则参考，代码为本家族重写）：github.com/zhaoxuya520/reverse-skill（MIT License）——`skills/js-reverse/references/env-patching.md`、`node-env-rebuild.md`、`local-rebuild.md`、`automation-entry.md`
