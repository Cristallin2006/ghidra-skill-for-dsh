---
name: traffic-analysis
description: CTF 流量分析与网络取证：pcap 分诊、DNS/ICMP/TCP 隐信道与隧道重组、USB HID 键鼠抓包还原、WPA/TLS 解密、文件与凭据提取。触发：流量/pcap/抓包/Wireshark/网络取证/流量包/隐蔽信道/隧道。不做二进制逆向——那是 ghidra-static 系；提取出的文件需逆向时回 re-triage。
whenToUse: 拿到 pcap/pcapng 要分析时；DNS 隧道、ICMP/时序/TCP flag 隐信道、USB HID 键盘鼠标抓包、802.11 eapol/WPA 解密、TLS keylog 解密、--export-objects 文件提取、明文凭据收割
---

# Traffic Analysis（场景 6：流量里找信号）

前置：拿到 pcap/pcapng（题目附件，或别的主线提取出的文件）／后继：提取出的二进制 → `~/.dsh/skills/re-triage` 重新分诊；文本/flag 类结论直接交付

> **内容看不懂时，信号在元数据里**：包长、TTL、IPID、时延、TCP flags 的 per-packet 分布画直方图，值落在可打印 ASCII 区间的分布就是信号（TokyoWesterns 2018 方法论，细节 references/tunnels.md §通用检测）。同一路径失败 2 次换工具，单方向 ≤15 分钟（铁律 6，全文见 ghidra-core §1）。

## 路径约定

```bash
TA="$HOME/.dsh/skills/traffic-analysis/scripts"   # 本 skill 脚本（全零依赖，Python 3 stdlib）
```

本 skill 不依赖 tshark——`pcap_triage.py` 自研解析器保底；tshark/Wireshark/aircrack-ng/hashcat 是否可用以 `python "$SK/doctor.py"` 的 toolchain 节为准（SK 路径见 ghidra-core），缺失按 hint 装或绕。

## 流程

### 1. 打不开先修

`xxd cap.pcap | head -1` 对 magic bytes（d4c3b2a1/a1b2c3d4=pcap，0a0d0d0a=pcapng）→ 修头/pcapfix/格式转换，配方见 `references/pcap-triage.md` §修复。

### 2. 开局三连（每条 30 秒内）

```bash
python "$TA/pcap_triage.py" cap.pcap      # 零依赖：包数/时间跨度/协议分布/包长直方图/top 会话 + 路由 hint
tshark -r cap.pcap -q -z io,phs           # 有 tshark 时交叉验证：协议分层统计
tshark -r cap.pcap -q -z conv,ip          # 会话/端点
```

- `pcap_triage.py` **exit 2 = 某协议占比 >60%**，直接跟它打印的路由 hint 走
- **大 pcap（百万包级）**：信号载体往往藏在包数最少的协议/会话里，按包数倒序找（EHAX 2026 经验）
- pcapng 会被 pcap_triage 拒收：`editcap -F pcap in.pcapng out.pcap` 转换后再来

### 3. 路由表（按分诊发现选路）

| 分诊发现 | 去哪 |
|---|---|
| DNS 占比高 / 查询名 >40 字节 / TXT 记录异常 | `references/tunnels.md` §DNS + `scripts/dnscat2_reassemble.py` |
| ICMP 异常（payload 非标准/长度可疑/时延双峰） | `references/tunnels.md` §ICMP + `scripts/timing_decode.py` |
| TCP flag 组合混乱（FIN+SYN 同现）、同端口包数 %4==0 | `references/tunnels.md` §TCP flags |
| 包内容雷同、间隔只有两档 | `references/tunnels.md` §时序 + `timing_decode.py --mode interval` |
| USB linktype（189/220/288） | `references/usb-hid.md` + `hid_keyboard.py` / `mouse_render.py` |
| 802.11/radiotap、eapol 四次握手 | `references/wifi-tls.md` §WPA |
| TLS 密文 + 附件有 keylog/私钥/coredump | `references/wifi-tls.md` §TLS |
| HTTP/SMB/FTP 明文传文件 | `references/pcap-triage.md` §文件提取 |
| FTP/Telnet/HTTP Basic/NTLM 认证流量 | `references/pcap-triage.md` §凭据 |
| 协议分布全正常、内容全噪声 | 元数据直方图：`timing_decode.py --mode len` / `--mode byte --offset N`（TTL=IP+8，IPID=IP+4），方法论 `references/tunnels.md` §通用检测 |

### 4. 证据落账（强制）

每个观察/结论走 ghidra-core `scripts/ledger.py`（`observe`/`conclude`，key 用 pcap 文件名），机制见 ghidra-core `references/evidence-ledger.md`。**提取出的文件先正向验证**（魔数/file 命令/能打开）才算证据；自建解码脚本在支撑结论前用已知答案自检（铁律 10 ②）。

### 5. 时间盒与换路

同一路径失败 2 次 → 换工具（如 hid 手工解析不行就回 tshark 换字段导）；单方向 ≤15 分钟无产出 → 回 §3 路由表选下一行；彻底卡住 `ledger.py stuck` 留痕并问用户。

## 脚本速查

| 脚本 | 一句话 |
|---|---|
| `scripts/pcap_triage.py` | 开局分诊（零依赖）；某协议占比 >60% exit 2 并给路由 hint |
| `scripts/hid_keyboard.py` | usbhid.data hex 行 → 还原文本（内置完整 HID 键码表+Shift 映射，--lines 跟踪方向键分行） |
| `scripts/mouse_render.py` | HID 鼠标/数位板位移 → 累加轨迹 → PGM 图（纯 stdlib；--png 需 PIL） |
| `scripts/dnscat2_reassemble.py` | DNS 查询名列表 → 去 9 字节头/去重传 → 重组 payload |
| `scripts/timing_decode.py` | 时序分档/包长/单字节字段 → bit/字节 → ASCII 渲染 |

## References

| 文件 | 何时读 |
|---|---|
| `references/pcap-triage.md` | pcap 修头/pcapfix、`--export-objects` 文件提取、流重组、明文凭据与 NTLMv2、strings 碰运气 |
| `references/tunnels.md` | DNS（dnscat2/尾部字节/TXT/oracle）、ICMP、TCP flags、时序隐信道配方 + 通用元数据直方图方法论 |
| `references/usb-hid.md` | USB 键盘 8 字节报告、鼠标/数位板画图还原、LED Morse、蓝牙 RFCOMM 重组 |
| `references/wifi-tls.md` | WPA eapol 破解+airdecap 二次分析、TLS 解密三途径、SMB3.1.1 会话密钥推导 |
