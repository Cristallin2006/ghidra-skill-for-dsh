# 隧道与隐信道配方（DNS / ICMP / TCP flags / 时序）

> 本文 `tshark` 指 SKILL.md 路径约定的 `"$TS"`（`~/Desktop/src/tools/wireshark/tshark.exe`，未加 PATH）。

## 通用检测方法论（先看这个）

**任何发送方能影响的 per-packet 元数据字段都是潜在信道**：包长、TTL、IPID、TCP window、DNS QNAME 长度、包间隔。

检测 = 画 per-packet 元数据直方图：

- 值全部落在可打印 ASCII 区间（32–126）→ 每包一字节，`timing_decode.py --mode len` / `--mode byte --offset N` 直接出文本（TokyoWesterns 2018：`ping -s <len>` 用 ICMP payload 长度藏 flag）
- 分布明显双峰 → 二值编码，阈值分档出 bit（`--threshold`）
- 正常流量是单峰高斯；隐信道是多模/离散档位

字段偏移速查（相对 IPv4 头）：TOS=1，IPID=4，TTL=8。

## DNS

判据：DNS 占比高（pcap_triage exit 2）、查询名 >40 字节、大量 TXT、同一域名高频查询、子域像 base32/hex。

### dnscat2 重组（BSidesSF 2017 dnscap）

配方：剥域名后缀 → hex label 拼接 → **去 9 字节 dnscat2 头**（session/seq/ack）→ **相邻去重吃重传**（比较含头整包——重传 seq/ack 相同；只比 payload 会把真实数据里的连续重复块误折叠）→ 拼接，产物按魔数识别（PNG/PK…）。脚本：

```bash
tshark -r cap.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name \
  | python "$TA/dnscat2_reassemble.py" --domain skullseclabs.org --out payload.bin
```

label 是 base32 时加 `--base32`；不给 `--domain` 会自动猜众数后缀。

### DNS 尾部字节 bit 编码（UTCTF 2026 Last Byte Standing）

每包在标准 DNS question 结构（header 12 + qname + null + type 2 + class 2）**之后**多塞一个字节 `0x30`/`0x31` = 1 bit。判据：DNS 包比查询名应有的长度略大，hex 里 `00 01`（Class IN）后跟 0x30/0x31。提取：qname 期望长度 = 12 + len(qname) + 1 + 2 + 2，超出的 trailing 字节拼 bit 串，8bit MSB-first 转 ASCII。

变体：查询名最后一个字符/每个 label 末字符/第 N 位是数据——查询名看着随机但有规律时，按位置抽字符再试 hex/base32 解码。

### TXT 长记录 / 隧道通用判据

`dns.qry.type == 16`（TXT）量大、`dns.resp.len > 512`、长 base32 子域 → 隧道。导出 `tshark -Y "dns.qry.type==16" -T fields -e dns.txt` 后按编码层剥。

### DNS 应答 oracle（ASIS Finals 2017）

服务器对正确 bit 前缀回 NOERROR、错误回 NXDOMAIN = 每查询泄 1 bit。CTF 里这是让你**复现查询逻辑离线重建**，不是让你真查——在 pcap 里把 NOERROR=1/NXDOMAIN=0 按序拼 bit 即可。

## ICMP

判据：ICMP 占比高、payload 非标准（正常 ping 是 32/64 字节固定 pattern）、payload 长度或时延呈离散档位。

| 配方 | 出处 | 做法 |
|---|---|---|
| payload 长度 = ASCII 码 | TokyoWesterns 2018 | `timing_decode.py --proto icmp --mode len`（值全在 32–126 即实锤） |
| payload 字节旋转 + base64 | HackIM 2016 | 拼 echo-request payload → 每字节减固定 SHIFT（试 1–255 找可打印）→ base64 解 |
| 请求-回复时延分档 | DefCamp 2018 Broken TV | 按 icmp.ident/seq 配对，dt<200ms=filler，200ms–1s=0，>1s=1；直方图双峰+填充区即实锤 |
| 包间隔时序 | EHAX 2026 | 见 §时序 |

## TCP flags 6bit → base64（BearCatCTF 2026 pCapsized）

判据：TCP flag 组合荒谬（FIN+SYN 同现）、同一 dport、**包数是 4 的倍数**（base64 对齐）。

```
flags & 0x3F -> 0-63 -> 正好索引 base64 字母表
encoded = ''.join(b64[p.flags & 0x3F] ...); base64.b64decode(encoded)
```

提取 flags 字节：flags 在 TCP 头偏移 13；`timing_decode.py --proto tcp --dport <p> --mode byte --offset <IP头长+13>`（IP 头通常 20 → offset 33，先 `--mode byte` 看直方图确认值域 0–63）。

## 时序（包间隔二值编码，EHAX 2026 Breathing Void）

判据：包内容完全雷同、只有两种间隔值、题目名暗示 breathing/void/silence/timing。

```bash
python "$TA/timing_decode.py" cap.pcap --proto icmp --mode interval --threshold 0.06
```

- 先打印的直方图确认双峰，自动阈值取 (min+max)/2，不齐就手给 `--threshold`
- 10ms→0 / 100ms→1 这类映射；**注意第一个间隔没有前驱**，解出来差 1 bit 时在开头补 0 再试
- bit → 8bit MSB-first → ASCII；不可打印就 `--invert` 翻极性
