# pcap 分诊细节：修复 / 文件提取 / 凭据收割

## 0. 修复（打不开才做）

magic bytes 速查（`xxd cap.pcap | head -1`）：

| 文件头 hex | 格式 |
|---|---|
| `d4 c3 b2 a1` | pcap 小端（微秒） |
| `a1 b2 c3 d4` | pcap 大端（微秒） |
| `4d 3c b2 a1` / `a1 b2 3c 4d` | pcap 纳秒（LE/BE） |
| `0a 0d 0d 0a` | pcapng |

```bash
pcapfix -d corrupted.pcap          # 先上工具（CSAW 2016），能修断头/断包/错长
editcap -F pcap in.pcapng out.pcap # pcapng -> pcap（本 skill 脚本只吃经典 pcap）
mergecap -w merged.pcap a.pcap b.pcap
```

pcapfix 修不动再手工：pcap 全局头 24 字节 = magic(4) + version 2.4(4) + thiszone(4) + sigfigs(4) + snaplen(4) + linktype(4)，用 python struct 重写 magic 和版本即可（配方来源：network.md §pcapfix）。

## 1. 开局三连细节

```bash
python "$TA/pcap_triage.py" cap.pcap     # 零依赖保底；exit 2 = 占比>60% 信号载体
capinfos cap.pcap                        # 有 Wireshark 时：包数/时长/速率
tshark -r cap.pcap -q -z io,phs          # 协议分层统计
tshark -r cap.pcap -q -z conv,tcp        # TCP 会话（按字节排序找大流量）
tshark -r cap.pcap -q -z endpoints,ip    # 端点
tshark -r cap.pcap -q -z io,stat,1       # 每秒 I/O（规则间隔 = beacon/C2）
```

**大 pcap 找信号载体**：百万包级题目信号常在包数最少的子集（EHAX 2026：多接口 pcapng 只有一个接口的几百包携带数据）。按接口/协议/会话包数倒序，先查最小的。`pcap_triage.py --json @out.json` 落盘后慢慢翻。

## 2. 文件提取（第一动作，先看有没有现成文件）

```bash
tshark -r cap.pcap --export-objects http,/tmp/http_obj    # HTTP 对象（MetaCTF 2026：flag 常在提取出的文件本身）
tshark -r cap.pcap --export-objects smb,/tmp/smb_obj
tshark -r cap.pcap --export-objects tftp,/tmp/tftp_obj
tshark -r cap.pcap -q -z "follow,tcp,ascii,0"             # 跟流看内容
tshark -r cap.pcap -q -z "follow,tcp,raw,3" > stream.bin  # 原始字节落盘
tcpflow -r cap.pcap -o /tmp/flows                         # 全量流重组落盘
```

- Wireshark GUI：File → Export Objects → HTTP/SMB/IMF
- 跟流看到 `PK\x03\x04` / `7z` / `%PDF` 魔数 → raw 导出后 `binwalk -e` / `foremost -i`
- multipart/form-data POST 到 /upload + 非常规 User-Agent = 外传签名（MetaCTF 2026 Dead Drop）

**分片压缩包重组**（ASIS Finals 2013）：大量同尺寸 HTTP 文件 + 一个较小尾片 + 首片带压缩包魔数 = 分片压缩包。顺序不是下载顺序——找 pcap 里的 Apache/nginx 目录列表页，按修改时间戳排序 `cat` 拼接；密码常在另一条 TCP 聊天流里（follow tcp 找 "secret key"）。

## 3. 明文凭据收割

| 协议 | 过滤器 / 命令 |
|---|---|
| FTP | `ftp.request.command == "USER" \|\| ftp.request.command == "PASS"`，`-e ftp.request.arg` |
| Telnet | follow tcp 全程明文 |
| HTTP Basic | `http.authbasic`（base64，直接解码） |
| SMTP AUTH | `smtp.req.command == "AUTH"`（base64） |
| NTLMv2 | 见下 |
| shell 流 | follow tcp 后 `grep -i password`；反 shell 签名：`cannot set terminal process group`、`www-data@host:/path$` |

**NTLMv2 → hashcat**（Pragyan 2026）：

```bash
tshark -r cap.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.auth.username -e ntlmssp.ntlmv2_response.ntproofstr -e ntlmssp.ntlmv2_response
# 拼成 user::domain:challenge:NTProofStr:blob
hashcat -m 5600 ntlmv2.txt rockyou.txt
```

已知密码格式（如纯小写+长度）就自己写爆破循环：MD4(utf16le(pw)) → HMAC-MD5(user.upper()+domain) → HMAC-MD5(server_challenge+blob) 对 NTProofStr（配方来源：network-advanced.md §NTLMv2）。

## 4. strings 碰运气（10 秒，不做白不做）

```bash
strings cap.pcap | grep -iE 'flag|ctf|key|pass'
tshark -r cap.pcap -A 2>/dev/null | grep -i flag    # tcpdump -A 同理
```

明文凭据/flag 常直接躺在 payload 里，这一步中了就省掉后面所有事。不中再进路由表。
