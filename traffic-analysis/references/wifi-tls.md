# WPA / TLS / SMB3 解密

> 本文 `tshark` 指 SKILL.md 路径约定的 `"$TS"`（`~/Desktop/src/tools/wireshark/tshark.exe`，未加 PATH）；aircrack-ng/hashcat 在 WSL Ubuntu（`wsl -d Ubuntu -u root -- <cmd>`）。

## WPA/WEP（802.11 抓包，DefCamp 2016）

确认有 eapol 四次握手（pcap_triage 的 EAPOL 启发式，或 `tshark -Y eapol` 应见 message 1–4）：

```bash
hcxpcapngtool -o hash.hc22000 cap.pcapng        # 转 hashcat 格式（新式，推荐）
hashcat -m 22000 hash.hc22000 rockyou.txt       # 爆破
aircrack-ng -a 2 -w rockyou.txt cap.pcapng      # 或 aircrack 一把梭
aircrack-ng -a 1 cap.pcapng                     # WEP 用 PTW 攻击（快）

airdecap-ng -p "<passphrase>" -e "<SSID>" cap.pcapng   # 解密
# 产出 cap-dec.pcap -> 当新 pcap 回开局三连二次分析
```

**坑**：题目常中途换密码——解出一段后在明文流量里找下一个密码的提示，再解下一段；IPP（打印协议）流的 job-name 字段常藏 flag。多次解密要多次 airdecap。

## TLS 解密三途径

| 途径 | 条件 | 操作 |
|---|---|---|
| ① SSLKEYLOGFILE | 题目给了 keylog（.log/sslkeys.txt），或客户端可重跑 | Wireshark：Edit→Preferences→Protocols→TLS→(Pre)-Master-Secret log filename |
| ② RSA 私钥 | 题目给 server.key，**且是 RSA 密钥交换** | `tshark -r cap.pcap -o "tls.keys_list:127.0.0.1,443,http,server.key" -Y http` |
| ③ coredump 挖 master key | 给了服务端/客户端 coredump | 见下 |

keylog 格式（NSS）：`CLIENT_RANDOM <32B client_random hex> <48B master_secret hex>`

② 的死穴：ECDHE/DHE 前向加密套件用私钥**解不开**——先看 ServerHello 的 cipher suite 再决定要不要试。证书 RSA 模数弱就分解（rsatool 重建私钥）。

**③ coredump 挖 master key（PlaidCTF 2014）**：OpenSSL 的 `ssl_session_st` 里 `master_key[48]` 紧挨 `session_id[32]` **前面**。

```bash
# 1. Wireshark 里从握手拿 session id（明文）
# 2. coredump 里搜 session id 字节，往前读 48 字节即 master key
hexdump -C corefile | grep --before=5 '19 ab 5e dc'
# 3. 写成 Wireshark 兼容的 keylog：
#    RSA Session-ID:<hex_session_id> Master-Key:<hex_master_key>
```

内存 dump / Volatility 提取同样适用。

## SMB3.1.1 加密会话（配方来源：network.md §SMB3）

链路：提 NTLMv2 → 破解 → 推导会话密钥 → AES-128-GCM 解密。

```bash
# 1. 提 NTLMv2（messagetype 3 里的 NTProofStr + username）
tshark -r cap.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.auth.username -e ntlmssp.ntlmv2_response.ntproofstr
# 2. 破解
hashcat -m 5600 ntlmv2.txt rockyou.txt
```

3. 密钥推导（Python，需 pycryptodomex）：`session_key = RC4(key_exchange_key).decrypt(encrypted_session_key)`，其中 `key_exchange_key = HMAC-MD5(response_key, ntproofstr)`、`response_key = HMAC-MD5(MD4(utf16le(pw)), utf16le(user.upper()+domain.upper()))`；加解密密钥用 SP800-108 Counter KDF（HMAC-SHA256，label `SMBC2SCipherKey`/`SMBS2CCipherKey`，context = preauth hash，L=128）。

4. 解密：transform header 里 signature=[4:20]、nonce=[20:32]、AAD=[20:52]、密文=[52:]，AES-128-GCM `decrypt_and_verify`。

完整代码（SP800_108_Counter_KDF / decrypt_smb311）见来源 `ctf-forensics/network.md` §SMB3 Encrypted Traffic——用的时候从那里抄，本文件只存指针与链路。
