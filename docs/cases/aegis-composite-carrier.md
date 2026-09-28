# 复合 XOR 载体（AegisTrace 判例）

> **存档说明：本文件含完整题解（golden 值/字段组合/置换表），刻意放在 skill 目录之外。**
> 请勿链回任何 skill 内文件（SKILL.md / 脚本注释 / references），否则 agent 解题时会被剧透，盲测失效。

> 来源：a52c332a 会话审计（42 min 无 flag）+ AegisTrace 复盘 v2。
> 一句话：**「字段是键的确定函数」不是「无信息」，是复合值的抵消项；真复合不一定消除冲突。**

## 识别特征（三条同时出现就该想到本模式）

1. pcap 里某条流存在**重复逻辑键**（如 `(tsval>>8)&0xff` 撞键），且冲突只由
   重传/时间戳重生字段（tsval/ipid/pkt）携带，其余字段在重复键上一致；
2. 某窄字段（如 `pay.lo`）在唯一键上可用简单式拟合（如 `(7-3k)%16`）——**确定函数**；
3. 附件二进制里有 hash 常量（memcmp/SHA-256 gate）和**零引用表**（置换/替换表）。

## 正解形状

```
nibble[k] = tsval.n0[k] ^ pay.lo[k] ^ seq.n1[k]   # 确定函数字段是要抵消的 XOR 项，不是噪声
challenge = perm_order(nibbles) 打包               # 零引用置换表是顺序源
sha256(challenge) == 二进制内嵌常量                 # oracle
```

## 两个最贵错误（都犯过）

- **E-剔除**：把确定函数字段判为「pure f(k)，零信息」剔除 ⇒ 搜索空间整条轴缺失，
  之后 >2e5 手搓候选全部不在解空间里（假覆盖）。
- **E-死磕排名**：conflict_oracle 的「消除冲突」排名结构性收敛不到真解——
  冲突由重生字段携带时，真组合继承冲突，**消不动**。排名不收敛 = 换方法的信号，
  不是调大 --top 的信号。

## 标准动作（照抄）

```bash
# 1. 冲突诊断（自动剔同键握手包；多流时先 --stream 选流）
python3 conflict_oracle.py cap.pcap --stream "A:x->B:y" --key-expr "(tsval>>8)&0xff"
# 2. 照抄它末尾的 decode_engine 处方（铺轴 + oracle 过滤）：
python3 decode_engine.py cap.pcap --stream "A:x->B:y" --key-expr "(tsval>>8)&0xff" \
  --fields "<处方给的窄字段池>" --ops xor --arity 1-3 \
  --order index --order seq --order tsval --packing hi --packing lo \
  --oracle sha256:<二进制里的 gate hash>
#    附件二进制有零引用置换表时加 --order perm:<表文件>
#    （ghidra-core scripts/unreferenced_data.py 提取零引用表）
```

## Golden（回归用）

AegisTrace `aegis_telemetry.pcap` 流 `10.77.3.41:49622->10.77.3.9:8443`：
- 键 `(tsval>>8)&0xff`，冲突键 = {5,12,31,45}（仅 tsval/tsval.n0/pkt 冲突）；
- 命中组合 `xor(pay.lo, tsval.n0, seq.n1)` + 顺序 `perm:rodata[0x32e0:0x3320]` + packing hi；
- 结果 `8f6419d4aa03b7257ecb9046186dad936114fade901b5c7a2f380bdce25577a1`，
  sha256 = `75c75a606710df2109f9eb85dfa29e7a4a46bcaf10aeb9ce00c7d99cff45146f`（= 二进制 .rodata@0x3320）。
