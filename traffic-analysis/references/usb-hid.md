# USB HID / 蓝牙抓包还原

## 键盘（EKOPARTY 2016 经典题型）

**8 字节报告结构**：

| 字节 | 含义 |
|---|---|
| 0 | 修饰键（bit1=左 Shift，bit5=右 Shift，还有 Ctrl/Alt） |
| 1 | 保留（0x00） |
| 2–7 | 最多 6 个同按键码；全 0 = 按键释放 |

提取 + 还原：

```bash
tshark -r usb.pcap -Y "usbhid.data" -T fields -e usbhid.data | python "$TA/hid_keyboard.py"
tshark -r usb.pcap -Y "usb.transfer_type==1 && usb.capdata" -T fields -e usb.capdata | python "$TA/hid_keyboard.py"
```

**字段坑**：新版 tshark 用 `usbhid.data`（纯 8 字节 HID 报告）；`usb.capdata` 是 leftover capture data，某些捕获里会带 URB 头导致偏移错位。hid_keyboard.py 每行只取前 8 字节——输出全是乱码时换另一个字段导，或对 `--raw` 模式手工对齐。

- 完整 HID 键码表 + Shift 映射内置在 `scripts/hid_keyboard.py`（0x04–0x1d=a–z，0x1e–0x27=1–0，0x28=Enter，0x2c=Space，0x4f–0x52=方向键……）
- 按住重复靠「新按键集合差分」吃掉；`--lines` 跟踪方向键把文本按行分组（HackIT 2017：flag 在方向键导航到的非零行）
- 同按 6 键的 chord 不是打字 = 速记隐写（UTCTF 2024 Gibberish）→ Plover 词典翻译，本 skill 不覆盖

## 鼠标/数位板画图（EHAX 2026 Painter）

7 字节报告：`btn, mode, dx(int16 LE), dy(int16 LE), wheel`。mode 区分绘制层（0=悬停 1/2=两种笔），相对位移**累加**成轨迹再渲染：

```bash
tshark -r usb.pcap -Y "usb.capdata" -T fields -e usb.capdata | python "$TA/mouse_render.py" --out draw
# 产出 draw_mode1.pgm / draw_mode2.pgm；每个 mode 单独渲染（不同层 = 不同字符）
```

要点：**按 mode 分开画**；相邻点位移 >50（`--max-jump`）视为抬笔不连线；`--scale 5` 起步，看不清加大；`--png` 需 PIL。标准 3 字节 boot mouse（btn, dx int8, dy int8）用 `--format simple`。

## LED Morse（BITSCTF 2017 Ghost in the Machine）

host→device 的 HID SET_REPORT 控制 Caps Lock LED（0x01=灭 0x03=亮），亮灭时长编 Morse：>300ms=划，<300ms=点。

- 过滤：`usb.transfer_type == 0x02` 且方向 host→device；数据在 URB 里（如 raw[30]）
- 按时间戳差分出点划序列 → Morse 表翻译；字母/单词边界看更长间隔

## 蓝牙 RFCOMM 重组（HITCON 2018 EV3 Basic）

CTF 爱把 flag 拆进 RFCOMM 分片，因为多数 walkthrough 止步于 TCP/UDP。

- Wireshark 过滤 `btrfcomm` / `btl2cap` / `btsnoop_hci`
- RFCOMM UIH 头 4 字节（带长度扩展 5 字节：`raw[2] & 1 == 0` → 4 否则 5）
- payload 前两字节常是 order + group_number：**先按 group 再按 order 排序**后拼接 data 字段
- 同理可套 USB bulk（`usb.transfer_type == 0x03`）与 MIDI-over-BLE

## 其他外设

- GBA 调试器 URB_INTERRUPT：块 type 6 = 显存 dump（240×160 RGB565），type 7 = 音频（hxp 2018）
- 5G SMS iMelody IEI 0x0c：音符串 `c4c4c4r2` 编 Morse（network.md §5G）
