#!/usr/bin/env python
"""hid_keyboard.py - USB HID 键盘报告（8 字节）还原文本。

输入：tshark 导出的 hex 行（文件或 stdin），每行一个 8 字节报告：
  tshark -r usb.pcap -Y "usbhid.data" -T fields -e usbhid.data | python hid_keyboard.py
  python hid_keyboard.py reports.txt
  python hid_keyboard.py --raw dump.txt      # 连续 hex 流，按 8 字节切片

报告格式：byte0=修饰键 byte1=保留 byte2-7=键码（最多 6 键同按）。
byte2==0 是按键释放，跳过；修饰键 bit1/bit5 = 左/右 Shift。

出口码：0 正常；2 = 没有解析出任何有效报告。
"""
from __future__ import annotations

import argparse
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

KEYMAP = {
    **{0x04 + i: chr(ord("a") + i) for i in range(26)},        # 0x04-0x1d: a-z
    **{0x1E + i: str(i + 1) for i in range(9)},                # 0x1e-0x26: 1-9
    0x27: "0",
    0x28: "\n", 0x29: "<ESC>", 0x2A: "<BS>", 0x2B: "\t", 0x2C: " ",
    0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\",
    0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
    0x39: "<CAPS>",
    **{0x3A + i: f"<F{i + 1}>" for i in range(12)},            # F1-F12
    0x46: "<PRTSC>", 0x47: "<SCRLOCK>", 0x48: "<PAUSE>",
    0x49: "<INS>", 0x4A: "<HOME>", 0x4B: "<PGUP>", 0x4C: "<DEL>",
    0x4D: "<END>", 0x4E: "<PGDN>",
    0x4F: "<RT>", 0x50: "<LT>", 0x51: "<DN>", 0x52: "<UP>",
    0x54: "/", 0x55: "*", 0x56: "-", 0x57: "+", 0x58: "\n",    # 小键盘
    **{0x59 + i: str(i + 1) for i in range(9)}, 0x62: "0", 0x63: ".",
}

SHIFT_MAP = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
    "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
    "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|",
    ";": ":", "'": '"', "`": "~", ",": "<", ".": ">", "/": "?",
}

ARROWS = {"<DN>", "<UP>", "<LT>", "<RT>"}


def shift_char(ch: str) -> str:
    if ch in SHIFT_MAP:
        return SHIFT_MAP[ch]
    return ch.upper() if len(ch) == 1 and ch.isalpha() else ch


def read_reports(path, raw: bool):
    text = open(path, encoding="utf-8", errors="replace").read() if path else sys.stdin.read()
    if raw:
        hexs = "".join(c for c in text if c in "0123456789abcdefABCDEF")
        return [bytes.fromhex(hexs[i:i + 16]) for i in range(0, len(hexs) - 15, 16)]
    reports = []
    for line in text.splitlines():
        hexs = "".join(c for c in line if c in "0123456789abcdefABCDEF")
        if len(hexs) >= 16:
            reports.append(bytes.fromhex(hexs[:16]))
    return reports


def decode(reports, track_lines: bool):
    lines = {0: ""}
    cur = 0
    prev_keys = set()
    hit = 0
    for rep in reports:
        if len(rep) < 8:
            continue
        mod = rep[0]
        keys = set(k for k in rep[2:8] if k)
        hit += 1
        for k in sorted(keys - prev_keys):   # 只发新按下的键，吃掉按住重复
            ch = KEYMAP.get(k, f"<{k:02x}>")
            if mod & 0x22:                    # 左/右 Shift
                ch = shift_char(ch)
            if track_lines:
                if ch == "<DN>":
                    cur += 1
                    lines.setdefault(cur, "")
                elif ch == "<UP>":
                    cur -= 1
                    lines.setdefault(cur, "")
                elif ch in ("<LT>", "<RT>"):
                    pass
                else:
                    lines[cur] = lines.get(cur, "") + ch
            else:
                if ch in ARROWS:
                    lines[cur] = lines.get(cur, "") + ch
                else:
                    lines[cur] = lines.get(cur, "") + ch
        prev_keys = keys
    return lines, hit


def main():
    ap = argparse.ArgumentParser(description="USB HID 键盘报告 -> 还原文本（内置完整 HID 键码表）")
    ap.add_argument("file", nargs="?", help="hex 行文件；缺省读 stdin")
    ap.add_argument("--raw", action="store_true", help="输入是连续 hex 流，按 8 字节切片")
    ap.add_argument("--lines", action="store_true",
                    help="跟踪方向键分行输出（HackIT 2017 式行间导航）")
    args = ap.parse_args()

    reports = read_reports(args.file, args.raw)
    lines, hit = decode(reports, args.lines)
    if hit == 0:
        print("[!] 没有解析出有效报告（需要每行 >=8 字节 hex）", file=sys.stderr)
        sys.exit(2)
    if args.lines:
        for i in sorted(lines):
            if lines[i]:
                print(f"[line {i}] {lines[i]}")
    else:
        print("".join(lines.values()))
    print(f"[+] 报告数={hit}", file=sys.stderr)


if __name__ == "__main__":
    main()
