#!/usr/bin/env python
"""mouse_render.py - HID 鼠标/数位板相对位移 -> 累加轨迹 -> PGM 灰度图。

报告格式（--format）：
  painter  7 字节：btn, mode, dx(int16 LE), dy(int16 LE), wheel   （EHAX 2026 Painter）
  simple   3 字节：btn, dx(int8), dy(int8)                         （标准 boot mouse）

用法：
  tshark -r usb.pcap -Y "usb.capdata" -T fields -e usb.capdata | python mouse_render.py --out draw
  python mouse_render.py deltas.txt --format painter --scale 5 --out draw
  # 产出 draw_mode1.pgm / draw_mode2.pgm ...（PGM 任何看图工具都能开；
  # --png 需要 PIL，缺了就用 PGM）

出口码：0 正常；2 = 没有可用位移点。
"""
from __future__ import annotations

import argparse
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def parse_reports(text: str, fmt: str):
    out = []
    for line in text.splitlines():
        hexs = "".join(c for c in line if c in "0123456789abcdefABCDEF")
        if len(hexs) < 6:
            continue
        raw = bytes.fromhex(hexs[: len(hexs) // 2 * 2])
        if fmt == "painter" and len(raw) >= 7:
            out.append((raw[0], raw[1],
                        struct.unpack("<h", raw[2:4])[0],
                        struct.unpack("<h", raw[4:6])[0]))
        elif fmt == "simple" and len(raw) >= 3:
            dx = struct.unpack("<b", raw[1:2])[0]
            dy = struct.unpack("<b", raw[2:3])[0]
            out.append((raw[0], 1, dx, dy))
    return out


def bresenham(x0, y0, x1, y1):
    """整数直线栅格化。"""
    points = []
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
    err = dx + dy
    while True:
        points.append((x0, y0))
        if x0 == x1 and y0 == y1:
            return points
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


def render_pgm(pts, scale: int, max_jump: int, flip_y: bool, path: str):
    min_x = min(p[0] for p in pts) - 10
    min_y = min(p[1] for p in pts) - 10
    max_x = max(p[0] for p in pts) + 10
    max_y = max(p[1] for p in pts) + 10
    w = max((max_x - min_x) * scale, 1)
    h = max((max_y - min_y) * scale, 1)
    img = bytearray(b"\xff" * w * h)

    def plot(px, py):
        if 0 <= px < w and 0 <= py < h:
            img[py * w + px] = 0

    prev = None
    for x, y in pts:
        cx, cy = (x - min_x) * scale, (y - min_y) * scale
        if flip_y:
            cy = h - 1 - cy
        if prev and abs(x - prev[0]) < max_jump and abs(y - prev[1]) < max_jump:
            for px, py in bresenham(prev[2], prev[3], cx, cy):
                for ox in range(scale):
                    for oy in range(scale):
                        plot(px + ox, py + oy)
        prev = (x, y, cx, cy)

    with open(path, "wb") as f:
        f.write(f"P5\n{w} {h}\n255\n".encode())
        f.write(bytes(img))
    return w, h


def main():
    ap = argparse.ArgumentParser(description="HID 鼠标/数位板位移 -> PGM 轨迹图（纯 stdlib）")
    ap.add_argument("file", nargs="?", help="hex 行文件；缺省读 stdin")
    ap.add_argument("--format", choices=["painter", "simple"], default="painter")
    ap.add_argument("--scale", type=int, default=5)
    ap.add_argument("--max-jump", type=int, default=50, help="超过此位移视为抬笔不连线")
    ap.add_argument("--flip-y", action="store_true", help="Y 轴翻转（屏幕坐标 vs 数学坐标）")
    ap.add_argument("--out", default="draw", help="输出前缀（默认 draw）")
    ap.add_argument("--png", action="store_true", help="用 PIL 另存 PNG（未装 PIL 则跳过）")
    args = ap.parse_args()

    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    reports = parse_reports(text, args.format)

    positions = {}
    x = y = 0
    for btn, mode, dx, dy in reports:
        x += dx
        y += dy
        positions.setdefault(mode, []).append((x, y))

    if not positions:
        print("[!] 没有可用位移点", file=sys.stderr)
        sys.exit(2)

    for mode, pts in sorted(positions.items()):
        path = f"{args.out}_mode{mode}.pgm"
        w, h = render_pgm(pts, args.scale, args.max_jump, args.flip_y, path)
        print(f"[+] mode={mode} 点数={len(pts)} 画布={w}x{h} -> {path}")
        if args.png:
            try:
                from PIL import Image
                Image.open(path).save(path[:-4] + ".png")
                print(f"[+] PNG -> {path[:-4]}.png")
            except ImportError:
                print("[!] 未装 PIL，只有 PGM；pip install pillow 可开 PNG", file=sys.stderr)


if __name__ == "__main__":
    main()
