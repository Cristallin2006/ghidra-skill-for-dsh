#!/usr/bin/env python
"""win_gui_drive.py - Windows GUI 消息驱动 oracle（驱动模态对话框 GUI 批量试输入）。

需要 pywin32，用 re-tools-venv 跑：
  ~/Desktop/src/re-tools-venv/Scripts/python.exe win_gui_drive.py ...

铁律（五题复盘 A4② / RE2.exe 实战）：
  * 打开窗口 / 触发弹模态对话框用 PostMessage —— 模态对话框里 SendMessage 会死锁
  * 高频连点用 SendMessage(BM_CLICK) —— PostMessage 队列约 10000 条后静默丢弃

流程：按窗口标题/类名找顶层窗口 -> 枚茄子控件（Edit/Button/Static...）->
      [--open 匹配控件]（PostMessage，可弹模态；--wait-ms 后自动重新定位窗口）->
      [--set 匹配控件 文本]（WM_SETTEXT）->
      [--click 匹配控件]（SendMessage BM_CLICK，重复 --max-reps 次）->
      [--read 匹配控件]（读回文本，可配 --expect 正则做结果判定）

控件匹配语法（对枚举到的每个子控件逐一判定）：
  class=Edit     类名子串（不区分大小写）
  text=确定      控件文本子串
  id=1001        控件 ID（GetDlgCtrlID，支持 0x 前缀）
  确定           裸串：先匹配文本子串，再匹配类名子串

示例：
  # 只枚举窗口结构（不伤目标）
  python win_gui_drive.py --title "RE2" --dry-run
  # 点 Register 弹出模态框，等 500ms 重定位，填序列号框，连点 Check 1000 次，读结果
  python win_gui_drive.py --title "RE2" --class "#32770" \\
      --open "text=Register" --wait-ms 500 \\
      --set "class=Edit" "AAAAAAAA" \\
      --click "text=Check" --max-reps 1000 --delay-ms 2 \\
      --read "class=Static" --expect "OK|成功"
  # 结果同时存 JSON
  python win_gui_drive.py --title "RE2" --dry-run --json @out.json

出口码：0 正常；1 用法错误；2 闸门拦截（窗口/控件未命中，或 --expect 不匹配）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time

for _s in (sys.stdout, sys.stderr):
    _s.reconfigure(encoding="utf-8", errors="replace")

try:
    import win32con
    import win32gui
except ImportError:
    print("[!] 需要 pywin32：用 re-tools-venv 跑 "
          "(~/Desktop/src/re-tools-venv/Scripts/python.exe)", file=sys.stderr)
    sys.exit(1)

WM_SETTEXT = win32con.WM_SETTEXT
BM_CLICK = win32con.BM_CLICK


class Parser(argparse.ArgumentParser):
    def error(self, message):  # 家族约定：用法错误 exit 1（argparse 默认 exit 2 与闸门冲突）
        print(f"[!] 用法错误: {message}", file=sys.stderr)
        self.print_usage(sys.stderr)
        sys.exit(1)


def find_windows(title_re: str | None, class_re: str | None) -> list[dict]:
    tp = re.compile(title_re, re.I) if title_re else None
    cp = re.compile(class_re, re.I) if class_re else None
    hits = []

    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return True
        try:
            title = win32gui.GetWindowText(hwnd)
            cls = win32gui.GetClassName(hwnd)
        except Exception:
            return True
        if tp and not tp.search(title):
            return True
        if cp and not cp.search(cls):
            return True
        hits.append({"hwnd": hwnd, "title": title, "class": cls})
        return True

    win32gui.EnumWindows(cb, None)
    return hits


def enum_children(hwnd: int) -> list[dict]:
    kids = []

    def cb(h, _):
        try:
            kids.append({
                "hwnd": h,
                "class": win32gui.GetClassName(h),
                "text": win32gui.GetWindowText(h),
                "id": win32gui.GetDlgCtrlID(h),
            })
        except Exception:
            pass
        return True

    try:
        win32gui.EnumChildWindows(hwnd, cb, None)
    except Exception:
        pass
    return kids


def parse_match(spec: str):
    if spec.startswith("class="):
        pat = spec[6:].lower()
        return lambda k: pat in k["class"].lower()
    if spec.startswith("text="):
        pat = spec[5:]
        return lambda k: pat in k["text"]
    if spec.startswith("id="):
        cid = int(spec[3:], 0)
        return lambda k: k["id"] == cid
    return lambda k: spec in k["text"] or spec.lower() in k["class"].lower()


def matched_hwnds(targets: list[dict], spec: str) -> list[int]:
    pred = parse_match(spec)
    out = []
    for t in targets:
        for k in t["children"]:
            if pred(k):
                out.append(k["hwnd"])
    return out


def main() -> int:
    ap = Parser(description="Windows GUI 消息驱动 oracle（PostMessage 开模态 / "
                              "SendMessage BM_CLICK 高频连点 / WM_SETTEXT 填框）")
    ap.add_argument("--title", help="顶层窗口标题正则（不区分大小写）")
    ap.add_argument("--class", dest="cls", help="顶层窗口类名正则（不区分大小写）")
    ap.add_argument("--dry-run", action="store_true", help="只枚举窗口结构，不执行任何动作")
    ap.add_argument("--open", action="append", default=[], metavar="MATCH",
                    help="PostMessage(BM_CLICK) 触发一次（开模态对话框用这个，防死锁）；可重复")
    ap.add_argument("--wait-ms", type=int, default=300,
                    help="--open 后等待毫秒数再重新定位窗口（默认 300）")
    ap.add_argument("--set", nargs=2, action="append", default=[],
                    metavar=("MATCH", "TEXT"), help="WM_SETTEXT 置文本；可重复")
    ap.add_argument("--click", action="append", default=[], metavar="MATCH",
                    help="SendMessage(BM_CLICK) 连点 --max-reps 次（高频用这个，防队列丢弃）；可重复")
    ap.add_argument("--max-reps", type=int, default=1, help="每个 --click 的连点次数（默认 1）")
    ap.add_argument("--delay-ms", type=int, default=0, help="连点间隔毫秒（默认 0）")
    ap.add_argument("--read", action="append", default=[], metavar="MATCH",
                    help="动作完成后读回匹配控件文本；可重复")
    ap.add_argument("--expect", help="对所有 --read 结果做正则判定，任一不匹配则 exit 2")
    ap.add_argument("--json", metavar="@out.json", help="完整结果写 JSON 文件")
    args = ap.parse_args()

    if not args.title and not args.cls:
        ap.error("--title 与 --class 至少给一个")
    if args.max_reps < 1:
        ap.error("--max-reps 必须 >= 1")

    gates = []  # 闸门拦截原因，非空则 exit 2
    result: dict = {"query": {"title": args.title, "class": args.cls},
                    "dry_run": args.dry_run, "targets": [], "actions": {}, "reads": []}

    def locate() -> list[dict]:
        ts = find_windows(args.title, args.cls)
        for t in ts:
            t["children"] = enum_children(t["hwnd"])
        return ts

    targets = locate()
    result["targets"] = targets
    if not targets:
        gates.append(f"未找到顶层窗口 title={args.title!r} class={args.cls!r}")
        result["gates"] = gates
        _emit(result, args.json)
        return 2

    if args.dry_run:
        _emit(result, args.json)
        return 0

    # 1) --open：PostMessage（模态安全），随后等待 + 重新定位（弹出的对话框可能才是后续目标）
    opened = []
    for spec in args.open:
        hs = matched_hwnds(targets, spec)
        if not hs:
            gates.append(f"--open {spec!r} 未匹配任何控件")
            continue
        for h in hs:
            win32gui.PostMessage(h, BM_CLICK, 0, 0)
        opened.append({"match": spec, "count": len(hs)})
    if opened:
        result["actions"]["open"] = opened
        time.sleep(args.wait_ms / 1000.0)
        targets = locate()
        result["targets_after_open"] = targets
        if not targets:
            gates.append("--open 后重新定位窗口失败（可能被关闭）")

    # 2) --set：WM_SETTEXT 置文本
    sets = []
    for spec, text in args.set:
        hs = matched_hwnds(targets, spec)
        if not hs:
            gates.append(f"--set {spec!r} 未匹配任何控件")
            continue
        for h in hs:
            win32gui.SendMessage(h, WM_SETTEXT, 0, text)
        sets.append({"match": spec, "text": text, "count": len(hs)})
    if sets:
        result["actions"]["set"] = sets

    # 3) --click：SendMessage(BM_CLICK) 连点
    clicks = []
    for spec in args.click:
        hs = matched_hwnds(targets, spec)
        if not hs:
            gates.append(f"--click {spec!r} 未匹配任何控件")
            continue
        n_sent = 0
        for rep in range(args.max_reps):
            for h in hs:
                if not win32gui.IsWindow(h):
                    gates.append(f"--click {spec!r} 第 {rep + 1} 轮时控件已销毁（窗口可能已关闭）")
                    break
                win32gui.SendMessage(h, BM_CLICK, 0, 0)
                n_sent += 1
            else:
                if args.delay_ms:
                    time.sleep(args.delay_ms / 1000.0)
                continue
            break
        clicks.append({"match": spec, "controls": len(hs), "clicks_sent": n_sent})
    if clicks:
        result["actions"]["click"] = clicks

    # 4) --read：读回结果控件文本
    expect_re = re.compile(args.expect) if args.expect else None
    for spec in args.read:
        hs = matched_hwnds(targets, spec)
        if not hs:
            gates.append(f"--read {spec!r} 未匹配任何控件")
            continue
        for h in hs:
            try:
                text = win32gui.GetWindowText(h) if win32gui.IsWindow(h) else None
            except Exception:
                text = None
            ok = bool(expect_re.search(text)) if (expect_re and text is not None) else None
            if ok is False:
                gates.append(f"--read {spec!r} 文本 {text!r} 不匹配 --expect {args.expect!r}")
            result["reads"].append({"match": spec, "hwnd": h, "text": text, "expect_ok": ok})

    result["gates"] = gates
    _emit(result, args.json)
    return 2 if gates else 0


def _emit(result: dict, json_path: str | None) -> None:
    line = json.dumps(result, ensure_ascii=False, indent=2)
    print(line)
    if json_path:
        with open(json_path.lstrip("@"), "w", encoding="utf-8") as f:
            f.write(line + "\n")


if __name__ == "__main__":
    sys.exit(main())
