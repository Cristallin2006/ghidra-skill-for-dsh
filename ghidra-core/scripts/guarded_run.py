#!/usr/bin/env python3
"""guarded_run.py - 长任务保护执行器（铁律：timeout 长任务必须落盘）。

替代裸 `timeout N python3 x.py > log`——后者的双重陷阱：python 块缓冲 +
到点 SIGTERM = 部分结果一字节不留（chal session bf_block0：20 分钟爆破
日志 0 字节）。本包装器：

  - 逐行转发子进程输出到 stdout **和** --log 文件（每行 flush，杀掉也有）
  - 静默超过 --heartbeat 秒打一行心跳（区分"算着呢"和"死了"）
  - 到点先 terminate、宽限 --grace 秒后 kill，日志里落终止标记
  - 结束打印一行状态：rc/timeout、耗时、log 路径
  - 退出码：子进程原码；超时 = 124（对齐 timeout(1)）

用法：
  python3 guarded_run.py --timeout 1200 --log out/job.log -- python3 -u x.py [args]

建议子进程仍加 -u（交互式库自己 print 时更实时），但不依赖——本包装器
按行收，子进程缓冲最多延迟到下一次 flush，不会因 SIGKILL 丢已写管道的内容。
跨平台（Windows 无 timeout(1)，本脚本即替代品）。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="长任务保护执行器：tee 落盘 + "
                                             "心跳 + timeout 杀前保全")
    ap.add_argument("--timeout", type=int, required=True, help="秒")
    ap.add_argument("--log", required=True, help="输出落盘路径（自动建目录）")
    ap.add_argument("--heartbeat", type=int, default=30, help="静默心跳间隔秒")
    ap.add_argument("--grace", type=int, default=5, help="terminate 后宽限秒")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="-- 后的真实命令")
    args = ap.parse_args()
    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("guarded_run: -- 后缺命令", file=sys.stderr)
        return 2

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logf = log_path.open("a", encoding="utf-8", errors="replace")

    def emit(line: str, also_stdout: bool = True) -> None:
        try:
            logf.write(line + "\n")
            logf.flush()
            if also_stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
        except Exception:
            pass

    t0 = time.monotonic()
    emit(f"[guarded_run] start {time.strftime('%H:%M:%S')} "
         f"timeout={args.timeout}s cmd={' '.join(cmd)}", also_stdout=False)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            bufsize=1, errors="replace")
    last_output = time.monotonic()
    stop = threading.Event()

    def reader() -> None:
        nonlocal last_output
        try:
            for line in proc.stdout:
                last_output = time.monotonic()
                emit(line.rstrip("\n"))
        except Exception:
            pass
        finally:
            stop.set()

    def heartbeat() -> None:
        while not stop.wait(args.heartbeat):
            silent = time.monotonic() - last_output
            if silent >= args.heartbeat:
                emit(f"[guarded_run] alive, elapsed "
                     f"{int(time.monotonic() - t0)}s, "
                     f"silent {int(silent)}s", also_stdout=False)

    rt = threading.Thread(target=reader, daemon=True)
    ht = threading.Thread(target=heartbeat, daemon=True)
    rt.start()
    ht.start()

    timed_out = False
    try:
        rc = proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        emit(f"[guarded_run] TIMEOUT {args.timeout}s — terminate",
             also_stdout=False)
        proc.terminate()
        try:
            rc = proc.wait(timeout=args.grace)
        except subprocess.TimeoutExpired:
            emit("[guarded_run] grace expired — kill", also_stdout=False)
            proc.kill()
            rc = proc.wait()
        rc = 124
    stop.set()
    rt.join(timeout=5)

    elapsed = int(time.monotonic() - t0)
    status = (f"[guarded_run] {'TIMEOUT' if timed_out else 'done'} "
              f"rc={rc} elapsed={elapsed}s log={log_path}")
    emit(status)
    logf.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
