#!/usr/bin/env python
"""Environment self-check for the ghidra-reverse skill (replaces the old
plugin's ghidra_status/ghidra_capabilities).

Host-side tool (run with any Python 3, NOT through driver.py exec):

  python doctor.py            # human-readable + JSON summary
  python doctor.py "@<path>"  # also write the JSON to <path>

Exit code 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import driver  # noqa: E402 - reuse the skill's environment resolution


def check(label, ok, detail=""):
    return {"check": label, "ok": bool(ok), "detail": detail}


def main() -> int:
    out_path = None
    if len(sys.argv) > 1 and sys.argv[1].startswith("@"):
        out_path = sys.argv[1][1:]

    results = []

    # 1. Ghidra install + launchers
    try:
        install = driver._configure_environment()
        headless = install / "support" / "analyzeHeadless.bat"
        gui = install / "ghidraRun.bat"
        ok = headless.is_file() and gui.is_file()
        results.append(check("ghidra_install", ok,
                             f"install={install} headless={headless.is_file()} "
                             f"gui={gui.is_file()}"))
    except SystemExit as exc:
        results.append(check("ghidra_install", False, str(exc)))
        install = None

    # 2. Java
    java_home = None
    try:
        install = install or driver._configure_environment()
        java_home = os_environ_java()
        java_exe = Path(java_home) / "bin" / "java.exe" if java_home else None
        if java_exe and java_exe.is_file():
            proc = subprocess.run([str(java_exe), "-version"],
                                  capture_output=True, text=True, timeout=30)
            ver_line = (proc.stderr or proc.stdout or "").splitlines()[0]
            results.append(check("java", proc.returncode == 0,
                                 f"JAVA_HOME={java_home} version={ver_line}"))
        else:
            results.append(check("java", False,
                                 f"java.exe not found under JAVA_HOME={java_home}"))
    except Exception as exc:
        results.append(check("java", False, str(exc)))

    # 3. pyghidra venv
    venv_python = Path.home() / "Desktop" / "src" / "ghidra-bridge" / \
        "pyghidra-venv" / "Scripts" / "python.exe"
    if not venv_python.is_file():
        results.append(check("pyghidra_venv", False,
                             f"venv python not found at {venv_python}"))
    else:
        try:
            proc = subprocess.run(
                [str(venv_python), "-c",
                 "import importlib.metadata, pyghidra; "
                 "print(importlib.metadata.version('pyghidra'))"],
                capture_output=True, text=True, timeout=60)
            ver = (proc.stdout or "").strip()
            ok = proc.returncode == 0 and ver
            results.append(check("pyghidra_venv", bool(ok),
                                 f"python={venv_python} pyghidra={ver or proc.stderr.strip()[:200]}"))
        except Exception as exc:
            results.append(check("pyghidra_venv", False, str(exc)))

    # 4. Workspace writable (+ junction resolves)
    try:
        ws = driver.workspace()
        probe = ws / "out" / ".doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        link = driver.project_root()
        results.append(check("workspace", True,
                             f"ws={ws} projects(via junction)={link}"))
    except Exception as exc:
        results.append(check("workspace", False, str(exc)))

    # 5. Existing projects
    try:
        projects_dir = driver.project_root()
        projects = sorted(p.stem for p in projects_dir.glob("*.gpr"))
        results.append(check("projects", True,
                             f"count={len(projects)} names={projects}"))
    except Exception as exc:
        results.append(check("projects", False, str(exc)))

    all_ok = all(r["ok"] for r in results)
    summary = {"status": "ok" if all_ok else "fail", "checks": results}
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    print(text)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    return 0 if all_ok else 1


def os_environ_java():
    import os
    return os.environ.get("JAVA_HOME") or driver.DEFAULT_JAVA_HOME


if __name__ == "__main__":
    raise SystemExit(main())
