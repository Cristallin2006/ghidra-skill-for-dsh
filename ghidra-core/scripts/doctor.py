#!/usr/bin/env python
"""Environment self-check for the ghidra-core skill (replaces the old
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


# ── Toolchain registry ────────────────────────────────────────────────────────
# Single source of truth for external-tool availability across the skill
# family.  kind: "path" (explicit file), "which" (PATH lookup), "pyimport"
# (import probe inside the re-tools venv python).
_RE_TOOLS = Path.home() / "Desktop" / "src" / "re-tools-venv" / "Scripts"
_TOOLS_DIR = Path.home() / "Desktop" / "src" / "tools"
_UNP_VENV = Path.home() / "Desktop" / "src" / "unpacker-venv" / "Scripts"


def _probe(entry):
    import shutil

    kind = entry.kind
    if kind == "path":
        p = Path(entry.path).expanduser()
        return p.is_file(), str(p)
    if kind == "which":
        found = shutil.which(entry.exe)
        return bool(found), found or f"{entry.exe} not on PATH"
    if kind == "pyimport":
        py = _RE_TOOLS / "python.exe"
        if not py.is_file():
            return False, f"re-tools-venv missing ({py})"
        proc = subprocess.run(
            [str(py), "-c", f"import {entry.module}"],
            capture_output=True, text=True, timeout=60)
        ok = proc.returncode == 0
        return ok, f"module {entry.module} in re-tools-venv: {'ok' if ok else proc.stderr.strip()[:120]}"
    raise ValueError(kind)


class _Tool:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def check(self):
        ok, detail = _probe(self)
        status = "available" if ok else (
            "missing (WARN, tier A)" if self.tier == "A"
            else f"not installed (tier {self.tier}, 按需)")
        return {
            "check": f"tool:{self.name}", "name": self.name, "tier": self.tier,
            "ok": ok, "status": status, "detail": detail,
            "referenced_by": self.refs, "install_hint": self.hint,
        }


TOOL_REGISTRY = [
    # ── Tier A: lightweight, high-frequency, installed ──
    _Tool(name="checksec", tier="A", kind="path",
          path=str(_RE_TOOLS / "checksec.exe"), refs="re-triage",
          hint="pip install checksec.py（进 re-tools-venv）；Windows GBK 控制台跑时前置 PYTHONUTF8=1（rich 进度条 Unicode 崩溃）"),
    _Tool(name="goresym", tier="A", kind="path",
          path=str(_TOOLS_DIR / "goresym" / "GoReSym.exe"), refs="re-triage",
          hint="github.com/mandiant/GoReSym release win64 zip 解压到 tools/goresym/"),
    _Tool(name="pyinstxtractor", tier="A", kind="path",
          path=str(_TOOLS_DIR / "pyinstxtractor" / "pyinstxtractor.py"), refs="re-triage",
          hint="github.com/extremecoders-re/pyinstxtractor 单文件拷到 tools/pyinstxtractor/"),
    _Tool(name="frida", tier="A", kind="path",
          path=str(_RE_TOOLS / "frida.exe"),
          refs="ghidra-core/ghidra-static/vuln-audit/re-unpack",
          hint="pip install frida-tools（进 re-tools-venv）"),
    _Tool(name="z3", tier="A", kind="pyimport", module="z3",
          refs="ghidra-static（ctf-patterns/anti-analysis）",
          hint="pip install z3-solver（进 re-tools-venv）"),
    _Tool(name="rust-demangler", tier="A", kind="pyimport", module="rust_demangler",
          refs="re-triage（rustfilt 的 pip 替代：无 cargo，纯 wheel 支持 _ZN legacy mangling）",
          hint="pip install rust-demangler（进 re-tools-venv）"),
    _Tool(name="upx", tier="A", kind="path",
          path=str(_TOOLS_DIR / "upx" / "upx.exe"), refs="re-triage/re-unpack",
          hint="github.com/upx/upx release win64 zip 解压到 tools/upx/"),
    _Tool(name="unpacker", tier="A", kind="path",
          path=str(_UNP_VENV / "unpacker.exe"), refs="re-unpack",
          hint="python3.12 -m venv unpacker-venv && pip install -e <Unpacker 克隆>"),
    # ── Tier B: heavy, install on demand ──
    _Tool(name="angr", tier="B", kind="pyimport", module="angr",
          refs="ghidra-static/re-triage/vuln-audit",
          hint="pip install angr（进 re-tools-venv）"),
    _Tool(name="qiling", tier="B", kind="pyimport", module="qiling",
          refs="ghidra-static/re-triage/re-unpack",
          hint="pip install qiling + 准备 rootfs（~/Desktop/src/qiling-rootfs）"),
    _Tool(name="speakeasy", tier="B", kind="pyimport", module="speakeasy",
          refs="（仿真备选）",
          hint="pip install speakeasy-emulator（进 re-tools-venv）"),
    _Tool(name="unipacker", tier="B", kind="pyimport", module="unipacker",
          refs="re-unpack",
          hint='pip install "unpacker[unipacker]"（进 unpacker-venv，已钉 setuptools<81）'),
    _Tool(name="ghidriff", tier="B", kind="pyimport", module="ghidriff",
          refs="ghidra-core（references/headless.md §8）",
          hint="pip install ghidriff"),
    _Tool(name="simba", tier="B", kind="pyimport", module="simba",
          refs="re-triage（references/anti-analysis.md MBA 化简）",
          hint="pip install simba-simplifier"),
    _Tool(name="strings", tier="B", kind="which", exe="strings",
          refs="re-triage（strings -el 补宽字符）",
          hint="Git Bash 无 binutils；用 python re.findall(rb'[ -~]{4,}', data) 等价物或装 binutils"),
    _Tool(name="readelf", tier="B", kind="which", exe="readelf",
          refs="re-triage/ghidra-static",
          hint="Git Bash 无 binutils；ELF 解析用 pyelftools（unpacker-venv 已带）"),
    # ── Tier C: GUI / manual ──
    _Tool(name="dnSpyEx", tier="C", kind="which", exe="dnSpy",
          refs="re-triage（.NET 样本）",
          hint="github.com/dnSpyEx/dnSpy release 解压即用（GUI）"),
    _Tool(name="de4dot", tier="C", kind="which", exe="de4dot",
          refs="re-triage（.NET 混淆）",
          hint="github.com/de4dot/de4dot 构建或取 release（CLI）"),
    _Tool(name="DIE", tier="C", kind="which", exe="diec",
          refs="re-triage（查壳 GUI/CLI）",
          hint="github.com/horsicq/DIE-engine release；diec 是其 CLI"),
    _Tool(name="x64dbg", tier="C", kind="which", exe="x64dbg",
          refs="ghidra-static（Windows GUI crackme 动态）",
          hint="x64dbg.com 下载快照解压（GUI 调试器）"),
    _Tool(name="GOOMBA", tier="C", kind="which", exe="GOOMBA",
          refs="re-triage（references/anti-analysis.md MBA 化简）",
          hint="Ghidra 插件 jar 拷进 <ghidra>/Extensions/Ghidra 后 GUI 启用"),
    _Tool(name="golang-loader", tier="C", kind="which", exe="golang-loader",
          refs="re-triage（Go 字符串恢复）",
          hint="Ghidra 插件（GUI 安装）；或用 GoReSym（Tier A）替代大部分场景"),
]


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

    # 6. ghidra-rpc venv (engine environment)
    rpc_venv_python = Path.home() / "Desktop" / "src" / "ghidra-bridge" / \
        "ghidra-rpc-venv" / "Scripts" / "python.exe"
    if not rpc_venv_python.is_file():
        results.append(check("rpc_venv", False,
                             f"venv python not found at {rpc_venv_python}"))
    else:
        results.append(check("rpc_venv", True, f"python={rpc_venv_python}"))

    # 7. ghidra-rpc importable + version (editable install of engine/)
    if rpc_venv_python.is_file():
        try:
            proc = subprocess.run(
                [str(rpc_venv_python), "-c",
                 "import importlib.metadata, ghidra_rpc; "
                 "print(importlib.metadata.version('ghidra-rpc')); "
                 "print(ghidra_rpc.__file__)"],
                capture_output=True, text=True, timeout=60)
            lines = (proc.stdout or "").strip().splitlines()
            ver = lines[0] if lines else ""
            loc = lines[1] if len(lines) > 1 else ""
            ok = proc.returncode == 0 and ver and "engine" in loc.replace("/", "\\")
            results.append(check("rpc_package", bool(ok),
                                 f"version={ver} location={loc}"
                                 + ("" if ok else " (expected editable install from skill engine/)")))
        except Exception as exc:
            results.append(check("rpc_package", False, str(exc)))

    # 8. daemon start/stop smoke (slow: one JVM cold start, ~30-60 s)
    if "--quick" not in sys.argv:
        try:
            import rpc_driver  # sibling script
            env = rpc_driver.configure_env()
            probe_gpr = rpc_driver.WS_LINK / "projects-rpc" / "doctor_probe.gpr"
            start = rpc_driver.run_rpc(env, probe_gpr,
                                       ["start", "--headless", "--detach"], timeout=300)
            if not start.get("ok"):
                results.append(check("rpc_daemon", False,
                                     f"start failed: {str(start)[:200]}"))
            else:
                status = rpc_driver.run_rpc(env, probe_gpr, ["status"], timeout=60)
                running = bool((status.get("result") or {}).get("running"))
                stop = rpc_driver.run_rpc(env, probe_gpr, ["stop"], timeout=120)
                stopped = bool((stop.get("result") or {}).get("status") == "stopped") \
                    or stop.get("ok")
                ok = running and stopped
                results.append(check("rpc_daemon", ok,
                                     f"start=ok running={running} stop_ok={stopped}"))
                # probe project is empty; remove it
                import shutil
                shutil.rmtree(probe_gpr.parent / "doctor_probe.rep",
                              ignore_errors=True)
                (probe_gpr.parent / "doctor_probe.gpr").unlink(missing_ok=True)
        except Exception as exc:
            results.append(check("rpc_daemon", False, str(exc)))

    # ── Toolchain layer (external tools referenced by the skill family) ──
    # The single source of truth for tool availability. Tier A missing = warn
    # (never fails the run; only Ghidra-core failures do). Tier B/C missing =
    # informational "not installed (按需)".
    toolchain = [t.check() for t in TOOL_REGISTRY]
    tier_a = [t for t in toolchain if t["tier"] == "A"]
    tier_b = [t for t in toolchain if t["tier"] == "B"]
    tier_c = [t for t in toolchain if t["tier"] == "C"]

    def _avail(ts):
        return f"{sum(1 for t in ts if t['ok'])}/{len(ts)}"

    all_ok = all(r["ok"] for r in results)
    summary = {
        "status": "ok" if all_ok else "fail",
        "checks": results,
        "toolchain": toolchain,
        "toolchain_summary": {
            "tier_A": _avail(tier_a),
            "tier_B": _avail(tier_b),
            "tier_C": _avail(tier_c),
            "tier_A_missing": [t["name"] for t in tier_a if not t["ok"]],
            "note": "tier A 缺失=warn（按 hint 补装）；tier B/C 缺失=按需，不算问题；"
                    "exit code 只反映 Ghidra 核心环境",
        },
    }
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    print(text)
    # human-readable one-liner
    print(f"toolchain: tier A {_avail(tier_a)}"
          + (f" (missing: {', '.join(summary['toolchain_summary']['tier_A_missing'])})"
             if summary["toolchain_summary"]["tier_A_missing"] else "")
          + f" | tier B {_avail(tier_b)} | tier C {_avail(tier_c)}",
          file=sys.stderr)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    return 0 if all_ok else 1


def os_environ_java():
    import os
    return os.environ.get("JAVA_HOME") or driver.DEFAULT_JAVA_HOME


if __name__ == "__main__":
    raise SystemExit(main())
