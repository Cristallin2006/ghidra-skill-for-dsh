"""PyGhidra driver for the ghidra-reverse skill.

Replaces the analyzeHeadless-based `run-headless.sh` invocation model. PyGhidra
scripts cannot run under `analyzeHeadless.bat` at all -- that launcher starts a
plain JVM, and Ghidra raises "Ghidra was not started with PyGhidra. Python is not
available" -- so every script invocation has to go through the PyGhidra launcher,
which lives in the Python interpreter of a PyGhidra-enabled environment.

Subcommands
-----------
  import <binary> [--force]
      Import a binary into the workspace project, run auto-analysis, and run
      triage_scan.py to produce out/<name>.triage.json.
  exec <binary> <script.py> [args...]
      Run a script against the project's program (read-only intent; scripts that
      write must use exec-w).
  exec-w <binary> <script.py> [args...]
      Same, but the project is saved after the script runs.
  list <binary>
      List the programs inside the workspace project.

Script arguments follow the skill's `@out` convention: a first argument of the
form `@<abs-path>` names the JSON output file and is passed through unchanged.

Environment
-----------
  GHIDRA_INSTALL_DIR   Ghidra install (default: the deployment's install)
  DSH_GHIDRA_WS        workspace root (default: ~/.dsh/ghidra-workspace)
  PYGHIDRA_JAVA_HOME   JDK home for the JVM (must be a JDK, not a JRE)
"""
from __future__ import annotations

import argparse
import contextlib
import os
import re
import sys
from pathlib import Path

DEFAULT_GHIDRA = r"C:\t001s\ghidra_12.1.3_PUBLIC_20260817\ghidra_12.1.3_PUBLIC"
DEFAULT_JAVA_HOME = r"C:\Java"
DEFAULT_WS = Path(os.path.expanduser("~")) / ".dsh" / "ghidra-workspace"


def _configure_environment() -> Path:
    """Point PyGhidra at the install and a real JDK before it starts the JVM."""
    install = os.environ.get("GHIDRA_INSTALL_DIR") or DEFAULT_GHIDRA
    os.environ["GHIDRA_INSTALL_DIR"] = install
    if not os.environ.get("JAVA_HOME"):
        for candidate in (os.environ.get("PYGHIDRA_JAVA_HOME"), DEFAULT_JAVA_HOME):
            if candidate and (Path(candidate) / "bin" / "java.exe").is_file():
                os.environ["JAVA_HOME"] = candidate
                break
    if not (Path(install) / "Ghidra").is_dir():
        raise SystemExit(f"Ghidra install not found at {install} (set GHIDRA_INSTALL_DIR)")
    return Path(install)


def workspace() -> Path:
    ws = Path(os.environ.get("DSH_GHIDRA_WS") or DEFAULT_WS)
    for sub in ("projects", "out", "logs"):
        (ws / sub).mkdir(parents=True, exist_ok=True)
    return ws


def project_root() -> Path:
    """Return a project directory whose path has no '.' element.

    Ghidra's ProjectLocator rejects any path element starting with a dot, and the
    default workspace lives under ~/.dsh, so the projects directory is exposed
    through a junction whose path contains no dot elements. Files physically stay
    in the real workspace.
    """
    ws = workspace()
    projects = ws / "projects"
    if ".dsh" not in projects.parts:
        return projects

    link = Path(os.environ.get("DSH_GHIDRA_WS_LINK") or (Path(os.path.expanduser("~")) / "dsh-ghidra-workspace"))
    link_projects = link / "projects"
    if not link_projects.is_dir():
        if os.name != "nt":
            link.mkdir(parents=True, exist_ok=True)
            try:
                if not link.exists():
                    link.symlink_to(ws, target_is_directory=True)
            except OSError as exc:  # pragma: no cover - environment dependent
                raise SystemExit(
                    f"cannot expose {ws} without a dot element: {exc}. "
                    "Set DSH_GHIDRA_WS to a path with no '.' element."
                ) from exc
        else:
            import subprocess

            if link.exists():
                import shutil

                shutil.rmtree(link, ignore_errors=True) if link.is_dir() and not link.is_symlink() else link.unlink(missing_ok=True)
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(ws)],
                check=True, capture_output=True, text=True,
            )
    if not (link / "projects").is_dir():
        raise SystemExit(f"junction {link} does not resolve to {ws}")
    return link / "projects"


def project_name_for(binary: Path) -> str:
    """Stable project name derived from the binary's content, as the skill documents."""
    import hashlib

    digest = hashlib.sha256(binary.read_bytes()).hexdigest()[:16]
    return f"dsh_{digest}"


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def run_script(script: Path, project, program, script_args, echo: bool = True):
    """Run one GhidraScript with currentProgram bound to `program`."""
    import pyghidra

    before = sys.stdout
    try:
        return pyghidra.ghidra_script(
            path=str(script),
            project=project,
            program=program,
            script_args=list(script_args),
            echo_stdout=echo,
            echo_stderr=echo,
        )
    finally:
        sys.stdout = before


# --------------------------------------------------------------------------- import

def cmd_import(args: argparse.Namespace) -> int:
    import pyghidra

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")

    ws = workspace()
    name = project_name_for(binary)
    project_path = project_root()
    gpr = project_path / f"{name}.gpr"

    if gpr.exists() and not args.force:
        print(f"import: project '{name}' already exists (use --force to re-import)")
    elif gpr.exists():
        import shutil

        shutil.rmtree(project_path / f"{name}.rep", ignore_errors=True)
        gpr.unlink(missing_ok=True)
        print(f"import: removed existing project '{name}'")

    print(f"import: project '{name}' from {binary.name}")
    project = pyghidra.open_project(str(project_path), name, create=True)
    try:
        with _open_program(pyghidra, project, binary, create=True) as program:
            print("import: analysis")
            log = pyghidra.analyze(program)
            (ws / "logs" / f"{name}.analysis.log").write_text(log or "", encoding="utf-8")

            triage = script_dir() / "triage_scan.py"
            out = ws / "out" / f"{binary.name}.triage.json"
            if not triage.is_file():
                print(f"import: WARNING: triage_scan.py missing at {triage}", file=sys.stderr)
            else:
                print(f"import: triage_scan.py -> {out}")
                stdout, stderr = run_script(triage, project, program, [f"@{out}"])
                if stderr and stderr.strip():
                    (ws / "logs" / f"{name}.triage.stderr.log").write_text(stderr, encoding="utf-8")
                if out.is_file():
                    print(f"import: triage report written: {out}")
                else:
                    print("import: WARNING: triage report missing", file=sys.stderr)
                    return 1

            # A project imported by another tool (for example the reverse-ghidra
            # plugin) can be read-only for this process; the triage report is
            # already on disk, so a refused save is not a failure.
            try:
                program.save("ghidra-reverse import", None)
            except Exception as exc:  # noqa: BLE001
                print(f"import: note: project not saved ({exc})")
    finally:
        project.close()

    print(f"import: done (project {name})")
    return 0


@contextlib.contextmanager
def _open_program(pyghidra, project, binary: Path, create: bool = False):
    """Yield the program for `binary` in `project`, importing it when needed."""
    from java.io import File  # noqa: N813 - JPype Java class

    found: list[str] = []
    pyghidra.walk_programs(project, lambda domain_file, _program: found.append(domain_file.getPathname()))
    match = next((p for p in found if p.rsplit("/", 1)[-1] == binary.name), None)

    if match is not None:
        program, consumer = pyghidra.consume_program(project, match)
        try:
            yield program
        finally:
            if consumer is not None:
                program.release(consumer)
        return

    if not create:
        raise SystemExit(f"{binary.name} is not in the project")

    print(f"import: loading {binary.name}")
    loader = (pyghidra.program_loader()
              .source(File(str(binary)))
              .project(project)
              .name(binary.name))
    results = loader.load()
    try:
        # program_loader().load() returns LoadResults, not a Program.
        yield results.getPrimaryDomainObject()
    finally:
        results.close()


# ----------------------------------------------------------------------------- exec


def cmd_exec(args: argparse.Namespace) -> int:
    import pyghidra

    binary = Path(args.binary).resolve()
    script = Path(args.script)
    if not script.is_absolute():
        for candidate in (script_dir() / script.name, Path.cwd() / script.name):
            if candidate.is_file():
                script = candidate
                break
    if not script.is_file():
        raise SystemExit(f"script not found: {args.script}")

    ws = workspace()
    name = project_name_for(binary)
    project_path = project_root()
    gpr = project_path / f"{name}.gpr"
    if not gpr.exists():
        raise SystemExit(f"project '{name}' not found - run: {Path(__file__).name} import {binary}")

    outer = project_path / f"{name}.exec.log"
    print(f"exec: project={name} script={script.name}")

    # PyGhidra writes changes back when the project is saved on close; a read-only
    # pass simply skips the explicit save below.
    with pyghidra.open_project(str(project_path), name, create=False) as project:
        with _open_program(pyghidra, project, binary, create=False) as program:
            stdout, stderr = run_script(script, project, program, args.script_args)
            outer.write_text((stdout or "") + "\n--- stderr ---\n" + (stderr or ""), encoding="utf-8")
            if args.write:
                program.save("ghidra-reverse script", None)
                print("exec: project saved")
    print(f"exec: done (log {outer})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    import pyghidra

    binary = Path(args.binary).resolve()
    ws = workspace()
    name = project_name_for(binary)
    with pyghidra.open_project(str(project_root()), name, create=False) as project:
        for program in pyghidra.walk_programs(project):
            print(f"  {program.getDomainFile().getPathname()}  ({program.getLanguageID()})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ghidra-reverse driver", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose JVM output")
    sub = parser.add_subparsers(dest="command", required=True)

    p_import = sub.add_parser("import", help="import + analyze + triage")
    p_import.add_argument("binary")
    p_import.add_argument("--force", action="store_true")
    p_import.set_defaults(func=cmd_import)

    for cmd, write in (("exec", False), ("exec-w", True)):
        p = sub.add_parser(cmd, help="run a script against the project")
        p.add_argument("binary")
        p.add_argument("script")
        p.add_argument("script_args", nargs=argparse.REMAINDER)
        p.set_defaults(func=cmd_exec, write=write)

    p_list = sub.add_parser("list", help="list programs in the project")
    p_list.add_argument("binary")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)
    install = _configure_environment()

    # The JVM must be up before any ghidra.* import; every pyghidra API call
    # below assumes a started launcher.
    import pyghidra

    if not pyghidra.started():
        pyghidra.start(verbose=args.verbose, install_dir=install)

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
