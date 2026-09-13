#!/usr/bin/env bash
# run-headless.sh - Git Bash wrapper around Ghidra analyzeHeadless for the
# dsh ghidra-reverse skill.
#
# Subcommands:
#   import <binary> [--force]   Import + full auto-analysis + triage_scan.py
#   exec   <binary> <script> [args...]   Run a script read-only (-readOnly)
#   exec-w <binary> <script> [args...]   Run a script with changes saved
#
# Script args: if the first script arg starts with '@', it is the output file
# path for the JSON payload (use an ABSOLUTE path, e.g.
#   "@$HOME/.dsh/ghidra-workspace/out/foo.json"
# or "@C:/Users/you/out/foo.json").
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-C:/t001s/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC}"
HEADLESS="$GHIDRA_HOME/support/analyzeHeadless.bat"
WS="${DSH_GHIDRA_WS:-$HOME/.dsh/ghidra-workspace}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "run-headless: ERROR: $*" >&2; exit 1; }

[ -f "$HEADLESS" ] || die "analyzeHeadless.bat not found at $HEADLESS (set GHIDRA_HOME to your Ghidra install dir)"

mkdir -p "$WS/projects" "$WS/out" "$WS/logs"

# Ghidra's ProjectLocator rejects any path element starting with '.' (the real
# workspace lives under ~/.dsh), so expose it to the JVM through a junction
# whose path contains no dot elements. Files physically stay in $WS.
WS_LINK="${DSH_GHIDRA_WS_LINK:-$HOME/dsh-ghidra-workspace}"
if [ ! -d "$WS_LINK/projects" ]; then
    rm -f "$WS_LINK" 2>/dev/null || true
    powershell -NoProfile -Command \
        "New-Item -ItemType Junction -Path '$(cygpath -w "$WS_LINK")' -Target '$(cygpath -w "$WS")' | Out-Null" \
        || die "failed to create junction $WS_LINK -> $WS"
    [ -d "$WS_LINK/projects" ] || die "junction $WS_LINK does not resolve to $WS"
fi

# Windows-form paths for the JVM / .bat (MSYS auto-conversion is unreliable
# for args like '@/c/...', so convert explicitly).
WS_WIN="$(cygpath -w "$WS_LINK")"
SCRIPTS_WIN="$(cygpath -w "$SCRIPT_DIR")"

# Convert one script arg: '@<posix-abs-path>' -> '@<windows-path>'
convert_arg() {
    local a="$1"
    case "$a" in
        @/*) printf '@%s' "$(cygpath -w "${a#@}")" ;;
        *)   printf '%s' "$a" ;;
    esac
}

project_name_for() {
    local bin_posix
    bin_posix="$(cygpath "$1")"
    [ -f "$bin_posix" ] || die "binary not found: $1"
    printf 'dsh_%s' "$(sha256sum "$bin_posix" | cut -c1-16)"
}

run_headless() {
    # run_headless <logfile-posix> <args...>
    local log_posix="$1"; shift
    local log_win; log_win="$(cygpath -w "$log_posix")"
    local start=$SECONDS
    echo "run-headless: launching analyzeHeadless (log: $log_posix)"
    set +e
    "$GHIDRA_HOME/support/analyzeHeadless.bat" "$@" -log "$log_win" 2>&1 \
        | grep -v -e '^Picked up ' || true
    local rc=${PIPESTATUS[0]}
    set -e
    local elapsed=$((SECONDS - start))
    echo "run-headless: analyzeHeadless exit=$rc elapsed=${elapsed}s"
    return "$rc"
}

cmd_import() {
    local binary="${1:?usage: run-headless.sh import <binary> [--force]}"
    local force="${2:-}"
    local proj; proj="$(project_name_for "$binary")"
    local bin_win; bin_win="$(cygpath -w "$binary")"
    local base; base="$(basename "$binary")"
    local gpr="$WS/projects/$proj.gpr"
    local triage_out="$WS/out/$base.triage.json"

    if [ -f "$gpr" ] && [ "$force" != "--force" ]; then
        echo "run-headless: project '$proj' already exists, skipping import (use --force to re-import)"
        [ -f "$triage_out" ] && echo "run-headless: existing triage report: $triage_out"
        return 0
    fi

    if [ "$force" = "--force" ]; then
        rm -rf "$gpr" "$WS/projects/$proj.rep" "$WS/projects/$proj.lock" 2>/dev/null || true
    fi

    run_headless "$WS/logs/$proj.import.log" \
        "$WS_WIN\\projects" "$proj" \
        -import "$bin_win" \
        -analysisTimeoutPerFile 600 \
        -max-cpu 4 \
        -scriptPath "$SCRIPTS_WIN" \
        -postScript triage_scan.py "@$(cygpath -w "$triage_out")"

    if [ -f "$triage_out" ]; then
        echo "run-headless: triage report written: $triage_out"
    else
        echo "run-headless: WARNING: triage output missing, check $WS/logs/$proj.import.log" >&2
        return 1
    fi
}

cmd_exec() {
    local readonly_flag="$1"; shift
    local binary="${1:?usage: run-headless.sh exec|exec-w <binary> <script> [args...]}"
    local script="${2:?usage: run-headless.sh exec|exec-w <binary> <script> [args...]}"
    shift 2
    local proj; proj="$(project_name_for "$binary")"
    local progname; progname="$(basename "$binary")"
    local gpr="$WS/projects/$proj.gpr"
    [ -f "$gpr" ] || die "project '$proj' not found - run: run-headless.sh import $binary first"

    local args=()
    local a
    for a in "$@"; do
        args+=("$(convert_arg "$a")")
    done

    local extra=()
    if [ "$readonly_flag" = "ro" ]; then
        extra+=("-readOnly")
    fi

    run_headless "$WS/logs/$proj.$(basename "$script" .py).log" \
        "$WS_WIN\\projects" "$proj" \
        -process "$progname" \
        -noanalysis \
        "${extra[@]}" \
        -scriptPath "$SCRIPTS_WIN" \
        -postScript "$script" ${args[@]+"${args[@]}"}

    # Surface the JSON markers from the log for convenience
    grep -A2 '===JSON_START===' "$WS/logs/$proj.$(basename "$script" .py).log" 2>/dev/null | tail -5 || true
}

main() {
    local sub="${1:-}"
    case "$sub" in
        import) shift; cmd_import "$@" ;;
        exec)   shift; cmd_exec ro "$@" ;;
        exec-w) shift; cmd_exec rw "$@" ;;
        *) cat >&2 <<'EOF'
usage: run-headless.sh <subcommand> ...

  import <binary> [--force]                import + analyze + triage_scan.py
  exec   <binary> <script.py> [args...]    run script read-only
  exec-w <binary> <script.py> [args...]    run script, save changes on exit

env: GHIDRA_HOME (default C:/t001s/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC)
     DSH_GHIDRA_WS (default ~/.dsh/ghidra-workspace)
EOF
           exit 2 ;;
    esac
}

main "$@"
