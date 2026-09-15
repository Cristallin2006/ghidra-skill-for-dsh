"""dsh custom tools for the ghidra-reverse skill (dsh-patch: additive module).

Ports the skill's four unique capabilities into the daemon:
  - exec_code        — open Ghidra-API escape hatch (unsandboxed exec, by design)
  - triage           — one-shot triage report (ported from triage_scan.py)
  - export_binary    — Original File export with md5 comparison
  - emulate_function — EmulatorHelper P-code emulation

Handlers follow the same contract as upstream tools: (ctx, args) -> dict,
raise on error.
"""

from __future__ import annotations

import json
import re

from ghidra_rpc.server.main import register_handler
from ghidra_rpc.server.tools.modifications import _maybe_swing, ghidra_transaction


# ── shared helpers ────────────────────────────────────────────────────────────

def _to_addr(program, text):
    return program.getAddressFactory().getAddress(str(text))


def _find_function(program, identifier):
    """Three-level lookup: 0x address -> exact name -> name substring."""
    fm = program.getFunctionManager()
    ident = str(identifier)
    if ident.lower().startswith("0x"):
        try:
            addr = _to_addr(program, ident)
            func = fm.getFunctionAt(addr)
            if func:
                return func
            func = fm.getFunctionContaining(addr)
            if func:
                return func
        except Exception:
            pass
    for func in fm.getFunctions(True):
        if func.getName() == ident:
            return func
    for func in fm.getFunctions(True):
        if ident.lower() in func.getName().lower():
            return func
    return None


# ── exec_code ─────────────────────────────────────────────────────────────────

def _handle_exec_code(ctx, args: dict) -> dict:
    """Execute a Python 3 code file inside the daemon with full Ghidra API.

    args: binary, code_file
    The code file runs with these names predefined:
      program, currentProgram, fm, listing, memory, toAddr, monitor,
      find_function(name_or_addr), output_json(data)

    The LAST output_json(...) payload becomes the result; if the code never
    calls output_json, a default success note is returned.

    UNSANDBOXED by design: the code can do anything the JVM can.
    """
    import traceback

    binary = args.get("binary", "")
    code_file = args.get("code_file", "")
    if not code_file:
        raise ValueError("Missing required argument: code_file")

    pi = ctx.get_program(binary)
    program = pi.program

    try:
        with open(code_file, "r", encoding="utf-8") as fh:
            src = fh.read()
    except OSError as e:
        raise ValueError(f"cannot read code file {code_file}: {e}")

    outputs = []

    def output_json(data):
        outputs.append(data)

    def run_code():
        from ghidra.util.task import ConsoleTaskMonitor

        namespace = {
            "__builtins__": __builtins__,
            "program": program,
            "currentProgram": program,
            "fm": program.getFunctionManager(),
            "listing": program.getListing(),
            "memory": program.getMemory(),
            "toAddr": lambda s: _to_addr(program, s),
            "monitor": ConsoleTaskMonitor(),
            "find_function": lambda ident: _find_function(program, ident),
            "output_json": output_json,
        }
        exec(compile(src, code_file, "exec"), namespace)

    try:
        _maybe_swing(ctx, run_code)
    except Exception as e:
        return {"status": "error", "error": str(e),
                "traceback": traceback.format_exc()}

    # A code file may also WRITE to the program; persist like other write ops.
    ctx.save_program(pi)

    if outputs:
        result = outputs[-1]
        if isinstance(result, dict):
            result.setdefault("output_count", len(outputs))
            return result
        return {"status": "success", "value": result,
                "output_count": len(outputs)}
    return {"status": "success", "note": "no explicit output"}


# ── triage ────────────────────────────────────────────────────────────────────

_MAX_STRINGS = 20000
_MAX_QUICK_STRINGS = 50

_SUSPICIOUS = {
    "anti_debug": [
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "ntsetinformationthread",
        "outputdebugstringa", "outputdebugstringw",
        "gettickcount", "queryperformancecounter", "rdtsc"
    ],
    "injection": [
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "openprocess", "ntmapviewofsection", "queueuserapc",
        "setwindowshookex"
    ],
    "crypto": [
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext",
        "bcryptencrypt", "aes"
    ],
    "network": [
        "internetopen", "internetconnect", "httpsendrequest",
        "winhttpopen", "urldownloadtofile", "socket", "connect",
        "send", "recv", "wsastartup"
    ],
    "persistence": [
        "regsetvalue", "regcreatekey", "createservice", "startservice",
        "schtasks"
    ],
    "dynamic_loading": [
        "loadlibrarya", "loadlibraryw", "getprocaddress", "ldrloaddll"
    ]
}

_VARIANT_SUFFIXES = ("", "a", "w", "ex", "exa", "exw")

_QUICK_STRING_RE = re.compile(
    r"flag|passw|correct|wrong|usage|key|congrat|success|fail", re.IGNORECASE)


def _matches_family(import_name, base):
    name = import_name.lower()
    if not name.startswith(base):
        return False
    return name[len(base):] in _VARIANT_SUFFIXES


def _handle_triage(ctx, args: dict) -> dict:
    """One-shot triage report; output shape matches the skill's triage.json."""
    binary = args.get("binary", "")
    pi = ctx.get_program(binary)

    def do_triage():
        program = pi.program
        result = {"status": "success"}

        # --- meta ---
        meta = {
            "program_name": program.getName(),
            "language": str(program.getLanguage().getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": str(program.getImageBase()),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress()),
            "executable_path": program.getExecutablePath(),
            "executable_format": program.getExecutableFormat(),
            "function_count": program.getFunctionManager().getFunctionCount(),
            "memory_blocks": []
        }
        try:
            md5 = program.getExecutableMD5()
            meta["md5"] = md5 if md5 else None
        except Exception:
            meta["md5"] = None

        mem = program.getMemory()
        block_names = []
        for block in mem.getBlocks():
            meta["memory_blocks"].append({
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "permissions": ("%s%s%s" % (
                    "r" if block.isRead() else "-",
                    "w" if block.isWrite() else "-",
                    "x" if block.isExecute() else "-"))
            })
            block_names.append(block.getName())
        result["meta"] = meta

        # --- imports / exports / entry points ---
        imports = {}
        st = program.getSymbolTable()
        sym_iter = st.getExternalSymbols()
        while sym_iter.hasNext():
            sym = sym_iter.next()
            parent = sym.getParentNamespace()
            lib = parent.getName() if parent is not None else "<unknown>"
            imports.setdefault(lib, [])
            name = sym.getName()
            if name not in imports[lib]:
                imports[lib].append(name)
        for lib in imports:
            imports[lib].sort()
        result["imports"] = imports

        exports = []
        entries = []
        entry_iter = st.getExternalEntryPointIterator()
        while entry_iter.hasNext():
            addr = entry_iter.next()
            sym = st.getPrimarySymbol(addr)
            name = sym.getName() if sym is not None else str(addr)
            rec = {"name": name, "address": str(addr)}
            if name in ("entry", "main", "_start", "WinMain", "DllMain",
                        "wWinMain", "mainCRTStartup", "wWinMainCRTStartup"):
                rec["type"] = "entry_point"
                entries.append(rec)
            else:
                rec["type"] = "export"
                exports.append(rec)
        result["exports"] = exports
        result["entry_points"] = entries
        result["exports_note"] = (
            "exports/entry_points are split from Ghidra's external-entry-point "
            "set by well-known entry names (entry/main/_start/WinMain/...); "
            "a stripped binary may classify its real entry as an export")

        # --- suspicious imports ---
        all_import_names = [(lib, name) for lib in imports for name in imports[lib]]
        suspicious = {}
        for category, bases in _SUSPICIOUS.items():
            hits = []
            for lib, name in all_import_names:
                for base in bases:
                    if _matches_family(name, base):
                        hits.append({"library": lib, "name": name})
                        break
            if hits:
                suspicious[category] = hits
        result["suspicious_imports"] = suspicious

        total_imports = len(all_import_names)
        clean_libs = all(lib.lower().startswith(("kernel32", "ntdll"))
                         for lib in imports)
        result["clean_iat_warning"] = bool(clean_libs and total_imports < 15)

        # --- strings (single pass serves quick_strings and lang hints) ---
        listing = program.getListing()
        quick = []
        total_strings = 0
        scanned = 0
        go_re = re.compile(r"go\.buildid|runtime\.gopanic")
        rust_re = re.compile(r"panicked at|\.rustc")
        py_re = re.compile(r"PYINSTALLER|pyarmor|python3", re.IGNORECASE)
        hints = {"go": False, "rust": False, "python": False}

        for data in listing.getDefinedData(True):
            scanned += 1
            if scanned > _MAX_STRINGS:
                break
            try:
                if not data.hasStringValue():
                    continue
                value = str(data.getValue())
            except Exception:
                continue
            total_strings += 1
            if not value:
                continue
            if len(quick) < _MAX_QUICK_STRINGS and _QUICK_STRING_RE.search(value):
                quick.append({"address": str(data.getAddress()), "value": value})
            if not hints["go"] and go_re.search(value):
                hints["go"] = True
            if not hints["rust"] and rust_re.search(value):
                hints["rust"] = True
            if not hints["python"] and py_re.search(value):
                hints["python"] = True

        result["quick_strings"] = {
            "total_strings_scanned": scanned,
            "total_defined_strings": total_strings,
            "scan_capped": scanned > _MAX_STRINGS,
            "matches": quick
        }

        dotnet = any(lib.lower().startswith("mscoree") for lib in imports)
        if not dotnet:
            dotnet = any(name == "_CorExeMain" for _, name in all_import_names)
        upx = any("UPX" in bname.upper() for bname in block_names)

        result["lang_hints"] = {
            "go": hints["go"], "rust": hints["rust"], "dotnet": dotnet,
            "python": hints["python"], "upx": upx
        }

        # --- PE extras (best effort) ---
        exe_format = program.getExecutableFormat() or ""
        if "Portable Executable" in exe_format or exe_format.upper().endswith("(PE)"):
            pe_extras = {}
            tls_section = next(
                (b for b in block_names
                 if b.lower() == ".tls" or b.lower().startswith(".tls$")), None)
            if tls_section is not None:
                pe_extras["tls_section"] = tls_section
                block = mem.getBlock(tls_section)
                if block is not None and block.getSize() > 0:
                    pe_extras["tls_section_size"] = block.getSize()
            if pe_extras:
                result["pe_extras"] = pe_extras

        return result

    return _maybe_swing(ctx, do_triage)


# ── export_binary ─────────────────────────────────────────────────────────────

def _handle_export_binary(ctx, args: dict) -> dict:
    """Export the program back to its original file format.

    args: binary, path
    """
    import hashlib
    import os

    binary = args.get("binary", "")
    export_path = args.get("path", "")
    if not export_path:
        raise ValueError("Missing required argument: path")

    pi = ctx.get_program(binary)

    def do_export():
        from java.io import File
        from ghidra.app.util.exporter import OriginalFileExporter
        from ghidra.util.task import ConsoleTaskMonitor

        program = pi.program
        exporter = OriginalFileExporter()
        if not exporter.canExportDomainObject(program):
            raise ValueError(
                "OriginalFileExporter cannot export this program "
                "(no original file bytes)")

        monitor = ConsoleTaskMonitor()
        ok = exporter.export(File(export_path), program, None, monitor)
        if not ok or not os.path.isfile(export_path):
            raise ValueError(
                f"export() returned {ok}; monitor: {monitor.getMessage()}")

        with open(export_path, "rb") as fh:
            blob = fh.read()

        try:
            original_md5 = program.getExecutableMD5()
        except Exception:
            original_md5 = None

        return {
            "status": "success",
            "export_path": os.path.abspath(export_path),
            "size": len(blob),
            "md5": hashlib.md5(blob).hexdigest(),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "original_md5": original_md5,
            "original_path": program.getExecutablePath(),
            "matches_original_md5": (original_md5 is not None
                                     and hashlib.md5(blob).hexdigest() == original_md5)
        }

    return _maybe_swing(ctx, do_export)


# ── emulate_function ─────────────────────────────────────────────────────────

def _handle_emulate_function(ctx, args: dict) -> dict:
    """Emulate a function with EmulatorHelper (P-code).

    args: binary, function, registers (dict), memory (dict), max_steps (int)
    Ported from the skill's emulate_function.py, including call-depth tracking
    (calls are followed into callees; only leaving the body at depth 0 counts
    as a return) and skipped_inputs reporting.
    """
    binary = args.get("binary", "")
    func_ident = args.get("function", "")
    register_inputs = args.get("registers") or {}
    memory_inputs = args.get("memory") or {}
    max_steps = int(args.get("max_steps", 10000))

    if not func_ident:
        raise ValueError("Missing required argument: function")

    pi = ctx.get_program(binary)

    def do_emulate():
        from ghidra.app.emulator import EmulatorHelper
        from ghidra.util.task import ConsoleTaskMonitor

        program = pi.program
        func = _find_function(program, func_ident)
        if func is None:
            raise ValueError(f"Function not found: {func_ident}")

        emulator = EmulatorHelper(program)
        monitor = ConsoleTaskMonitor()

        try:
            entry_point = func.getEntryPoint()

            skipped_inputs = []
            for reg_name, value in register_inputs.items():
                try:
                    reg = emulator.getLanguage().getRegister(reg_name)
                    if reg is None:
                        raise ValueError("unknown register: " + str(reg_name))
                    if isinstance(value, str):
                        value = (int(value, 16) if value.lower().startswith("0x")
                                 else int(value))
                    emulator.writeRegister(reg, value)
                except Exception as e:
                    skipped_inputs.append({
                        "kind": "register", "name": str(reg_name),
                        "value": value if isinstance(value, (int, str)) else str(value),
                        "reason": str(e)})

            for addr_str, data in memory_inputs.items():
                try:
                    addr = _to_addr(program, addr_str)
                    if addr is None:
                        raise ValueError("invalid address: " + str(addr_str))
                    if isinstance(data, list):
                        for i, byte_val in enumerate(data):
                            emulator.writeMemoryValue(addr.add(i), 1, byte_val & 0xff)
                    elif isinstance(data, str) and not data.startswith(("0x", "0X")):
                        for i, char in enumerate(data):
                            emulator.writeMemoryValue(addr.add(i), 1, ord(char))
                    else:
                        v = data
                        if isinstance(v, str):
                            v = (int(v, 16) if v.startswith(("0x", "0X")) else int(v))
                        emulator.writeMemoryValue(addr, 4, v)
                except Exception as e:
                    skipped_inputs.append({
                        "kind": "memory", "name": str(addr_str),
                        "value": data if isinstance(data, (int, str)) else str(data),
                        "reason": str(e)})

            emulator.writeRegister(emulator.getPCRegister(), entry_point.getOffset())

            execution_trace = []
            step_count = 0
            call_depth = 0
            stop_reason = "max_steps"

            while step_count < max_steps:
                current_addr = emulator.getExecutionAddress()
                if current_addr is None:
                    stop_reason = "no_execution_address"
                    break

                in_body = func.getBody().contains(current_addr)
                if not in_body and call_depth == 0:
                    stop_reason = "returned"
                    break

                inst = program.getListing().getInstructionAt(current_addr)
                if inst is None:
                    stop_reason = "no_instruction_at_pc"
                    break

                flow = inst.getFlowType()
                is_call = flow.isCall()

                trace_entry = {
                    "step": step_count,
                    "address": str(current_addr),
                    "instruction": inst.toString(),
                    "call_depth": call_depth
                }

                try:
                    success = emulator.step(monitor)
                    if not success:
                        trace_entry["error"] = "Execution failed"
                        execution_trace.append(trace_entry)
                        stop_reason = "execution_error"
                        break
                except Exception as e:
                    trace_entry["error"] = str(e)
                    execution_trace.append(trace_entry)
                    stop_reason = "execution_error"
                    break

                execution_trace.append(trace_entry)
                step_count += 1

                if is_call:
                    call_depth += 1
                elif flow.isTerminal():
                    if call_depth > 0:
                        call_depth -= 1
                    else:
                        stop_reason = "returned"
                        break

            register_states = {}
            lang = emulator.getLanguage()
            proc_name = lang.getProcessor().toString().lower()
            if proc_name.startswith("x86"):
                common_regs = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                               "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                               "RIP", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI",
                               "EBP", "ESP", "EIP"]
            elif proc_name.startswith("arm"):
                common_regs = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                               "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"]
            elif proc_name.startswith("mips"):
                common_regs = ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1",
                               "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1",
                               "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9",
                               "sp", "fp", "ra", "pc"]
            else:
                common_regs = [r.getName() for r in lang.getRegisters()
                               if not r.isProcessorContext()
                               and r.getMinimumByteSize() >= 4]

            for reg_name in common_regs:
                try:
                    reg = lang.getRegister(reg_name)
                    if reg is not None:
                        value = emulator.readRegister(reg)
                        register_states[reg_name] = "0x%x" % value
                except Exception:
                    pass

            return {
                "status": "success",
                "function_name": func.getName(),
                "entry_point": str(entry_point),
                "steps_executed": step_count,
                "max_steps_reached": step_count >= max_steps,
                "stop_reason": stop_reason,
                "call_depth_at_stop": call_depth,
                "skipped_inputs": skipped_inputs,
                "register_states": register_states,
                "execution_trace": execution_trace[:100],
                "trace_truncated": len(execution_trace) > 100
            }
        finally:
            emulator.dispose()

    return _maybe_swing(ctx, do_emulate)


register_handler("exec_code", _handle_exec_code)
register_handler("triage", _handle_triage)
register_handler("export_binary", _handle_export_binary)
register_handler("emulate_function", _handle_emulate_function)
