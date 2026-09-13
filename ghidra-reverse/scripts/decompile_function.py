# Ghidra script to decompile a function to C pseudocode
# @category DSH.Reverse
# @runtime PyGhidra

# --- DSH @out support (self-contained, no cross-script imports) ---
# If the first script argument starts with '@', it is popped and treated as an
# output file path: the full JSON payload is written there, and stdout only
# carries a short status summary between the markers.
_DSH_OUT_PATH = None

def _dsh_extract_out():
    global _DSH_OUT_PATH
    try:
        args = list(getScriptArgs())
    except NameError:
        return []
    if args and str(args[0]).startswith("@"):
        _DSH_OUT_PATH = str(args[0])[1:]
        args = args[1:]
    return args

_DSH_ARGS = _dsh_extract_out()
# --- end DSH @out support ---


import json
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

def output_json(data):
    """Write full JSON to the @out file if given, else print between markers."""
    if _DSH_OUT_PATH:
        try:
            f = open(_DSH_OUT_PATH, "w")
            try:
                f.write(json.dumps(data))
            finally:
                f.close()
            count = 0
            for key in ("strings", "functions", "instructions", "results",
                        "imports", "symbols", "xrefs", "blocks", "classes",
                        "basic_blocks", "c_code", "bytes"):
                if key in data and data[key] is not None:
                    v = data[key]
                    try:
                        count = len(v)
                    except TypeError:
                        count = 1
                    break
            if "string_count" in data:
                count = data["string_count"]
            elif "function_count" in data:
                count = data["function_count"]
            elif "instruction_count" in data:
                count = data["instruction_count"]
            summary = {
                "status": data.get("status", "success"),
                "out": _DSH_OUT_PATH,
                "count": count
            }
            if data.get("status") == "error":
                summary["error"] = data.get("error")
            print("===JSON_START===")
            print(json.dumps(summary))
            print("===JSON_END===")
        except Exception as write_err:
            print("===JSON_START===")
            print(json.dumps({"status": "error",
                              "error": "failed to write out file: " + str(write_err)}))
            print("===JSON_END===")
    else:
        print("===JSON_START===")
        print(json.dumps(data))
        print("===JSON_END===")

def find_function(program, identifier):
    """
    Find a function by name or address.

    Args:
        program: The Ghidra program
        identifier: Function name or address string (0x...)

    Returns:
        Function object or None
    """
    fm = program.getFunctionManager()

    # Try as address first
    if identifier.startswith("0x") or identifier.startswith("0X"):
        try:
            addr = toAddr(identifier)
            func = fm.getFunctionAt(addr)
            if func:
                return func
            # Try containing function
            func = fm.getFunctionContaining(addr)
            if func:
                return func
        except:
            pass

    # Try as function name
    for func in fm.getFunctions(True):
        if func.getName() == identifier:
            return func

    # Try partial match
    for func in fm.getFunctions(True):
        if identifier.lower() in func.getName().lower():
            return func

    return None

def run():
    """Main script entry point."""
    try:
        program = currentProgram
        if program is None:
            output_json({
                "status": "error",
                "error": "No program loaded"
            })
            return

        # Get function identifier from script args
        args = _DSH_ARGS
        if not args:
            output_json({
                "status": "error",
                "error": "No function specified. Provide function name or address."
            })
            return

        func_identifier = args[0]

        # Find the function
        func = find_function(program, func_identifier)
        if func is None:
            output_json({
                "status": "error",
                "error": "Function not found: " + func_identifier
            })
            return

        # Initialize decompiler
        decompiler = DecompInterface()
        options = DecompileOptions()
        decompiler.setOptions(options)

        if not decompiler.openProgram(program):
            output_json({
                "status": "error",
                "error": "Failed to initialize decompiler"
            })
            return

        try:
            # Decompile the function
            monitor = ConsoleTaskMonitor()
            results = decompiler.decompileFunction(func, 60, monitor)

            if not results.decompileCompleted():
                output_json({
                    "status": "error",
                    "error": "Decompilation failed: " + str(results.getErrorMessage())
                })
                return

            decomp_func = results.getDecompiledFunction()
            c_code = decomp_func.getC() if decomp_func else None

            if not c_code:
                output_json({
                    "status": "error",
                    "error": "No decompiled code produced"
                })
                return

            # Collect local variables
            local_vars = []
            high_func = results.getHighFunction()
            if high_func:
                local_symbols = high_func.getLocalSymbolMap()
                if local_symbols:
                    for symbol in local_symbols.getSymbols():
                        var_info = {
                            "name": symbol.getName(),
                            "type": str(symbol.getDataType()),
                            "size": symbol.getSize()
                        }
                        storage = symbol.getStorage()
                        if storage:
                            var_info["storage"] = str(storage)
                        local_vars.append(var_info)

            output_json({
                "status": "success",
                "function_name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "c_code": c_code,
                "local_variables": local_vars
            })

        finally:
            decompiler.dispose()

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Run the script
run()
