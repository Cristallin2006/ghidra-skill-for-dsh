# Ghidra script to get imported and exported symbols
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

        # Get arguments
        args = _DSH_ARGS
        symbol_type = args[0] if args else "all"

        symbol_table = program.getSymbolTable()
        fm = program.getFunctionManager()

        result = {
            "status": "success",
            "type": symbol_type
        }

        # Get imports
        if symbol_type in ["imports", "all"]:
            imports = []

            # Get external functions
            for func in fm.getExternalFunctions():
                ext_loc = func.getExternalLocation()
                import_info = {
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "is_function": True
                }
                if ext_loc:
                    lib = ext_loc.getLibraryName()
                    if lib:
                        import_info["library"] = lib
                    orig_name = ext_loc.getOriginalImportedName()
                    if orig_name:
                        import_info["original_name"] = orig_name
                imports.append(import_info)

            # Also check for imported symbols from symbol table
            external_manager = program.getExternalManager()
            for lib_name in external_manager.getExternalLibraryNames():
                # Use getExternalLocations(libraryName) on the manager, not the library
                ext_loc_iter = external_manager.getExternalLocations(lib_name)
                if ext_loc_iter:
                    while ext_loc_iter.hasNext():
                        ext_loc = ext_loc_iter.next()
                        # Skip if already captured as function
                        existing = [i for i in imports if i.get("name") == ext_loc.getLabel()]
                        if not existing:
                            import_info = {
                                "name": ext_loc.getLabel(),
                                "library": lib_name,
                                "is_function": ext_loc.isFunction()
                            }
                            addr = ext_loc.getAddress()
                            if addr:
                                import_info["address"] = str(addr)
                            imports.append(import_info)

            result["imports"] = imports
            result["import_count"] = len(imports)

        # Get exports
        if symbol_type in ["exports", "all"]:
            exports = []

            # Check entry points and exported symbols
            for symbol in symbol_table.getAllSymbols(True):
                # Check if it's an entry point or exported
                if symbol.isExternalEntryPoint() or symbol.getSource().toString() == "IMPORTED":
                    continue

                # Check for export flag or entry point
                addr = symbol.getAddress()
                if addr.isExternalAddress():
                    continue

                # Get function if this is a function entry
                func = fm.getFunctionAt(addr)
                if func and func.isExternal():
                    continue

                # Check if marked as entry point
                is_entry = program.getSymbolTable().isExternalEntryPoint(addr)

                if is_entry or symbol.getName() in ["main", "_start", "entry", "DllMain", "WinMain"]:
                    export_info = {
                        "name": symbol.getName(),
                        "address": str(addr),
                        "is_function": func is not None,
                        "is_entry_point": is_entry
                    }
                    if func:
                        export_info["signature"] = str(func.getSignature())
                    exports.append(export_info)

            # Also get symbols marked as global
            for symbol in symbol_table.getAllSymbols(True):
                if symbol.isGlobal() and not symbol.isExternal():
                    addr = symbol.getAddress()
                    if addr.isExternalAddress():
                        continue
                    # Check if already added
                    existing = [e for e in exports if e.get("address") == str(addr)]
                    if existing:
                        continue
                    func = fm.getFunctionAt(addr)
                    if func and not func.isExternal():
                        export_info = {
                            "name": symbol.getName(),
                            "address": str(addr),
                            "is_function": True,
                            "is_global": True,
                            "signature": str(func.getSignature())
                        }
                        exports.append(export_info)

            result["exports"] = exports
            result["export_count"] = len(exports)

        # Get entry points specifically
        entry_points = []
        for addr in symbol_table.getExternalEntryPointIterator():
            symbol = symbol_table.getPrimarySymbol(addr)
            func = fm.getFunctionAt(addr)
            entry_info = {
                "address": str(addr),
                "name": symbol.getName() if symbol else "unknown",
                "is_function": func is not None
            }
            if func:
                entry_info["signature"] = str(func.getSignature())
            entry_points.append(entry_info)

        result["entry_points"] = entry_points
        result["entry_point_count"] = len(entry_points)

        output_json(result)

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Run the script
run()
