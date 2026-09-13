# Ghidra script to search for strings in a program
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
import re

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
        min_length = int(args[0]) if args else 4
        pattern = args[1] if len(args) > 1 else None
        pattern_regex = re.compile(pattern) if pattern else None

        # Collect strings from defined data
        listing = program.getListing()
        strings = []

        for data in listing.getDefinedData(True):
            if not data.hasStringValue():
                continue

            try:
                value = str(data.getValue())

                # Apply length filter
                if len(value) < min_length:
                    continue

                # Apply pattern filter
                if pattern_regex and not pattern_regex.search(value):
                    continue

                address = data.getAddress()

                # Get references to this string
                refs = []
                for ref in getReferencesTo(address):
                    from_addr = ref.getFromAddress()
                    # Get the function containing the reference
                    func = program.getFunctionManager().getFunctionContaining(from_addr)
                    ref_info = {
                        "from": str(from_addr),
                        "type": str(ref.getReferenceType())
                    }
                    if func:
                        ref_info["function"] = func.getName()
                    refs.append(ref_info)

                string_info = {
                    "address": str(address),
                    "value": value,
                    "length": len(value),
                    "type": str(data.getDataType()),
                    "references": refs
                }
                strings.append(string_info)

            except Exception as e:
                # Skip strings that can't be processed
                continue

        # Sort by address
        strings.sort(key=lambda x: x["address"])

        output_json({
            "status": "success",
            "string_count": len(strings),
            "min_length": min_length,
            "pattern": pattern,
            "strings": strings
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Run the script
run()
