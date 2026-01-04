# arael_extract.py - Ghidra headless script for Arael
# Usage: analyzeHeadless ... -postScript arael_extract.py /path/to/output.json
#
# This script extracts all analysis data from the current Ghidra program
# and writes it as JSON to the specified output file.

import json
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def extract_all():
    """Extract all analysis data from current program."""

    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    # Get entry point
    entry_symbol = None
    try:
        for sym in currentProgram.getSymbolTable().getSymbols("entry"):
            entry_symbol = sym
            break
    except Exception:
        entry_symbol = None
    entry_point = str(entry_symbol.getAddress()) if entry_symbol else str(currentProgram.getMinAddress())

    result = {
        "version": "1.0.0",
        "metadata": {
            "analysisId": str(java.util.UUID.randomUUID()),
            "timestamp": str(java.time.Instant.now()),
            "araelVersion": "1.0.0",
            "ghidraVersion": str(getGhidraVersion()),
            "analysisDurationMs": 0,
            "connectionMode": "headless",
            "cached": False
        },
        "binary": {
            "filename": currentProgram.getName(),
            "filepath": currentProgram.getExecutablePath(),
            "size": 0,  # Would need file access
            "hashes": {
                "md5": str(currentProgram.getExecutableMD5()),
                "sha1": "",
                "sha256": str(currentProgram.getExecutableSHA256())
            },
            "format": currentProgram.getExecutableFormat(),
            "architecture": str(currentProgram.getLanguage().getProcessor()),
            "endianness": "little" if currentProgram.getLanguage().isBigEndian() == False else "big",
            "entryPoint": entry_point,
            "imageBase": str(currentProgram.getImageBase())
        },
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": []
    }

    # Extract functions
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        func_data = {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "signature": str(func.getSignature()),
            "isThunk": func.isThunk(),
            "isExternal": func.isExternal(),
            "callers": [],
            "callees": [],
            "pseudocode": None
        }

        # Get callers
        for ref in getReferencesTo(func.getEntryPoint()):
            if ref.getReferenceType().isCall():
                func_data["callers"].append(str(ref.getFromAddress()))

        # Get callees
        for called in func.getCalledFunctions(monitor):
            func_data["callees"].append(called.getName())

        # Decompile (with timeout)
        try:
            decomp_result = decomp.decompileFunction(func, 30, monitor)
            if decomp_result.decompileCompleted():
                decomp_func = decomp_result.getDecompiledFunction()
                if decomp_func:
                    func_data["pseudocode"] = decomp_func.getC()
            else:
                func_data["decompileError"] = decomp_result.getErrorMessage()
        except Exception as e:
            func_data["decompileError"] = str(e)

        result["functions"].append(func_data)

    # Extract strings
    for string in currentProgram.getListing().getDefinedStrings():
        string_data = {
            "address": str(string.getAddress()),
            "value": string.getValue(),
            "length": string.getLength(),
            "encoding": "ascii",
            "xrefs": []
        }

        # Get xrefs to this string
        for ref in getReferencesTo(string.getAddress()):
            ref_func = getFunctionContaining(ref.getFromAddress())
            string_data["xrefs"].append({
                "address": str(ref.getFromAddress()),
                "function": ref_func.getName() if ref_func else "unknown",
                "type": "data"
            })

        result["strings"].append(string_data)

    # Extract imports
    st = currentProgram.getSymbolTable()
    for symbol in st.getExternalSymbols():
        result["imports"].append({
            "name": symbol.getName(),
            "library": str(symbol.getParentNamespace()),
            "address": str(symbol.getAddress()),
            "type": "function"
        })

    # Extract exports
    for symbol in st.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            result["exports"].append({
                "name": symbol.getName(),
                "address": str(symbol.getAddress())
            })

    return result


def getGhidraVersion():
    """Get Ghidra version string."""
    try:
        from ghidra import GhidraVersion
        return GhidraVersion.getApplicationVersion()
    except:
        return "unknown"


if __name__ == "__main__":
    import java.util
    import java.time

    output_path = getScriptArgs()[0] if len(getScriptArgs()) > 0 else "/tmp/arael_output.json"

    try:
        print("[Arael] Starting extraction...")
        data = extract_all()

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print("[Arael] Extraction complete: " + output_path)
    except Exception as e:
        error_data = {"error": str(e)}
        with open(output_path, 'w') as f:
            json.dump(error_data, f)
        print("[Arael] Extraction failed: " + str(e))
        import traceback
        traceback.print_exc()
