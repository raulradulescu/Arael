#!/usr/bin/env python3
"""
PyGhidra wrapper for Arael analysis.
Works with Ghidra 12.0+ which requires PyGhidra for Python scripting.
"""

import sys
import os
import json
import tempfile


def main():
    if len(sys.argv) < 3:
        print("Usage: run_analysis.py <binary_path> <output_path>", file=sys.stderr)
        sys.exit(1)

    binary_path = os.path.abspath(sys.argv[1])
    output_path = sys.argv[2]
    ghidra_path = os.environ.get('GHIDRA_PATH', '')

    if not ghidra_path:
        print("GHIDRA_PATH environment variable not set", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    # Import pyghidra and start Ghidra
    import pyghidra
    pyghidra.start(install_dir=ghidra_path)

    # Now import Ghidra modules
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File

    # Create a temporary project
    project_dir = tempfile.mkdtemp(prefix='arael_')
    project_name = 'AraelAnalysis'

    try:
        # Open/create project and import binary
        with pyghidra.open_project(project_dir, project_name, create=True) as project:
            # Import the binary file
            binary_file = File(binary_path)

            # Use program loader to import and analyze
            loader = pyghidra.program_loader()
            loader = loader.source(binary_file)
            loader = loader.project(project)

            with loader.load() as load_results:
                # Get the primary loaded program
                loaded = load_results.getPrimary()
                program = loaded.getDomainObject()

                # Run analysis
                pyghidra.analyze(program)

                monitor = ConsoleTaskMonitor()
                result = extract_analysis(program, monitor)

                with open(output_path, 'w') as f:
                    json.dump(result, f, indent=2)

                print(f"Analysis written to: {output_path}")

    finally:
        # Clean up project directory
        import shutil
        try:
            shutil.rmtree(project_dir, ignore_errors=True)
        except:
            pass


def extract_analysis(program, monitor):
    """Extract all analysis data from the program."""
    from ghidra.app.decompiler import DecompInterface

    result = {
        'filename': program.getName(),
        'format': program.getExecutableFormat(),
        'architecture': str(program.getLanguage().getProcessor()),
        'addressSize': program.getAddressFactory().getDefaultAddressSpace().getSize(),
        'compiler': str(program.getCompiler()) if program.getCompiler() else None,
        'functions': [],
        'strings': [],
        'imports': [],
        'exports': [],
        'sections': []
    }

    # Extract functions with decompilation
    from ghidra.util.task import ConsoleTaskMonitor
    fm = program.getFunctionManager()
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    task_monitor = ConsoleTaskMonitor()

    for func in fm.getFunctions(True):
        func_info = {
            'name': func.getName(),
            'address': str(func.getEntryPoint()),
            'size': int(func.getBody().getNumAddresses()),
            'signature': str(func.getSignature()),
            'isThunk': func.isThunk(),
            'isExternal': func.isExternal(),
            'callers': [],
            'callees': [],
            'pseudocode': None
        }

        # Decompile non-external, non-thunk functions
        if not func.isExternal() and not func.isThunk():
            try:
                decomp_results = decompiler.decompileFunction(func, 30, task_monitor)
                if decomp_results and decomp_results.decompileCompleted():
                    decomp_func = decomp_results.getDecompiledFunction()
                    if decomp_func:
                        func_info['pseudocode'] = decomp_func.getC()
            except Exception as e:
                pass  # Skip decompilation errors

        result['functions'].append(func_info)

    decompiler.dispose()

    # Extract strings
    data_iter = program.getListing().getDefinedData(True)
    for data in data_iter:
        if data.hasStringValue():
            try:
                value = data.getValue()
                if value and isinstance(value, str) and len(value) >= 4:
                    result['strings'].append({
                        'value': value,
                        'address': str(data.getAddress()),
                        'length': len(value),
                        'encoding': 'utf8'
                    })
            except:
                pass

    # Extract imports using external manager
    ext_mgr = program.getExternalManager()
    for lib_name in ext_mgr.getExternalLibraryNames():
        for ext_loc in ext_mgr.getExternalLocations(lib_name):
            result['imports'].append({
                'name': ext_loc.getLabel(),
                'address': str(ext_loc.getAddress()) if ext_loc.getAddress() else None,
                'library': lib_name
            })

    # Extract exports
    symbol_table = program.getSymbolTable()
    for sym in symbol_table.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            result['exports'].append({
                'name': sym.getName(),
                'address': str(sym.getAddress())
            })

    # Extract sections/memory blocks
    memory = program.getMemory()
    for block in memory.getBlocks():
        result['sections'].append({
            'name': block.getName(),
            'start': str(block.getStart()),
            'end': str(block.getEnd()),
            'size': int(block.getSize()),
            'permissions': {
                'read': block.isRead(),
                'write': block.isWrite(),
                'execute': block.isExecute()
            }
        })

    return result


if __name__ == '__main__':
    main()
