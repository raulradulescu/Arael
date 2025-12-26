#!/usr/bin/env python3
"""
Exports Script
Extracts exported symbols from binaries using PyGhidra 3.0+
"""

import sys
import json
import argparse
import re
import os
from pathlib import Path
from project_loader import load_program, format_address

try:
    import pyghidra
except ImportError:
    print("ERROR: pyghidra not installed. Run: pip install pyghidra", file=sys.stderr)
    sys.exit(1)


def get_exports(program, name_pattern=None, export_type='all'):
    """Extract exported symbols from the program."""
    from ghidra.program.model.symbol import SymbolType

    symbol_table = program.getSymbolTable()
    exports = []

    # Compile regex pattern if provided
    pattern = None
    if name_pattern:
        try:
            pattern = re.compile(name_pattern)
        except re.error as e:
            print(f"ERROR: Invalid regex pattern: {e}", file=sys.stderr)
            sys.exit(1)

    # Iterate through all external symbols (exports)
    external_manager = program.getExternalManager()

    # Also check symbol table for exported symbols
    for symbol in symbol_table.getAllSymbols(True):
        # Skip non-exported symbols
        if not symbol.isExternal() and not symbol.isExternalEntryPoint():
            # Check if it's a global symbol (likely exported)
            if not symbol.isGlobal():
                continue

        name = symbol.getName()
        address = format_address(symbol.getAddress())

        # Apply name pattern filter
        if pattern and not pattern.search(name):
            continue

        # Determine symbol type
        symbol_type = symbol.getSymbolType()

        is_function = symbol_type == SymbolType.FUNCTION
        is_data = symbol_type == SymbolType.LABEL or symbol_type == SymbolType.GLOBAL

        # Apply type filter
        if export_type == 'function' and not is_function:
            continue
        elif export_type == 'data' and not is_data:
            continue

        # Get size
        size = 0
        if is_function:
            func_manager = program.getFunctionManager()
            func = func_manager.getFunctionAt(symbol.getAddress())
            if func:
                size = func.getBody().getNumAddresses()
        else:
            # For data symbols, try to get size from data type
            data_at = program.getListing().getDataAt(symbol.getAddress())
            if data_at:
                size = data_at.getLength()

        export_entry = {
            'name': name,
            'address': address,
            'size': int(size),
            'type': 'function' if is_function else 'data'
        }

        exports.append(export_entry)

    # Also get exports from the export table if available
    exports_from_table = get_exports_from_table(program, pattern, export_type)

    # Merge and deduplicate by address
    seen_addresses = {exp['address'] for exp in exports}
    for exp in exports_from_table:
        if exp['address'] not in seen_addresses:
            exports.append(exp)
            seen_addresses.add(exp['address'])

    # Sort by address
    exports.sort(key=lambda x: int(x['address'].replace('0x', ''), 16) if x['address'].startswith('0x') else 0)

    return exports


def get_exports_from_table(program, pattern=None, export_type='all'):
    """Get exports from the PE/ELF export table if available."""
    exports = []

    # Get the program's executable format
    executable_format = program.getExecutableFormat()

    # For PE files, check export table
    if 'PE' in executable_format or 'Portable Executable' in executable_format:
        exports.extend(get_pe_exports(program, pattern, export_type))
    # For ELF files, check dynamic symbol table
    elif 'ELF' in executable_format or 'Executable and Linking Format' in executable_format:
        exports.extend(get_elf_exports(program, pattern, export_type))

    return exports


def get_pe_exports(program, pattern=None, export_type='all'):
    """Extract exports from PE export table."""
    exports = []

    # Try to find export directory
    memory = program.getMemory()
    listing = program.getListing()

    # Look for .edata section or IMAGE_EXPORT_DIRECTORY
    for block in memory.getBlocks():
        if '.edata' in block.getName().lower() or 'export' in block.getName().lower():
            # This is a simplified approach - proper parsing would require
            # walking the PE structures
            pass

    return exports


def get_elf_exports(program, pattern=None, export_type='all'):
    """Extract exports from ELF dynamic symbol table."""
    exports = []

    # For ELF, dynamic symbols with STB_GLOBAL binding are exports
    # This is already covered by the main get_exports function
    # which checks for global symbols

    return exports


def main():
    parser = argparse.ArgumentParser(description='Extract exported symbols using Ghidra')
    parser.add_argument('binary_path', help='Path to binary file')
    parser.add_argument('--pattern', help='Regex pattern to filter symbol names')
    parser.add_argument('--type', choices=['function', 'data', 'all'], default='all',
                        help='Type of exports to retrieve')

    args = parser.parse_args()

    binary_path = Path(args.binary_path).resolve()
    if not binary_path.exists():
        print(f"ERROR: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    try:
        # Initialize PyGhidra with Ghidra installation path
        ghidra_path = os.environ.get('GHIDRA_PATH')
        if not ghidra_path:
            print(json.dumps({
                'error': 'GHIDRA_PATH environment variable not set',
                'exports': None
            }))
            sys.exit(1)

        pyghidra.start(install_dir=ghidra_path)

        # Import Ghidra modules after starting pyghidra
        from ghidra.program.model.symbol import SymbolType

        with load_program(binary_path) as program:
            # Get exports
            exports = get_exports(program, args.pattern, args.type)

            print(json.dumps({
                'exports': exports
            }))

    except Exception as e:
        print(json.dumps({
            'error': str(e),
            'exports': None
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
