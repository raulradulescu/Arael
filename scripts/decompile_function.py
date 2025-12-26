#!/usr/bin/env python3
"""
Function Decompiler
Extract and display decompiled code for a specific function by name or address.
"""

import json
import sys
from pathlib import Path


def find_function(data, identifier):
    """
    Find function by name or address.
    Returns the function dict or None.
    """
    # Try exact name match first
    for func in data['functions']:
        if func['name'] == identifier:
            return func

    # Try case-insensitive name match
    identifier_lower = identifier.lower()
    for func in data['functions']:
        if func['name'].lower() == identifier_lower:
            return func

    # Try address match (with or without 0x prefix)
    addr = identifier.lower().replace('0x', '')
    for func in data['functions']:
        if func['address'].lower() == addr or func['address'].lower() == '0x' + addr:
            return func

    # Try partial name match
    for func in data['functions']:
        if identifier_lower in func['name'].lower():
            return func

    return None


def print_function_header(func):
    """Print function metadata."""
    print('=' * 80)
    print(f'Function: {func["name"]}')
    print('=' * 80)
    print(f'Address:         {func["address"]}')
    print(f'Size:            {func["size"]} bytes')
    print(f'Signature:       {func["signature"]}')
    print(f'Is Thunk:        {func["isThunk"]}')
    print(f'Is External:     {func["isExternal"]}')

    if func.get('callers'):
        print(f'Called by:       {len(func["callers"])} functions')
    if func.get('callees'):
        print(f'Calls:           {len(func["callees"])} functions')


def save_to_file(func, output_path):
    """Save decompiled code to file."""
    with open(output_path, 'w') as f:
        f.write(f'// Function: {func["name"]}\n')
        f.write(f'// Address: {func["address"]}\n')
        f.write(f'// Size: {func["size"]} bytes\n')
        f.write(f'// Signature: {func["signature"]}\n\n')
        f.write(func.get('pseudocode', '// No pseudocode available\n'))
    print(f'\nSaved to: {output_path}')


def main():
    if len(sys.argv) < 3:
        print('Usage: decompile_function.py <analysis.json> <function_name_or_address> [--output file.c]')
        print('\nExamples:')
        print('  # Decompile by name')
        print('  python decompile_function.py analysis.json main')
        print('')
        print('  # Decompile by address')
        print('  python decompile_function.py analysis.json 0x140001450')
        print('')
        print('  # Save to file')
        print('  python decompile_function.py analysis.json validate_password --output password.c')
        sys.exit(1)

    json_path = sys.argv[1]
    identifier = sys.argv[2]

    output_file = None
    if '--output' in sys.argv:
        output_idx = sys.argv.index('--output')
        if output_idx + 1 < len(sys.argv):
            output_file = sys.argv[output_idx + 1]

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    with open(json_path, 'r') as f:
        data = json.load(f)

    func = find_function(data, identifier)

    if not func:
        print(f'Error: Function not found: {identifier}')
        print('\nTry using search_functions.py to find the exact name.')
        sys.exit(1)

    print_function_header(func)

    if func.get('pseudocode'):
        print('\nDecompiled Code:')
        print('-' * 80)
        print(func['pseudocode'])

        if output_file:
            save_to_file(func, output_file)
    else:
        print('\nNo pseudocode available for this function.')


if __name__ == '__main__':
    main()
