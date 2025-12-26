#!/usr/bin/env python3
"""
Function Search Tool
Search for specific functions in Arael analysis output.
"""

import json
import re
import sys
from pathlib import Path


def search_functions(data, pattern, show_code=False):
    """
    Search for functions matching a pattern.
    Returns list of matching functions.
    """
    regex = re.compile(pattern, re.IGNORECASE)
    matches = []

    for func in data['functions']:
        if regex.search(func['name']):
            matches.append(func)

    return matches


def print_function_list(funcs):
    """Print a list of functions."""
    print(f'\nFound {len(funcs)} matching functions:')
    print('-' * 80)

    for func in funcs:
        print(f'  {func["name"]:50} {func["size"]:6} bytes @ {func["address"]}')


def print_function_detail(func):
    """Print detailed information about a function."""
    print('\n' + '=' * 80)
    print(f'FUNCTION: {func["name"]}')
    print('=' * 80)
    print(f'Address:    {func["address"]}')
    print(f'Size:       {func["size"]} bytes')
    print(f'Signature:  {func["signature"]}')
    print(f'Is Thunk:   {func["isThunk"]}')
    print(f'Is External: {func["isExternal"]}')

    if func.get('pseudocode'):
        print(f'\nDecompiled Code:')
        print('-' * 80)
        print(func['pseudocode'])


def main():
    if len(sys.argv) < 3:
        print('Usage: search_functions.py <analysis.json> <pattern> [--detail]')
        print('\nExamples:')
        print('  # Search for main functions')
        print('  python search_functions.py analysis.json "^main\\."')
        print('')
        print('  # Search for password-related functions')
        print('  python search_functions.py analysis.json "password|validate|check"')
        print('')
        print('  # Show detailed info for first match')
        print('  python search_functions.py analysis.json "main\\.main" --detail')
        sys.exit(1)

    json_path = sys.argv[1]
    pattern = sys.argv[2]
    show_detail = '--detail' in sys.argv

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    print(f'Loading analysis from {json_path}...')
    with open(json_path, 'r') as f:
        data = json.load(f)

    print(f'Searching {len(data["functions"])} functions for pattern: {pattern}')

    matches = search_functions(data, pattern)

    if not matches:
        print('No functions found matching pattern.')
        sys.exit(0)

    if show_detail and matches:
        # Show detailed view of first match
        print_function_detail(matches[0])

        if len(matches) > 1:
            print(f'\n(Showing 1 of {len(matches)} matches)')
    else:
        # Show list view
        print_function_list(matches)


if __name__ == '__main__':
    main()
