#!/usr/bin/env python3
"""
Binary Diff Tool
Compare two binary analysis results to find differences.
"""

import json
import sys
from pathlib import Path


def load_analysis(path):
    """Load analysis JSON."""
    with open(path, 'r') as f:
        return json.load(f)


def compare_functions(data1, data2):
    """Compare function lists between two binaries."""
    funcs1 = {f['name']: f for f in data1['functions']}
    funcs2 = {f['name']: f for f in data2['functions']}

    only_in_1 = set(funcs1.keys()) - set(funcs2.keys())
    only_in_2 = set(funcs2.keys()) - set(funcs1.keys())
    common = set(funcs1.keys()) & set(funcs2.keys())

    changed = []
    for name in common:
        f1, f2 = funcs1[name], funcs2[name]
        if f1['size'] != f2['size'] or f1.get('pseudocode') != f2.get('pseudocode'):
            changed.append((name, f1, f2))

    return {
        'only_in_1': only_in_1,
        'only_in_2': only_in_2,
        'common': common,
        'changed': changed
    }


def compare_strings(data1, data2):
    """Compare strings between two binaries."""
    strings1 = {s['value'] for s in data1['strings']}
    strings2 = {s['value'] for s in data2['strings']}

    only_in_1 = strings1 - strings2
    only_in_2 = strings2 - strings1
    common = strings1 & strings2

    return {
        'only_in_1': only_in_1,
        'only_in_2': only_in_2,
        'common': common
    }


def compare_imports(data1, data2):
    """Compare imports between two binaries."""
    imports1 = {i['name'] for i in data1.get('imports', [])}
    imports2 = {i['name'] for i in data2.get('imports', [])}

    only_in_1 = imports1 - imports2
    only_in_2 = imports2 - imports1
    common = imports1 & imports2

    return {
        'only_in_1': only_in_1,
        'only_in_2': only_in_2,
        'common': common
    }


def print_summary(data1, data2, file1, file2):
    """Print comparison summary."""
    print('=' * 80)
    print('BINARY COMPARISON SUMMARY')
    print('=' * 80)
    print(f'\nFile 1: {file1}')
    print(f'  Format: {data1.get("format")}')
    print(f'  Functions: {len(data1["functions"]):,}')
    print(f'  Strings: {len(data1["strings"]):,}')
    print(f'  Imports: {len(data1.get("imports", [])):,}')

    print(f'\nFile 2: {file2}')
    print(f'  Format: {data2.get("format")}')
    print(f'  Functions: {len(data2["functions"]):,}')
    print(f'  Strings: {len(data2["strings"]):,}')
    print(f'  Imports: {len(data2.get("imports", [])):,}')


def print_function_diff(func_diff, file1, file2):
    """Print function differences."""
    print('\n[FUNCTION DIFFERENCES]')
    print('-' * 80)

    print(f'\nOnly in {file1}: {len(func_diff["only_in_1"])} functions')
    for name in sorted(list(func_diff['only_in_1']))[:10]:
        print(f'  - {name}')
    if len(func_diff['only_in_1']) > 10:
        print(f'  ... and {len(func_diff["only_in_1"]) - 10} more')

    print(f'\nOnly in {file2}: {len(func_diff["only_in_2"])} functions')
    for name in sorted(list(func_diff['only_in_2']))[:10]:
        print(f'  + {name}')
    if len(func_diff['only_in_2']) > 10:
        print(f'  ... and {len(func_diff["only_in_2"]) - 10} more')

    print(f'\nModified: {len(func_diff["changed"])} functions')
    for name, f1, f2 in func_diff['changed'][:10]:
        size_diff = f2['size'] - f1['size']
        sign = '+' if size_diff > 0 else ''
        print(f'  ~ {name:50} ({f1["size"]} -> {f2["size"]} bytes, {sign}{size_diff})')
    if len(func_diff['changed']) > 10:
        print(f'  ... and {len(func_diff["changed"]) - 10} more')


def print_string_diff(string_diff, file1, file2):
    """Print string differences."""
    print('\n[STRING DIFFERENCES]')
    print('-' * 80)

    print(f'\nOnly in {file1}: {len(string_diff["only_in_1"])} strings')
    for s in sorted(list(string_diff['only_in_1']))[:5]:
        print(f'  - "{s[:60]}"')
    if len(string_diff['only_in_1']) > 5:
        print(f'  ... and {len(string_diff["only_in_1"]) - 5} more')

    print(f'\nOnly in {file2}: {len(string_diff["only_in_2"])} strings')
    for s in sorted(list(string_diff['only_in_2']))[:5]:
        print(f'  + "{s[:60]}"')
    if len(string_diff['only_in_2']) > 5:
        print(f'  ... and {len(string_diff["only_in_2"]) - 5} more')


def print_import_diff(import_diff, file1, file2):
    """Print import differences."""
    print('\n[IMPORT DIFFERENCES]')
    print('-' * 80)

    print(f'\nOnly in {file1}: {len(import_diff["only_in_1"])} imports')
    for name in sorted(list(import_diff['only_in_1']))[:10]:
        print(f'  - {name}')

    print(f'\nOnly in {file2}: {len(import_diff["only_in_2"])} imports')
    for name in sorted(list(import_diff['only_in_2']))[:10]:
        print(f'  + {name}')


def main():
    if len(sys.argv) < 3:
        print('Usage: diff_binaries.py <analysis1.json> <analysis2.json>')
        print('\nExample:')
        print('  python diff_binaries.py old_version.json new_version.json')
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]

    if not Path(file1).exists():
        print(f'Error: File not found: {file1}')
        sys.exit(1)

    if not Path(file2).exists():
        print(f'Error: File not found: {file2}')
        sys.exit(1)

    print('Loading analysis files...')
    data1 = load_analysis(file1)
    data2 = load_analysis(file2)

    print_summary(data1, data2, Path(file1).name, Path(file2).name)

    func_diff = compare_functions(data1, data2)
    print_function_diff(func_diff, Path(file1).name, Path(file2).name)

    string_diff = compare_strings(data1, data2)
    print_string_diff(string_diff, Path(file1).name, Path(file2).name)

    import_diff = compare_imports(data1, data2)
    print_import_diff(import_diff, Path(file1).name, Path(file2).name)

    print('\n' + '=' * 80)
    print('Comparison complete!')
    print('=' * 80)


if __name__ == '__main__':
    main()
