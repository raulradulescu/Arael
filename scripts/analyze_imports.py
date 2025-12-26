#!/usr/bin/env python3
"""
Import Analyzer
Analyze and categorize imported libraries and functions.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path


def categorize_imports(imports):
    """Group imports by library."""
    by_library = defaultdict(list)

    for imp in imports:
        lib = imp.get('library', 'unknown')
        by_library[lib].append(imp)

    return dict(by_library)


def detect_capabilities(imports):
    """Detect binary capabilities based on imports."""
    capabilities = {
        'Network': [],
        'File I/O': [],
        'Crypto': [],
        'Process': [],
        'Registry': [],
        'Memory': [],
        'Threading': [],
        'GUI': [],
        'Other': []
    }

    patterns = {
        'Network': ['socket', 'connect', 'send', 'recv', 'http', 'url', 'inet', 'WSA'],
        'File I/O': ['fopen', 'fread', 'fwrite', 'CreateFile', 'ReadFile', 'WriteFile', 'open', 'read', 'write'],
        'Crypto': ['crypt', 'hash', 'md5', 'sha', 'aes', 'rsa', 'Crypt'],
        'Process': ['CreateProcess', 'exec', 'fork', 'system', 'ShellExecute', 'WinExec'],
        'Registry': ['RegOpenKey', 'RegSetValue', 'RegQueryValue', 'RegDeleteKey'],
        'Memory': ['VirtualAlloc', 'malloc', 'HeapAlloc', 'mmap', 'VirtualProtect'],
        'Threading': ['CreateThread', 'pthread', 'Thread', 'Mutex', 'Semaphore'],
        'GUI': ['MessageBox', 'CreateWindow', 'ShowWindow', 'Dialog', 'Button']
    }

    for imp in imports:
        name = imp['name'].lower()
        categorized = False

        for category, keywords in patterns.items():
            if any(kw.lower() in name for kw in keywords):
                capabilities[category].append(imp)
                categorized = True
                break

        if not categorized:
            capabilities['Other'].append(imp)

    # Remove empty categories
    return {k: v for k, v in capabilities.items() if v}


def print_summary(imports):
    """Print import summary."""
    print('=' * 80)
    print('IMPORT ANALYSIS SUMMARY')
    print('=' * 80)
    print(f'\nTotal imports: {len(imports)}')


def print_by_library(by_library):
    """Print imports grouped by library."""
    print('\n[IMPORTS BY LIBRARY]')
    print('-' * 80)

    for lib in sorted(by_library.keys()):
        funcs = by_library[lib]
        print(f'\n{lib} ({len(funcs)} functions)')
        for func in sorted(funcs, key=lambda x: x['name'])[:20]:
            addr = func.get('address', 'unknown')
            print(f'  • {func["name"]:40} @ {addr}')

        if len(funcs) > 20:
            print(f'  ... and {len(funcs) - 20} more')


def print_capabilities(capabilities):
    """Print detected capabilities."""
    print('\n[DETECTED CAPABILITIES]')
    print('-' * 80)

    for category in sorted(capabilities.keys()):
        funcs = capabilities[category]
        if not funcs:
            continue

        print(f'\n{category} ({len(funcs)} imports)')
        for func in funcs[:10]:
            lib = func.get('library', 'unknown')
            print(f'  • {func["name"]:40} ({lib})')

        if len(funcs) > 10:
            print(f'  ... and {len(funcs) - 10} more')


def export_csv(imports, output_path):
    """Export imports to CSV."""
    import csv

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Library', 'Address', 'Type'])

        for imp in sorted(imports, key=lambda x: (x.get('library', ''), x['name'])):
            writer.writerow([
                imp['name'],
                imp.get('library', ''),
                imp.get('address', ''),
                imp.get('type', '')
            ])

    print(f'\nExported to: {output_path}')


def main():
    if len(sys.argv) < 2:
        print('Usage: analyze_imports.py <analysis.json> [--csv output.csv] [--capabilities]')
        print('\nExamples:')
        print('  # Show all imports by library')
        print('  python analyze_imports.py analysis.json')
        print('')
        print('  # Detect capabilities')
        print('  python analyze_imports.py analysis.json --capabilities')
        print('')
        print('  # Export to CSV')
        print('  python analyze_imports.py analysis.json --csv imports.csv')
        sys.exit(1)

    json_path = sys.argv[1]
    show_capabilities = '--capabilities' in sys.argv

    csv_output = None
    if '--csv' in sys.argv:
        csv_idx = sys.argv.index('--csv')
        if csv_idx + 1 < len(sys.argv):
            csv_output = sys.argv[csv_idx + 1]

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    with open(json_path, 'r') as f:
        data = json.load(f)

    imports = data.get('imports', [])

    if not imports:
        print('No imports found in analysis.')
        sys.exit(0)

    print_summary(imports)

    by_library = categorize_imports(imports)
    print_by_library(by_library)

    if show_capabilities:
        capabilities = detect_capabilities(imports)
        print_capabilities(capabilities)

    if csv_output:
        export_csv(imports, csv_output)


if __name__ == '__main__':
    main()
