#!/usr/bin/env python3
"""
Binary Analysis Report Generator
Uses Arael's JSON output to generate human-readable analysis reports.
"""

import json
import sys
from pathlib import Path


def load_analysis(json_path):
    """Load analysis JSON from file."""
    with open(json_path, 'r') as f:
        return json.load(f)


def print_summary(data):
    """Print binary metadata and statistics."""
    print('=' * 80)
    print(' ' * 25 + 'BINARY ANALYSIS REPORT')
    print('=' * 80)

    print('\n[BINARY METADATA]')
    print(f'  File Format:     {data["format"]}')
    print(f'  Architecture:    {data["architecture"]} ({data["addressSize"]}-bit)')
    print(f'  Compiler:        {data.get("compiler", "unknown")}')

    print('\n[ANALYSIS STATISTICS]')
    print(f'  Total Functions: {len(data["functions"]):,}')
    print(f'  Total Strings:   {len(data["strings"]):,}')
    print(f'  Total Imports:   {len(data["imports"]):,}')
    print(f'  Total Exports:   {len(data.get("exports", [])):,}')
    print(f'  Memory Sections: {len(data.get("sections", [])):,}')


def detect_language(data):
    """Detect programming language based on function names."""
    funcs = data['functions']

    # Check for Go
    go_funcs = [f for f in funcs if f['name'].startswith(('runtime.', 'fmt.', 'reflect.'))]
    if len(go_funcs) > 10:
        return 'Go (Golang)', go_funcs

    # Check for C++
    cpp_funcs = [f for f in funcs if '::' in f['name'] or f['name'].startswith('_Z')]
    if len(cpp_funcs) > 5:
        return 'C++', cpp_funcs

    # Check for Rust
    rust_funcs = [f for f in funcs if 'core::' in f['name'] or 'alloc::' in f['name']]
    if len(rust_funcs) > 5:
        return 'Rust', rust_funcs

    return 'C or Unknown', []


def print_language_info(data):
    """Print detected language information."""
    lang, lang_funcs = detect_language(data)

    print(f'\n[DETECTED LANGUAGE: {lang}]')

    if lang.startswith('Go'):
        funcs = data['functions']
        print(f'  runtime package: {len([f for f in funcs if f["name"].startswith("runtime.")])}')
        print(f'  fmt package:     {len([f for f in funcs if f["name"].startswith("fmt.")])}')
        print(f'  main package:    {len([f for f in funcs if f["name"].startswith("main.")])}')


def print_top_functions(data, n=10):
    """Print largest functions by size."""
    print(f'\n[TOP {n} LARGEST FUNCTIONS]')
    sorted_funcs = sorted(data['functions'], key=lambda x: x['size'], reverse=True)[:n]
    for i, func in enumerate(sorted_funcs, 1):
        print(f'  {i:2}. {func["name"]:50} {func["size"]:6} bytes @ {func["address"]}')


def print_security_findings(data):
    """Look for interesting security-related strings."""
    print('\n[SECURITY ANALYSIS]')

    keywords = ['password', 'key', 'secret', 'token', 'flag', 'admin', 'auth']
    findings = []

    for s in data['strings']:
        val_lower = s['value'].lower()
        for kw in keywords:
            if kw in val_lower and len(s['value']) > 3:
                findings.append((kw, s['address'], s['value']))
                break

    if findings:
        print('  Found potentially sensitive strings:')
        for kw, addr, val in findings[:20]:
            clean_val = val.replace('\n', '\\n')[:60]
            print(f'    [{kw.upper()}] @ {addr}: "{clean_val}"')
    else:
        print('  No obvious security-sensitive strings found.')


def print_memory_sections(data):
    """Print memory section information."""
    if 'sections' not in data or not data['sections']:
        return

    print('\n[MEMORY SECTIONS]')
    for sec in data['sections'][:15]:
        perms = sec['permissions']
        perm_str = ('R' if perms['read'] else '-') + \
                   ('W' if perms['write'] else '-') + \
                   ('X' if perms['execute'] else '-')
        print(f'  [{perm_str}] {sec["name"]:20} {sec["start"]:16} - {sec["end"]:16} ({sec["size"]:8} bytes)')


def main():
    if len(sys.argv) < 2:
        print('Usage: analyze_binary.py <analysis.json>')
        print('\nExample:')
        print('  python analyze_binary.py /tmp/binary_analysis.json')
        sys.exit(1)

    json_path = sys.argv[1]

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    data = load_analysis(json_path)

    print_summary(data)
    print_language_info(data)
    print_top_functions(data)
    print_security_findings(data)
    print_memory_sections(data)

    print('\n' + '=' * 80)
    print('Analysis complete!')
    print('=' * 80)


if __name__ == '__main__':
    main()
