#!/usr/bin/env python3
"""
String Search Tool
Search for specific strings in Arael analysis output.
"""

import json
import re
import sys
from pathlib import Path


def search_strings(data, pattern, case_sensitive=False):
    """
    Search for strings matching a pattern.
    Returns list of matching strings.
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    regex = re.compile(pattern, flags)
    matches = []

    for s in data['strings']:
        if regex.search(s['value']):
            matches.append(s)

    return matches


def print_strings(strings, max_len=80):
    """Print a list of strings."""
    print(f'\nFound {len(strings)} matching strings:')
    print('-' * 100)

    for s in strings:
        value = s['value'].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        if len(value) > max_len:
            value = value[:max_len] + '...'
        print(f'  [{s["address"]}] "{value}"')


def categorize_strings(strings):
    """Categorize strings by type."""
    categories = {
        'URLs': [],
        'Paths': [],
        'Error Messages': [],
        'Format Strings': [],
        'Other': []
    }

    for s in strings:
        val = s['value']
        if val.startswith('http://') or val.startswith('https://'):
            categories['URLs'].append(s)
        elif '/' in val and (val.startswith('/') or ':' in val):
            categories['Paths'].append(s)
        elif any(kw in val.lower() for kw in ['error', 'fail', 'invalid', 'cannot']):
            categories['Error Messages'].append(s)
        elif '%' in val or '{' in val:
            categories['Format Strings'].append(s)
        else:
            categories['Other'].append(s)

    return categories


def print_categorized(categories):
    """Print strings organized by category."""
    for category, strings in categories.items():
        if not strings:
            continue

        print(f'\n[{category}] ({len(strings)} strings)')
        print('-' * 100)
        for s in strings[:10]:  # Limit to 10 per category
            value = s['value'].replace('\n', '\\n')[:80]
            print(f'  [{s["address"]}] "{value}"')

        if len(strings) > 10:
            print(f'  ... and {len(strings) - 10} more')


def main():
    if len(sys.argv) < 3:
        print('Usage: search_strings.py <analysis.json> <pattern> [--case-sensitive] [--categorize]')
        print('\nExamples:')
        print('  # Search for passwords')
        print('  python search_strings.py analysis.json "password|secret|key"')
        print('')
        print('  # Search for flags (case-sensitive)')
        print('  python search_strings.py analysis.json "FLAG\\{.*\\}" --case-sensitive')
        print('')
        print('  # Categorize all strings containing "error"')
        print('  python search_strings.py analysis.json "error" --categorize')
        sys.exit(1)

    json_path = sys.argv[1]
    pattern = sys.argv[2]
    case_sensitive = '--case-sensitive' in sys.argv
    categorize = '--categorize' in sys.argv

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    print(f'Loading analysis from {json_path}...')
    with open(json_path, 'r') as f:
        data = json.load(f)

    print(f'Searching {len(data["strings"])} strings for pattern: {pattern}')
    if case_sensitive:
        print('(case-sensitive mode)')

    matches = search_strings(data, pattern, case_sensitive)

    if not matches:
        print('No strings found matching pattern.')
        sys.exit(0)

    if categorize:
        categories = categorize_strings(matches)
        print_categorized(categories)
    else:
        print_strings(matches)


if __name__ == '__main__':
    main()
