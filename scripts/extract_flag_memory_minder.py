#!/usr/bin/env python3
"""
CTF Flag Extractor for memory_minder challenge
Extracts the flag by analyzing Rune structures in the decompiled code.
"""

import json
import re
import sys
from pathlib import Path


def extract_runes(data):
    """
    Extract rune information from Match() and Expected() functions.
    Returns a dict: {rune_number: {'match': char, 'expected': char}}
    """
    runes = {}

    for func in data['functions']:
        # Match pattern: main.(*RN).Match or main.(*RN).Expected
        match = re.match(r'main\.\(\*R(\d+)\)\.(Match|Expected)', func['name'])
        if not match:
            continue

        rune_num = int(match.group(1))
        func_type = match.group(2)
        code = func['pseudocode']

        if rune_num not in runes:
            runes[rune_num] = {}

        if func_type == 'Match':
            # Look for pattern: b == 0xNN
            m = re.search(r'b == (0x[0-9a-fA-F]+)', code)
            if m:
                val = int(m.group(1), 16)
                runes[rune_num]['match'] = chr(val) if 32 <= val <= 126 else f'<{val:02x}>'

        elif func_type == 'Expected':
            # Look for pattern: return 0xNN
            m = re.search(r'return (0x[0-9a-fA-F]+)', code)
            if m:
                val = int(m.group(1), 16)
                runes[rune_num]['expected'] = chr(val) if 32 <= val <= 126 else f'<{val:02x}>'

    return runes


def print_rune_table(runes):
    """Print a formatted table of rune mappings."""
    print('\n' + '=' * 60)
    print('RUNE MAPPING TABLE')
    print('=' * 60)
    print('Rune   | Match Input | Expected Output')
    print('-------|-------------|----------------')

    for i in sorted(runes.keys()):
        match_char = runes[i].get('match', '?')
        expected_char = runes[i].get('expected', '?')
        print(f'  R{i:<2}  |      {match_char}      |       {expected_char}')


def build_flag(runes):
    """Build the flag string from rune data."""
    flag_input = ''
    flag_output = ''

    for i in sorted(runes.keys()):
        match_char = runes[i].get('match', '')
        expected_char = runes[i].get('expected', '')

        # Skip non-printable characters
        if not match_char.startswith('<'):
            flag_input += match_char
        if not expected_char.startswith('<'):
            flag_output += expected_char

    return flag_input, flag_output


def main():
    if len(sys.argv) < 2:
        print('Usage: extract_flag_memory_minder.py <analysis.json>')
        print('\nExample:')
        print('  python extract_flag_memory_minder.py /tmp/memory_minder_analysis.json')
        sys.exit(1)

    json_path = sys.argv[1]

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    print('Loading analysis data...')
    with open(json_path, 'r') as f:
        data = json.load(f)

    print(f'Analyzing {len(data["functions"])} functions...')

    # Extract rune information
    runes = extract_runes(data)

    if not runes:
        print('Error: No rune structures found! Is this the memory_minder binary?')
        sys.exit(1)

    print(f'Found {len(runes)} rune structures!')

    # Display rune table
    print_rune_table(runes)

    # Build and display flag
    flag_input, flag_output = build_flag(runes)

    print('\n' + '=' * 60)
    print('SOLUTION')
    print('=' * 60)
    print(f'Input sequence:    {flag_input}')
    print(f'Expected sequence: {flag_output}')
    print(f'\n🚩 FLAG: {flag_output}')
    print('=' * 60)


if __name__ == '__main__':
    main()
