#!/usr/bin/env python3
"""
Cross-References Script
Extracts cross-references to/from addresses using PyGhidra 3.0+
"""

import sys
import json
import argparse
import os
from pathlib import Path
from project_loader import load_program, format_address

try:
    import pyghidra
except ImportError:
    print("ERROR: pyghidra not installed. Run: pip install pyghidra", file=sys.stderr)
    sys.exit(1)


def parse_address(program, address_str):
    """Parse address string to Ghidra Address object."""
    addr_factory = program.getAddressFactory()

    # Try hex format
    if address_str.startswith('0x'):
        try:
            offset = int(address_str, 16)
            return addr_factory.getDefaultAddressSpace().getAddress(offset)
        except:
            pass

    # Try as function name
    func_manager = program.getFunctionManager()
    for func in func_manager.getFunctions(True):
        if func.getName() == address_str:
            return func.getEntryPoint()

    # Try hex without 0x prefix
    try:
        offset = int(address_str, 16)
        return addr_factory.getDefaultAddressSpace().getAddress(offset)
    except:
        pass

    # Try decimal
    try:
        offset = int(address_str, 10)
        return addr_factory.getDefaultAddressSpace().getAddress(offset)
    except:
        pass

    return None


def get_function_name_at(program, address):
    """Get function name at address, or None."""
    func_manager = program.getFunctionManager()
    func = func_manager.getFunctionContaining(address)
    if func:
        return func.getName()
    return None


def get_xrefs_to(program, address, max_results):
    """Get all references TO an address (who calls this)."""
    ref_manager = program.getReferenceManager()
    refs = []

    for ref in ref_manager.getReferencesTo(address):
        if len(refs) >= max_results:
            break

        from_addr = ref.getFromAddress()
        ref_type = ref.getReferenceType()

        refs.append({
            'from': format_address(from_addr),
            'type': get_ref_type_name(ref_type),
            'functionName': get_function_name_at(program, from_addr)
        })

    return refs


def get_xrefs_from(program, address, max_results):
    """Get all references FROM an address (what does this call)."""
    ref_manager = program.getReferenceManager()
    refs = []

    for ref in ref_manager.getReferencesFrom(address):
        if len(refs) >= max_results:
            break

        to_addr = ref.getToAddress()
        ref_type = ref.getReferenceType()

        refs.append({
            'to': format_address(to_addr),
            'type': get_ref_type_name(ref_type),
            'functionName': get_function_name_at(program, to_addr)
        })

    return refs


def get_xrefs_both(program, address, max_results):
    """Get both TO and FROM references."""
    refs_to = get_xrefs_to(program, address, max_results)
    refs_from = get_xrefs_from(program, address, max_results)

    # Combine, but respect max_results
    combined = refs_to + refs_from
    return combined[:max_results]


def get_ref_type_name(ref_type):
    """Convert Ghidra RefType to human-readable string."""
    if ref_type.isCall():
        return 'call'
    elif ref_type.isJump():
        return 'jump'
    elif ref_type.isData():
        return 'data'
    elif ref_type.isRead():
        return 'read'
    elif ref_type.isWrite():
        return 'write'
    else:
        return ref_type.getName().lower()


def main():
    parser = argparse.ArgumentParser(description='Get cross-references using Ghidra')
    parser.add_argument('binary_path', help='Path to binary file')
    parser.add_argument('address', help='Address to analyze')
    parser.add_argument('--direction', choices=['to', 'from', 'both'], default='both',
                        help='Direction of references')
    parser.add_argument('--max', type=int, default=100, help='Maximum number of results')

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
                'references': None
            }))
            sys.exit(1)

        pyghidra.start(install_dir=ghidra_path)

        # Import Ghidra modules after starting pyghidra
        from ghidra.program.model.symbol import RefType

        with load_program(binary_path) as program:
            # Parse address
            addr = parse_address(program, args.address)
            if not addr:
                print(json.dumps({
                    'error': f'Address not found: {args.address}',
                    'references': None
                }))
                sys.exit(0)

            # Get cross-references
            if args.direction == 'to':
                references = get_xrefs_to(program, addr, args.max)
            elif args.direction == 'from':
                references = get_xrefs_from(program, addr, args.max)
            else:  # both
                references = get_xrefs_both(program, addr, args.max)

            print(json.dumps({
                'references': references
            }))

    except Exception as e:
        print(json.dumps({
            'error': str(e),
            'references': None
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
