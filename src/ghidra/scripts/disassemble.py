#!/usr/bin/env python3
"""
Disassemble Binary Script
Extracts assembly instructions using PyGhidra 3.0+
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


def disassemble_function(program, function_name_or_address, include_bytes, include_references):
    """Disassemble a function by name or address."""
    func_manager = program.getFunctionManager()
    listing = program.getListing()

    # Find function
    target_func = None
    for func in func_manager.getFunctions(True):
        if func.getName() == function_name_or_address or str(func.getEntryPoint()) == function_name_or_address:
            target_func = func
            break

    if not target_func:
        # Try parsing as address
        addr = parse_address(program, function_name_or_address)
        if addr:
            target_func = func_manager.getFunctionAt(addr)

    if not target_func:
        return None

    # Disassemble function body
    instructions = []
    body = target_func.getBody()

    for addr_range in body:
        current_addr = addr_range.getMinAddress()
        end_addr = addr_range.getMaxAddress()

        while current_addr and current_addr.compareTo(end_addr) <= 0:
            inst = listing.getInstructionAt(current_addr)
            if not inst:
                break

            inst_data = {
                'address': format_address(inst.getAddress()),
                'mnemonic': inst.getMnemonicString(),
                'operands': format_operands(inst)
            }

            if include_bytes:
                bytes_arr = inst.getBytes()
                inst_data['bytes'] = ' '.join([f'{b & 0xFF:02x}' for b in bytes_arr])

            if include_references:
                refs = []
                # Get references from this instruction
                ref_manager = program.getReferenceManager()
                for ref in ref_manager.getReferencesFrom(inst.getAddress()):
                    ref_type = ref.getReferenceType()
                    refs.append({
                        'address': format_address(ref.getToAddress()),
                        'type': ref_type.getName().lower()
                    })

                if refs:
                    inst_data['references'] = refs

            instructions.append(inst_data)
            current_addr = inst.getAddress().add(inst.getLength())

    return instructions


def disassemble_range(program, start_address, length, include_bytes, include_references):
    """Disassemble an address range."""
    listing = program.getListing()

    addr = parse_address(program, start_address)
    if not addr:
        return None

    instructions = []
    current_addr = addr
    bytes_read = 0

    while bytes_read < length:
        inst = listing.getInstructionAt(current_addr)
        if not inst:
            break

        inst_data = {
            'address': format_address(inst.getAddress()),
            'mnemonic': inst.getMnemonicString(),
            'operands': format_operands(inst)
        }

        if include_bytes:
            bytes_arr = inst.getBytes()
            inst_data['bytes'] = ' '.join([f'{b & 0xFF:02x}' for b in bytes_arr])

        if include_references:
            refs = []
            ref_manager = program.getReferenceManager()
            for ref in ref_manager.getReferencesFrom(inst.getAddress()):
                ref_type = ref.getReferenceType()
                refs.append({
                    'address': format_address(ref.getToAddress()),
                    'type': ref_type.getName().lower()
                })

            if refs:
                inst_data['references'] = refs

        instructions.append(inst_data)

        inst_len = inst.getLength()
        bytes_read += inst_len
        current_addr = current_addr.add(inst_len)

    return instructions


def format_operands(inst):
    """Format operands for an instruction."""
    parts = []
    for idx in range(inst.getNumOperands()):
        operand = inst.getDefaultOperandRepresentation(idx)
        if operand is None:
            continue
        parts.append(str(operand))
    return ', '.join(parts)


def main():
    parser = argparse.ArgumentParser(description='Disassemble binary using Ghidra')
    parser.add_argument('binary_path', help='Path to binary file')
    parser.add_argument('target', help='Function name/address or start address')
    parser.add_argument('--length', type=int, help='Number of bytes to disassemble (for address range mode)')
    parser.add_argument('--no-bytes', action='store_true', help='Exclude raw bytes')
    parser.add_argument('--no-references', action='store_true', help='Exclude cross-references')

    args = parser.parse_args()

    binary_path = Path(args.binary_path).resolve()
    if not binary_path.exists():
        print(f"ERROR: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    include_bytes = not args.no_bytes
    include_references = not args.no_references

    try:
        # Initialize PyGhidra with Ghidra installation path
        ghidra_path = os.environ.get('GHIDRA_PATH')
        if not ghidra_path:
            print(json.dumps({
                'error': 'GHIDRA_PATH environment variable not set',
                'instructions': None
            }))
            sys.exit(1)

        pyghidra.start(install_dir=ghidra_path)

        # Import Ghidra modules after starting pyghidra
        from ghidra.program.model.listing import CodeUnit
        from ghidra.program.model.address import AddressSet

        with load_program(binary_path) as program:
            # Disassemble
            if args.length:
                # Address range mode
                instructions = disassemble_range(
                    program,
                    args.target,
                    args.length,
                    include_bytes,
                    include_references
                )
            else:
                # Function mode
                instructions = disassemble_function(
                    program,
                    args.target,
                    include_bytes,
                    include_references
                )

            if instructions is None:
                print(json.dumps({
                    'error': f'Target not found: {args.target}',
                    'instructions': None
                }))
            else:
                print(json.dumps({
                    'instructions': instructions
                }))

    except Exception as e:
        print(json.dumps({
            'error': str(e),
            'instructions': None
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
