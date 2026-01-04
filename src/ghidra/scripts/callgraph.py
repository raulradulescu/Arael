#!/usr/bin/env python3
"""
Call Graph Script
Generates call graphs in various formats using PyGhidra 3.0+
"""

import sys
import json
import argparse
import os
from pathlib import Path
from collections import deque
from project_loader import load_program, format_address

try:
    import pyghidra
except ImportError:
    print("ERROR: pyghidra not installed. Run: pip install pyghidra", file=sys.stderr)
    sys.exit(1)


def resolve_address(program, offset):
    """Resolve an address, optionally treating offsets relative to image base."""
    addr_factory = program.getAddressFactory()
    address = addr_factory.getDefaultAddressSpace().getAddress(offset)
    if os.environ.get('ARAEL_ADDRESS_MODE', '').lower() == 'offset':
        try:
            memory = program.getMemory()
            if not memory.contains(address):
                base_addr = program.getMinAddress()
                address = base_addr.add(offset)
        except Exception:
            pass
    return address


def parse_address_or_function(program, target):
    """Parse address string or function name to Ghidra Address object."""

    # Try hex format
    if target.startswith('0x'):
        try:
            offset = int(target, 16)
            return resolve_address(program, offset)
        except:
            pass

    # Try as function name
    func_manager = program.getFunctionManager()
    for func in func_manager.getFunctions(True):
        if func.getName() == target:
            return func.getEntryPoint()

    # Try hex without 0x prefix
    try:
        offset = int(target, 16)
        return resolve_address(program, offset)
    except:
        pass

    # Try decimal
    try:
        offset = int(target, 10)
        return resolve_address(program, offset)
    except:
        pass

    return None


def get_function_at(program, address):
    """Get function at address, or None."""
    func_manager = program.getFunctionManager()
    return func_manager.getFunctionContaining(address)


def get_called_functions(program, function, exclude_external, include_thunks):
    """Get all functions called by this function."""
    called = []
    ref_manager = program.getReferenceManager()

    # Get all addresses in function body
    body = function.getBody()

    # Iterate through all references from this function
    for address in body.getAddresses(True):
        for ref in ref_manager.getReferencesFrom(address):
            # Only care about calls
            if not ref.getReferenceType().isCall():
                continue

            to_addr = ref.getToAddress()
            to_func = get_function_at(program, to_addr)

            if not to_func:
                continue

            # Apply filters
            if exclude_external and to_func.isExternal():
                continue

            if not include_thunks and to_func.isThunk():
                continue

            called.append(to_func)

    return called


def build_callgraph_bfs(program, root_function, max_depth, exclude_external, include_thunks):
    """Build call graph using BFS from root function."""
    nodes = {}
    edges = []

    # BFS queue: (function, depth)
    queue = deque([(root_function, 0)])
    visited = set()

    while queue:
        func, depth = queue.popleft()
        func_addr = str(func.getEntryPoint())

        if func_addr in visited:
            continue

        visited.add(func_addr)

        # Add node
        if func_addr not in nodes:
            nodes[func_addr] = {
                'name': func.getName(),
                'address': format_address(func.getEntryPoint()),
                'size': func.getBody().getNumAddresses(),
                'isExternal': func.isExternal(),
                'isThunk': func.isThunk()
            }

        # Don't expand beyond max depth
        if depth >= max_depth:
            continue

        # Get called functions
        called_funcs = get_called_functions(program, func, exclude_external, include_thunks)

        for called in called_funcs:
            called_addr = str(called.getEntryPoint())

            # Add edge
            edges.append({
                'from': func.getName(),
                'to': called.getName(),
                'type': 'call'
            })

            # Add to queue if not visited
            if called_addr not in visited:
                queue.append((called, depth + 1))

    return list(nodes.values()), edges


def build_full_callgraph(program, exclude_external, include_thunks):
    """Build complete call graph for all functions."""
    func_manager = program.getFunctionManager()
    nodes = []
    edges = []

    # Build nodes
    for func in func_manager.getFunctions(True):
        if exclude_external and func.isExternal():
            continue

        if not include_thunks and func.isThunk():
            continue

        nodes.append({
            'name': func.getName(),
            'address': format_address(func.getEntryPoint()),
            'size': func.getBody().getNumAddresses(),
            'isExternal': func.isExternal(),
            'isThunk': func.isThunk()
        })

    # Build edges
    for func in func_manager.getFunctions(True):
        if exclude_external and func.isExternal():
            continue

        if not include_thunks and func.isThunk():
            continue

        called_funcs = get_called_functions(program, func, exclude_external, include_thunks)

        for called in called_funcs:
            edges.append({
                'from': func.getName(),
                'to': called.getName(),
                'type': 'call'
            })

    return nodes, edges


def generate_json(nodes, edges):
    """Generate JSON format output."""
    return {
        'nodes': nodes,
        'edges': edges
    }


def generate_dot(nodes, edges):
    """Generate DOT format for Graphviz."""
    lines = ['digraph CallGraph {']
    lines.append('  rankdir=TB;')
    lines.append('  node [shape=box, style=rounded];')
    lines.append('')

    # Add nodes
    for node in nodes:
        label = f"{node['name']}\\n{node['address']}"
        color = 'lightgray' if node.get('isExternal') else 'lightblue'
        style = 'dashed' if node.get('isThunk') else 'solid'

        lines.append(f'  "{node["name"]}" [label="{label}", fillcolor={color}, style="filled,{style}"];')

    lines.append('')

    # Add edges
    for edge in edges:
        style = 'dotted' if edge['type'] == 'conditional' else 'solid'
        lines.append(f'  "{edge["from"]}" -> "{edge["to"]}" [style={style}];')

    lines.append('}')

    return '\n'.join(lines)


def generate_mermaid(nodes, edges):
    """Generate Mermaid format for markdown."""
    lines = ['graph TD']

    # Add nodes (Mermaid auto-creates nodes from edges, but we can style them)
    node_styles = {}
    for i, node in enumerate(nodes):
        node_id = node['name'].replace('.', '_').replace('-', '_')

        if node.get('isExternal'):
            node_styles[node['name']] = f'classDef ext{i} fill:#ddd,stroke:#999;'
        elif node.get('isThunk'):
            node_styles[node['name']] = f'classDef thunk{i} fill:#ffa,stroke:#cc8;'

        # Create node with label
        lines.append(f'  {node_id}["{node["name"]}<br/>{node["address"]}"]')

        if node['name'] in node_styles:
            lines.append(f'  class {node_id} ext{i};' if node.get('isExternal') else f'  class {node_id} thunk{i};')

    lines.append('')

    # Add edges
    for edge in edges:
        from_id = edge['from'].replace('.', '_').replace('-', '_')
        to_id = edge['to'].replace('.', '_').replace('-', '_')

        arrow = '-->' if edge['type'] == 'call' else '-..->'
        lines.append(f'  {from_id} {arrow} {to_id}')

    # Add style definitions
    lines.append('')
    for style in node_styles.values():
        lines.append(f'  {style}')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Generate call graph using Ghidra')
    parser.add_argument('binary_path', help='Path to binary file')
    parser.add_argument('--format', choices=['json', 'dot', 'mermaid'], default='json',
                        help='Output format')
    parser.add_argument('--root', help='Root function name or address (if not specified, full graph)')
    parser.add_argument('--depth', type=int, default=5, help='Maximum depth for BFS')
    parser.add_argument('--no-external', action='store_true', help='Exclude external functions')
    parser.add_argument('--include-thunks', action='store_true', help='Include thunk functions')

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
                'nodes': [],
                'edges': []
            }))
            sys.exit(1)

        pyghidra.start(install_dir=ghidra_path)

        # Import Ghidra modules after starting pyghidra
        from ghidra.program.model.symbol import RefType

        with load_program(binary_path) as program:
            # Build call graph
            if args.root:
                # BFS from root function
                addr = parse_address_or_function(program, args.root)
                if not addr:
                    print(json.dumps({
                        'error': f'Function not found: {args.root}',
                        'nodes': [],
                        'edges': []
                    }))
                    sys.exit(0)

                root_func = get_function_at(program, addr)
                if not root_func:
                    print(json.dumps({
                        'error': f'No function at address: {addr}',
                        'nodes': [],
                        'edges': []
                    }))
                    sys.exit(0)

                nodes, edges = build_callgraph_bfs(
                    program,
                    root_func,
                    args.depth,
                    args.no_external,
                    args.include_thunks
                )
            else:
                # Full call graph
                nodes, edges = build_full_callgraph(
                    program,
                    args.no_external,
                    args.include_thunks
                )

            # Generate output in requested format
            if args.format == 'json':
                result = generate_json(nodes, edges)
                print(json.dumps(result))
            elif args.format == 'dot':
                dot_graph = generate_dot(nodes, edges)
                result = {
                    'nodes': nodes,
                    'edges': edges,
                    'graphData': dot_graph
                }
                print(json.dumps(result))
            elif args.format == 'mermaid':
                mermaid_graph = generate_mermaid(nodes, edges)
                result = {
                    'nodes': nodes,
                    'edges': edges,
                    'graphData': mermaid_graph
                }
                print(json.dumps(result))

    except Exception as e:
        print(json.dumps({
            'error': str(e),
            'nodes': [],
            'edges': []
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
