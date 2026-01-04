#!/usr/bin/env python3
"""
Best-effort .pyc decompiler helper.
Uses uncompyle6 when available, otherwise falls back to marshal + dis + AST stubs.
"""

import argparse
import ast
import dis
import inspect
import json
import marshal
import os
import shutil
import subprocess
import sys
import tempfile
import types


def run_uncompyle6(pyc_path):
    tmpdir = tempfile.mkdtemp(prefix="arael_uncompyle6_")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "uncompyle6", "-o", tmpdir, pyc_path],
            capture_output=True,
            text=True
        )

        warnings = []
        if proc.stderr:
            warnings.append(proc.stderr.strip())

        if proc.returncode != 0:
            error = proc.stderr.strip() or proc.stdout.strip() or "uncompyle6 failed"
            return None, [error], warnings

        for root, _, files in os.walk(tmpdir):
            for name in files:
                if name.endswith(".py"):
                    output_path = os.path.join(root, name)
                    with open(output_path, "r", encoding="utf-8", errors="replace") as handle:
                        return handle.read(), [], warnings

        if proc.stdout:
            return proc.stdout, [], warnings

        return None, ["uncompyle6 produced no output"], warnings
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def detect_class_names(code_obj):
    class_names = set()
    instructions = list(dis.get_instructions(code_obj))
    for idx, instr in enumerate(instructions):
        if instr.opname == "LOAD_BUILD_CLASS":
            for j in range(idx + 1, len(instructions)):
                candidate = instructions[j]
                if candidate.opname == "LOAD_CONST" and isinstance(candidate.argval, types.CodeType):
                    class_names.add(candidate.argval.co_name)
                    break
    return class_names


def collect_imports(code_obj):
    modules = []
    for instr in dis.get_instructions(code_obj):
        if instr.opname == "IMPORT_NAME" and instr.argval:
            modules.append(instr.argval)
    return sorted(set(modules))


def build_arguments(code_obj):
    posonly = getattr(code_obj, "co_posonlyargcount", 0)
    argcount = code_obj.co_argcount
    kwonly = code_obj.co_kwonlyargcount
    total = posonly + argcount + kwonly

    arg_names = list(code_obj.co_varnames[:posonly + argcount])
    kwonly_names = list(code_obj.co_varnames[posonly + argcount: total])

    args = [ast.arg(arg=name or f"arg{i}") for i, name in enumerate(arg_names)]
    kwonlyargs = [ast.arg(arg=name or f"kw{i}") for i, name in enumerate(kwonly_names)]

    vararg = ast.arg(arg="args") if code_obj.co_flags & inspect.CO_VARARGS else None
    kwarg = ast.arg(arg="kwargs") if code_obj.co_flags & inspect.CO_VARKEYWORDS else None

    return ast.arguments(
        posonlyargs=[],
        args=args,
        kwonlyargs=kwonlyargs,
        kw_defaults=[None] * len(kwonlyargs),
        defaults=[],
        vararg=vararg,
        kwarg=kwarg
    )


def build_stub_source(code_obj):
    imports = collect_imports(code_obj)
    class_names = detect_class_names(code_obj)

    body = []
    for module in imports:
        body.append(ast.Import(names=[ast.alias(name=module, asname=None)]))

    for const in code_obj.co_consts:
        if not isinstance(const, types.CodeType):
            continue
        if const.co_name == "<module>":
            continue

        is_async = bool(
            const.co_flags & (
                inspect.CO_COROUTINE |
                inspect.CO_ASYNC_GENERATOR |
                inspect.CO_ITERABLE_COROUTINE
            )
        )

        if const.co_name in class_names:
            body.append(
                ast.ClassDef(
                    name=const.co_name,
                    bases=[],
                    keywords=[],
                    body=[ast.Pass()],
                    decorator_list=[]
                )
            )
            continue

        args = build_arguments(const)
        func_node = ast.AsyncFunctionDef if is_async else ast.FunctionDef
        body.append(
            func_node(
                name=const.co_name,
                args=args,
                body=[ast.Pass()],
                decorator_list=[]
            )
        )

    if not body:
        body.append(ast.Pass())

    module = ast.Module(body=body, type_ignores=[])
    ast.fix_missing_locations(module)

    if hasattr(ast, "unparse"):
        return ast.unparse(module).strip() + "\n"

    # Fallback if ast.unparse is unavailable.
    lines = ["# Bytecode stub (AST unparse unavailable)"]
    for module in imports:
        lines.append(f"import {module}")
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType) and const.co_name != "<module>":
            lines.append(f"def {const.co_name}():")
            lines.append("    pass")
    return "\n".join(lines) + "\n"


def load_code_object(pyc_path, header_size):
    with open(pyc_path, "rb") as handle:
        data = handle.read()

    if header_size <= 0 or header_size >= len(data):
        raise ValueError("Invalid .pyc header size")

    return marshal.loads(data[header_size:])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to .pyc file")
    parser.add_argument("--header-size", type=int, default=0)
    args = parser.parse_args()

    result = {
        "success": False,
        "sourceCode": None,
        "decompiler": "unknown",
        "errors": [],
        "warnings": []
    }

    source, errors, warnings = run_uncompyle6(args.file)
    if source:
        result["success"] = True
        result["sourceCode"] = source
        result["decompiler"] = "uncompyle6"
        result["warnings"] = warnings
        print(json.dumps(result))
        return

    if errors:
        result["warnings"].extend(errors)

    try:
        code_obj = load_code_object(args.file, args.header_size)
        source = build_stub_source(code_obj)
        result["success"] = True
        result["sourceCode"] = source
        result["decompiler"] = "unknown"
        result["warnings"].append(
            "Fallback stub generated from bytecode (uncompyle6 unavailable or failed)."
        )
    except Exception as exc:
        result["errors"].append(str(exc))

    print(json.dumps(result))


if __name__ == "__main__":
    main()
