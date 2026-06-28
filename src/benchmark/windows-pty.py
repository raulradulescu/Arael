#!/usr/bin/env python3
"""Run a command in a Windows pseudo-terminal and relay its combined output."""

from __future__ import annotations

import os
import signal
import sys


def main() -> int:
    command = sys.argv[1:]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("windows-pty.py: missing command", file=sys.stderr)
        return 2

    try:
        from winpty import PtyProcess
    except ImportError:
        print(
            "windows-pty.py: pywinpty is required for Antigravity headless runs "
            "(install with: python -m pip install pywinpty)",
            file=sys.stderr,
        )
        return 2

    process = PtyProcess.spawn(
        command,
        cwd=os.getcwd(),
        env=os.environ.copy(),
        dimensions=(40, 160),
    )

    def terminate(_signum: int, _frame: object) -> None:
        if process.isalive():
            process.terminate(force=True)

    signal.signal(signal.SIGINT, terminate)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, terminate)

    try:
        while True:
            try:
                output = process.read(4096)
            except EOFError:
                break
            if output:
                sys.stdout.write(output)
                sys.stdout.flush()
    finally:
        if process.isalive():
            process.wait()

    exit_status = process.exitstatus
    return exit_status if isinstance(exit_status, int) else 1


if __name__ == "__main__":
    raise SystemExit(main())
