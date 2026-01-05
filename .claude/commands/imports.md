# Analyze Imports

Analyze imports for the current binary.

Use the `arael_imports` MCP tool to list all imported functions.

Group by capability:
- Network (socket, connect, send, recv)
- Crypto (AES, SHA, RSA functions)
- File I/O (open, read, write)
- Process (fork, exec, CreateProcess)
- Anti-debug (ptrace, IsDebuggerPresent)
- Registry (Windows only)

Flag dangerous combinations.
