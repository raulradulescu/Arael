# Hexdump

Hexdump memory at: $ARGUMENTS

Use the `arael_hexdump` MCP tool to show raw bytes.

Arguments: `<address> [length]`
- address: Virtual address (e.g., `0x401000`)
- length: Number of bytes (optional, default 256)

Examples:
- `/hexdump 0x401000` - 256 bytes at address
- `/hexdump 0x401000 64` - 64 bytes at address
