# Arael

**Reverse Engineering Assistant for Cybersecurity Professionals**

Arael is an MCP (Model Context Protocol) server that bridges Ghidra's powerful binary analysis capabilities with Claude Code. It enables AI-assisted reverse engineering by exposing decompilation, disassembly, and binary analysis through structured JSON APIs.

> Bachelor's Thesis Project for 2026 by Raul Radulescu

## Features

- **Full Binary Analysis**: Analyze ELF x86_64 binaries with Ghidra's auto-analysis
- **Decompilation**: Get C pseudocode for any function
- **Function Listing**: List all functions with filtering options
- **String Extraction**: Extract strings with cross-references
- **Import Analysis**: View imported functions grouped by library
- **Hexdump**: Dump raw bytes at any address
- **Caching**: Results are cached for fast subsequent queries

## Quick Start

### Prerequisites

- Node.js 20+
- Python 3.9+
- Java 17+
- Ghidra 11.0+

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/arael.git
cd arael

# Set Ghidra path
export GHIDRA_PATH=/path/to/ghidra_11.0_PUBLIC

# Install dependencies
pip install ghidra-bridge
npm install

# Build
npm run build

# Verify installation
npx arael-check
```

### Configure Claude Code

Add to `~/.config/claude-code/mcp.json`:

```json
{
  "servers": {
    "arael": {
      "command": "node",
      "args": ["/path/to/arael/dist/mcp/server.js"],
      "env": {
        "GHIDRA_PATH": "/path/to/ghidra_11.0_PUBLIC"
      }
    }
  }
}
```

### Start Ghidra Bridge (Optional, for faster queries)

```bash
./scripts/start-ghidra-bridge.sh
```

### Use in Claude Code

```
> /arael ./suspicious_binary

I've analyzed the binary. Here's what I found:
- Entry point: 0x401000 (_start)
- 47 functions identified
- Suspicious imports: ptrace (anti-debug?), mmap (shellcode?)

Would you like me to decompile any specific function?
```

## CLI Usage

Arael also provides a CLI for direct use or with local LLMs:

```bash
# Full analysis
arael analyze ./binary

# List functions
arael functions ./binary --filter "^check_"

# Decompile a function
arael decompile ./binary --function main

# Extract strings
arael strings ./binary --min-length 6 --with-xrefs

# List imports
arael imports ./binary

# Hexdump
arael hexdump ./binary --address 0x401000 --length 128

# Cache management
arael cache --stats
arael cache --clear
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `arael_analyze` | Full binary analysis |
| `arael_decompile` | Decompile specific function |
| `arael_functions` | List functions with filters |
| `arael_strings` | Extract strings |
| `arael_imports` | List imports |
| `arael_hexdump` | Raw byte dump |

## Scope (v1.0)

| Aspect | Supported |
|--------|-----------|
| Format | ELF only |
| Architecture | x86_64 only |
| Analysis | Static only |

Future versions will add PE, Mach-O, and ARM support.

## Development

```bash
# Run tests
npm test

# Run only unit tests
npm run test:unit

# Run with coverage
npm run test:coverage

# Lint
npm run lint
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Local LLM Integration](docs/LOCAL_LLM.md)

## License

MIT
