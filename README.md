# Arael

**Reverse Engineering Assistant for Cybersecurity Professionals**

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![Ghidra](https://img.shields.io/badge/Ghidra-12.0-blue)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue)]()

Arael is an MCP (Model Context Protocol) server that bridges Ghidra's powerful binary analysis capabilities with Claude Code. It enables AI-assisted reverse engineering by exposing decompilation, disassembly, and binary analysis through structured JSON APIs.

> **Bachelor's Thesis Project for 2026 by Raul Radulescu**
> **Status:** Phase 1 & 2 Complete ✅ | MVP Functional 🚀

---

## ✨ **What's New in v2.4**

- **New MCP tools**: disassemble, xrefs, exports, and call graph (JSON/DOT/Mermaid)
- **Packing + section heuristics**: entropy checks, packer signatures, RWX/high-entropy flags
- **Import enrichment**: capability tagging + risk levels in analysis output
- **x86 expansion**: 32-bit and 16-bit (MZ/COM/boot sector) load hints
- **Utility upgrades**: system strings fallback and PyInstaller/UPX helpers

---

## Features

### Core Analysis
- **Full Binary Analysis**: ELF/PE/Mach-O/MZ/COM/RAW via Ghidra 12.0
- **Decompilation**: C pseudocode per function (PyGhidra 3.0)
- **Disassembly**: Function or address-range instruction listings
- **Function Listing**: Filters by name/size, optional thunk/external filters
- **String Extraction**: Encoding-aware strings with optional system `strings` fallback
- **Import + Export Listing**: Imports categorized by capability/risk, exports supported
- **Cross-References**: Xrefs to/from specific addresses
- **Call Graphs**: JSON/DOT/Mermaid graph output
- **Hexdump**: VA-aware dump with ELF segment mapping
- **Smart Caching**: SQLite cache keyed by SHA-256

### Security/Heuristics
- **Packing detection**: entropy + packer signatures (UPX, PyInstaller, Themida, etc.)
- **Section analysis**: RWX and high-entropy anomalies
- **Import risk tagging**: network/crypto/process/file I/O capability labels

### Multi-Format Support
| Format | Status | Notes |
|--------|--------|-------|
| ELF | ✅ Fully Supported | x86_64, VA→file offset mapping |
| PE  | ✅ Tested | 32/64-bit Windows executables |
| Mach-O | ✅ Tested | macOS binaries |
| MZ/COM/RAW | ✅ Supported | 16-bit DOS/boot images with load hints |
| ARM | ⏸️ Future | Processor config only |

---

## Quick Start

### Prerequisites

- **Node.js** 20+
- **Python** 3.10+ (with pyghidra)
- **Java** 17+
- **Ghidra** 12.0+ (release install or snap, not source tree)

### Installation

```bash
# Clone the repository
git clone https://github.com/raulradulescu/arael.git
cd arael

# Optional: create a local venv for PyGhidra
python3 -m venv .venv
source .venv/bin/activate
# On Windows: .venv\\Scripts\\activate

# Install Python dependencies (PyGhidra)
pip install pyghidra

# Install Node dependencies
npm install

# Configure environment
cat > .env <<'EOF'
# WSL
GHIDRA_PATH="/path/to/ghidra_12.0_PUBLIC"
ARAEL_PYTHON="/path/to/arael/.venv/bin/python"

# Windows
GHIDRA_PATH="C:\\path\\to\\ghidra_12.0_PUBLIC"
ARAEL_PYTHON="C:\\Python311\\python.exe"
EOF

# The loader auto-selects the WSL/Windows block based on your platform.
# Optional:
#   ARAEL_USE_SYSTEM_STRINGS=1
#   ARAEL_STRINGS_GREP="FLAG|password"

# Build
npm run build

# Run tests
npm test
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
        "GHIDRA_PATH": "/path/to/ghidra_12.0_PUBLIC",
        "ARAEL_PYTHON": "/path/to/python"
      }
    }
  }
}
```

---

## 📖 Usage Examples

### CLI Usage

```bash
# Full analysis
arael analyze ./malware.exe

# List functions matching pattern
arael functions ./binary --filter "^main\."

# Decompile by name or address
arael decompile ./binary --function validate_password
arael decompile ./binary --address 0x140001450

# Extract strings
arael strings ./binary --min-length 6

# List imports with capability detection
arael imports ./binary

# Hexdump with address translation
arael hexdump ./binary --address 0x401000 --length 128

# Cache management
arael cache --stats
arael cache --clear
```

### Slash Commands (Claude Code)

| Command | Usage | Description |
|---------|-------|-------------|
| `/arael` | `/arael ./binary` | Full binary analysis |
| `/decompile` | `/decompile main` | Get C pseudocode |
| `/disasm` | `/disasm 0x401000` | Get assembly |
| `/xrefs` | `/xrefs decrypt` | Cross-references |
| `/callgraph` | `/callgraph main` | Call graph |
| `/strings` | `/strings flag` | Search strings |
| `/imports` | `/imports` | List imports |
| `/hexdump` | `/hexdump 0x401000` | Raw bytes |

### MCP Tools (via Claude Code)

```python
# Analyze a binary
result = await arael_analyze({
    "filepath": "./suspicious.exe"
})

# Decompile a function
code = await arael_decompile({
    "filepath": "./binary",
    "function": "main"
})

# Search for functions
funcs = await arael_functions({
    "filepath": "./binary",
    "filter": { "namePattern": "crypto|aes|encrypt" }
})

# Cross-references and call graph
xrefs = await arael_xrefs({
    "filepath": "./binary",
    "address": "0x401000",
    "direction": "to"
})

graph = await arael_callgraph({
    "filepath": "./binary",
    "format": "dot"
})
```

---

## 🐍 Python Analysis Scripts

### General Analysis

**`analyze_binary.py`** - Comprehensive report
```bash
python scripts/analyze_binary.py analysis.json
```
Shows: metadata, statistics, language detection, top functions, security findings

**`generate_report.py`** - HTML report generator
```bash
python scripts/generate_report.py analysis.json report.html
```
Creates professional HTML report with dark theme

### Search & Discovery

**`search_functions.py`** - Function search
```bash
# Search by pattern
python scripts/search_functions.py analysis.json "validate|check"

# Show full decompilation
python scripts/search_functions.py analysis.json "^main\.main$" --detail
```

**`search_strings.py`** - String search
```bash
# Find flags/secrets
python scripts/search_strings.py analysis.json "FLAG|password|key"

# Categorize results
python scripts/search_strings.py analysis.json "error" --categorize
```

**`decompile_function.py`** - Extract function code
```bash
# By name
python scripts/decompile_function.py analysis.json validate_password

# By address
python scripts/decompile_function.py analysis.json 0x140001450 --output func.c
```

### Security Analysis

**`analyze_imports.py`** - Import analysis & capability detection
```bash
# Basic analysis
python scripts/analyze_imports.py analysis.json

# Detect capabilities (Network, Crypto, File I/O, etc.)
python scripts/analyze_imports.py analysis.json --capabilities

# Export to CSV
python scripts/analyze_imports.py analysis.json --csv imports.csv
```

### CTF & Challenges

**`extract_flag_memory_minder.py`** - CTF flag extractor
```bash
python scripts/extract_flag_memory_minder.py memory_minder_analysis.json
```
Automatically extracts flags from memory_minder-style challenges

### Binary Comparison

**`diff_binaries.py`** - Compare two versions
```bash
python scripts/diff_binaries.py old_version.json new_version.json
```
Shows added/removed/modified functions, strings, and imports

---

## 🎮 Real-World Examples

### Example 1: C Binary with Secrets

```bash
# Analyze
GHIDRA_PATH="..." python dist/ghidra/scripts/run_analysis.py \
    tests/fixtures/complex_example.exe \
    /tmp/complex_analysis.json

# Find secrets
python scripts/search_strings.py /tmp/complex_analysis.json "FLAG|password|secret"
```

**Results:**
```
[0x140005097] "FLAG{test_secret_123}"
[0x1400050d4] "super_secret_password"
```

### Example 2: Go Binary CTF Challenge

```bash
# Analyze 2.5 MB Go binary
GHIDRA_PATH="..." python dist/ghidra/scripts/run_analysis.py \
    tests/fixtures/memory_minder \
    /tmp/memory_minder_analysis.json

# Extract flag
python scripts/extract_flag_memory_minder.py /tmp/memory_minder_analysis.json
```

**Results:**
```
Found 28 rune structures!
🚩 FLAG: HTB{M3M0RY_R3W1D_SNOWGL0B3}
```

---

## MCP Tools Reference

| Tool | Description | Parameters |
|------|-------------|------------|
| `arael_analyze` | Full binary analysis | `filepath`, `force?` |
| `arael_decompile` | Decompile function | `filepath`, `function` |
| `arael_disassemble` | Disassemble function or range | `filepath`, `function?`, `startAddress?`, `length?` |
| `arael_xrefs` | Cross-references to/from address | `filepath`, `address`, `direction?`, `maxResults?` |
| `arael_functions` | List functions | `filepath`, `filter?` |
| `arael_strings` | Extract strings | `filepath`, `minLength?`, `encoding?` |
| `arael_imports` | List imports | `filepath` |
| `arael_exports` | List exports | `filepath`, `filter?` |
| `arael_callgraph` | Call graph (JSON/DOT/Mermaid) | `filepath`, `format?`, `rootFunction?`, `maxDepth?` |
| `arael_hexdump` | Raw byte dump | `filepath`, `start`, `length?`, `width?` |

---

## 🧪 Development

### Running Tests

```bash
# All tests (unit + integration)
npm test

# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration

# With coverage
npm run test:coverage

# Connection test (validates Ghidra setup)
npm run test:connection
```

### Project Structure

```
arael/
├── src/
│   ├── cli/           # CLI entry points
│   ├── mcp/           # MCP server & handlers (analyze, decompile, disassemble, xrefs, callgraph, exports)
│   ├── ghidra/        # Ghidra integration
│   │   ├── scripts/   # PyGhidra scripts (run_analysis, disassemble, xrefs, exports, callgraph)
│   │   ├── bridge.ts  # ghidra-bridge (optional)
│   │   ├── headless.ts # PyGhidra headless mode
│   │   └── connection.ts # Connection manager
│   ├── cache/         # SQLite caching
│   ├── output/        # Schema & builders
│   └── utils/         # Preflight, packing, sections, import-analysis, pyc-decompiler
├── tests/
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   └── fixtures/      # Test binaries
├── scripts/           # Python analysis helpers
└── docs/              # Documentation
```

### Technology Stack

- **Runtime:** Node.js 20 + TypeScript 5.4
- **Analysis:** Ghidra 12.0 + PyGhidra 3.0
- **Cache:** SQLite (better-sqlite3)
- **Testing:** Jest 29.7
- **Python:** 3.10+ (venv recommended for PyGhidra)

---

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md) - Detailed setup instructions
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Local LLM Integration](docs/LOCAL_LLM.md) - Use with Ollama/LM Studio
- [PRD v2.4](PRD_Arael_v2.4.md) - Product requirements & implementation status

---

## 🎯 Roadmap

### ✅ Phase 1: Foundation (Complete)
- Project scaffold with TypeScript & Jest
- PyGhidra 3.0 integration (Ghidra 12.0+)
- Headless mode with run_analysis.py
- SQLite cache implementation
- Preflight validation (ELF/PE/Mach-O)

### ✅ Phase 2: Core Tools (Complete)
- `arael_analyze`, `arael_functions`, `arael_decompile`
- `arael_strings`, `arael_imports`, `arael_hexdump`

### ✅ Phase 3: Advanced Tools (Complete)
- `arael_disassemble`, `arael_xrefs`, `arael_exports`, `arael_callgraph`
- Packing detection (UPX, PyInstaller, 10+ signatures)
- Section analysis (entropy, RWX anomalies)
- Import categorization (12 capability categories)

### ✅ Phase 4: Polish & Docs (Complete)
- Comprehensive error messages
- INSTALLATION.md, TROUBLESHOOTING.md, LOCAL_LLM.md
- .env configuration support

### ✅ Phase 5: Architecture & Bytecode (Complete)
- x86 32-bit architecture support
- x86 16-bit architecture support (DOS/real mode)
- .pyc decompilation (pycdc + uncompyle6 + marshal/dis)

### ⏸️ Phase 6: Publishing (Pending)
- npm package publish
- Claude Code MCP integration testing
- ARM64/ARM32 architecture support

---

## 🏆 Achievements

- **Extensive Test Coverage** (unit + integration suites)
- **Multi-Format Support** (ELF, PE, Mach-O, MZ/COM/RAW)
- **Expanded MCP Surface** (10 tools including callgraph/xrefs/disassemble/exports)
- **CTF Proven** (Successfully solved memory_minder)

---

## 🤝 Contributing

Contributions welcome! This is a thesis project but community improvements are appreciated.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass (`npm test`)
5. Submit a pull request

---

## 📝 License

MIT

---

## 🙏 Acknowledgments

- **Ghidra** by NSA for the incredible reverse engineering framework
- **PyGhidra** for Python integration
- **Claude AI** for development assistance
- **HackTheBox** for the memory_minder challenge

---

**Built with ❤️ for the cybersecurity community**
