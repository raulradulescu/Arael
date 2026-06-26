# Arael

**Reverse Engineering Assistant for Cybersecurity Professionals**

[![Version](https://img.shields.io/badge/version-3.0.1-blue)]()
[![Tests](https://img.shields.io/badge/tests-271%20passing-brightgreen)]()
[![Ghidra](https://img.shields.io/badge/Ghidra-12.0-blue)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)]()

Arael runs Ghidra analysis and exposes the results as structured JSON. Use it as a CLI, an MCP server for LLMs, or an interactive shell for quick triage.

> **Bachelor's Thesis Project for 2026 by Raul Radulescu**

---

## Why Arael
- One command to analyze a binary with Ghidra
- Clean JSON output for automation, scripts, and LLM prompts
- CLI, MCP server, and interactive shell in one tool

---

## New in v2.6

### LLM Integration
- **`arael context`**: LLM-optimized analysis with classification, behaviors, and IOCs
- **`arael ask`**: Natural language queries using OpenAI, Anthropic, Google (Gemini), or Ollama
- **Behavior Detection**: 25+ rules detecting network, injection, credential theft, ransomware patterns
- **MITRE ATT&CK Mapping**: 36 techniques mapped with confidence scores
- **IOC Extraction**: IPs, domains, URLs, registry keys, file paths, mutexes
- **Binary Classification**: Benign/suspicious/malware with type detection (trojan, stealer, rat, etc.)
- **Import Database**: 483 functions with capability categories and risk levels

```bash
# LLM-ready context
arael context ./malware.exe

# Ask questions using LLM (OpenAI, Anthropic, Google, or Ollama)
arael ask ./binary -q "Is this malicious?"
arael ask ./binary -q malicious -p google

# JSON output for programmatic use
arael context ./binary --json
```

**Output includes:**
- Classification with confidence and reasoning
- Detected behaviors with evidence
- MITRE ATT&CK techniques and tactics
- Extracted IOCs
- Risk assessment
- Suggested analysis steps

### Also in v2.5
- Interactive Shell: `arael shell ./binary`
- Batch Analysis: `arael batch ./samples/*.exe`
- YARA Scanning: 43 built-in + 310 ReversingLabs rules
- HTML Reports: `arael report ./binary`
- ARM64/ARM32 support

---

## Quick Start

### Prerequisites
- Node.js 20+, Python 3.10+, Java 17+, Ghidra 12.0+

### Install and build
```bash
git clone https://github.com/raulradulescu/arael.git
cd arael

# Python setup
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install pyghidra

# Node setup
npm install

# Configure .env
echo 'GHIDRA_PATH="/path/to/ghidra_12.0_PUBLIC"' > .env
echo 'ARAEL_PYTHON="/path/to/.venv/bin/python"' >> .env

# Optional: Add LLM API keys for 'arael ask' command
echo 'OPENAI_API_KEY=sk-...' >> .env
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env
echo 'GOOGLE_API_KEY=AIza...' >> .env

# Build
npm run build
```

### First run
```bash
# Fast overview for LLMs or humans
arael context ./binary

# Full JSON analysis
arael analyze ./binary
```

### Optional: Configure Claude Code
Add to `~/.config/claude-code/mcp.json`:
```json
{
  "servers": {
    "arael": {
      "command": "node",
      "args": ["/path/to/arael/dist/mcp/server.js"],
      "env": {
        "GHIDRA_PATH": "/path/to/ghidra",
        "ARAEL_PYTHON": "/path/to/python"
      }
    }
  }
}
```

---

## Usage

### CLI (common workflows)
```bash
# Core analysis
arael analyze ./binary
arael functions ./binary --filter "^main"
arael decompile ./binary --function main
arael disassemble ./binary --function main

# Data extraction
arael strings ./binary --min-length 6
arael imports ./binary
arael exports ./binary

# Flow analysis
arael xrefs ./binary --address 0x401000
arael callgraph ./binary --format mermaid --root main

# Utilities
arael hexdump ./binary --address 0x401000 --length 128
arael yara ./binary
arael report ./binary --output report.html
arael report --from-json ./analysis.json --output report.html
arael report --from-cache <row-id-or-sha256> --output report.html --open
arael cache --list
arael benchmark-agents ./challenges --format html --output agent-run.html

# LLM queries (v2.6)
arael ask ./binary -q "Is this malicious?"
arael ask ./binary -q summary -p ollama
arael ask --list-templates

# Interactive and batch
arael shell ./binary
arael batch "./samples/*.exe" --output ./results
```

### MCP tools (for LLMs)
```python
# LLM-optimized context (v2.6)
context = await arael_context({"filepath": "./binary"})
# Returns: classification, behaviors, iocs, mitreAttack, riskAssessment

# Full analysis
result = await arael_analyze({"filepath": "./binary"})

# Decompile
code = await arael_decompile({"filepath": "./binary", "function": "main"})

# Cross-references
xrefs = await arael_xrefs({"filepath": "./binary", "address": "0x401000"})
```

### Slash commands (Claude Code)

| Command | Description |
|---------|-------------|
| `/arael` | Full binary analysis |
| `/decompile` | Decompile function |
| `/disasm` | Disassemble |
| `/xrefs` | Cross-references |
| `/callgraph` | Call graph |
| `/strings` | Search strings |
| `/imports` | List imports |
| `/hexdump` | Raw bytes |

---

## Command Reference

### Core Analysis
| Command | Description | Output |
|---------|-------------|--------|
| `analyze` | Full Ghidra analysis | JSON: binary, functions[], strings[], imports[], exports[] |
| `context` | LLM-optimized context (v2.6) | JSON: classification, behaviors[], mitreAttack{}, iocs{}, riskAssessment |
| `ask` | Ask LLM questions (v2.6) | LLM response with analysis context |
| `functions` | List functions | JSON array: name, address, size |
| `decompile` | C pseudocode | String: decompiled code |
| `disassemble` | Assembly listing | JSON array: instructions |
| `strings` | Extract strings | JSON array: value, address, xrefs[] |
| `imports` | Import analysis | JSON: by library with categories, risk levels |
| `exports` | Export listing | JSON array: name, address, type |
| `xrefs` | Cross-references | JSON array: from/to address, type |
| `callgraph` | Call graph | JSON/DOT/Mermaid |
| `hexdump` | Byte dump | Formatted hex/ASCII |
| `yara` | Pattern scanning | JSON: rule matches |
| `shell` | Interactive REPL | Commands: decompile, disasm, xrefs, etc. |
| `batch` | Multi-binary analysis | JSON files per binary |
| `report` | HTML report | Standalone HTML |

### Reports and Cache
`arael report` can render from a binary, a saved `AnalysisResult` JSON file, or the
SQLite analysis cache. Cached and JSON reports do not start Ghidra.

```bash
arael report ./binary -o report.html
arael report --from-json ./analysis.json -o report.html
arael report --from-cache <row-id|cache-key|sha256|path> -o report.html --open
arael report ./binary --cache-only -o report.html
```

Cache inspection:
```bash
arael cache --stats
arael cache --list --limit 50
arael cache --show <identifier> --json
arael cache --export <identifier> -o analysis.json
```

Benchmark reports support HTML:
```bash
arael benchmark ./samples --format html -o benchmark.html
arael benchmark-agents ./challenges --format html -o agent-benchmark.html
```

### Security Analysis (v2.6)
- **Behavior Detection**: Network client/server, process injection, credential theft, persistence, anti-debug, keylogging, file encryption
- **MITRE ATT&CK**: T1055 (Injection), T1547.001 (Registry Run Keys), T1071 (C2), T1486 (Ransomware), T1555 (Credentials), etc.
- **IOC Extraction**: IPv4/IPv6, domains, URLs, emails, file paths, registry keys, mutexes, user agents
- **Import Risk**: 483 functions categorized (Network, Crypto, Process, Injection, AntiDebug, Persistence)
- **Packing Detection**: UPX, PyInstaller, Themida, VMProtect + entropy analysis

### Multi-Format Support
| Format | Architectures |
|--------|---------------|
| ELF | x86_64, x86, ARM64, ARM32, MIPS, RISC-V |
| PE | x86_64, x86, ARM64, ARM32 |
| Mach-O | x86_64, ARM64 (Apple Silicon) |
| MZ/COM/RAW | 16-bit DOS, boot sectors |

---

## YARA Scanning

| Rule Set | Rules | Description |
|----------|-------|-------------|
| builtin | 43 | Packers, crypto, shellcode, evasion |
| reversinglabs | 310 | Malware families (optional) |
| all | 353 | Combined |

```bash
arael yara ./binary                      # Built-in rules
arael yara ./binary --ruleset all        # All rules
arael yara ./binary --category ransomware
```

---

## Development

```bash
npm test              # All tests
npm run test:unit     # Unit only
npm run test:integration
npm run test:coverage
```

### Project Structure
```
arael/
├── src/
│   ├── analysis/     # v2.6: behavior-detector, ioc-extractor, mitre-mapper, import-database, string-xrefs
│   ├── llm/          # v2.6: LLM providers (OpenAI, Anthropic, Google, Ollama), prompts
│   ├── cli/          # CLI commands including context and ask
│   ├── mcp/          # MCP server & handlers
│   ├── ghidra/       # Ghidra integration
│   ├── cache/        # SQLite caching
│   └── utils/        # Packing, preflight, YARA
├── tests/
└── docs/             # LOCAL_LLM_PROMPT.md/.xml
```

---

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Local LLM Integration](docs/LOCAL_LLM_PROMPT.md) - System prompts for Ollama/llama.cpp
- [PRD v2.6](docs/PRD_Arael_v2.6.md) - Product requirements

---

## Roadmap

### Complete (v2.6)
- **Phase 1-2**: Foundation, PyGhidra, core tools
- **Phase 3**: Advanced tools (xrefs, callgraph, disassemble)
- **Phase 4**: Packing detection, import categorization
- **Phase 5**: x86 16/32-bit, .pyc decompilation
- **Phase 6**: Interactive shell, batch, YARA, reports, ARM
- **Phase 7**: LLM Context Layer - context command, behaviors, MITRE, IOCs
- **Phase 8**: `arael ask` - Natural language queries with LLM providers

---

## Acknowledgments

- **Ghidra** by NSA
- **PyGhidra** for Python integration
- **ReversingLabs** for [YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
- **MITRE ATT&CK** for technique framework

---

**MIT License** | Built for the cybersecurity community
