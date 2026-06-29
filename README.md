# Arael

**A reverse-engineering assistant built on Ghidra and PyGhidra**

[![Version](https://img.shields.io/badge/version-3.0.4-blue)]()
[![Tests](https://img.shields.io/badge/tests-288%20(183%20unit%20%2B%20105%20integration)-brightgreen)]()
[![Ghidra](https://img.shields.io/badge/Ghidra-12.0%2B-blue)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)]()
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-blue)]()

Arael runs static binary analysis through Ghidra and returns structured results. Use it from the command line, an interactive shell, or as an MCP server for an AI client such as Claude Code.

> Bachelor's thesis project by Raul Radulescu, 2026.

## What Arael does

- Analyzes executables: metadata, functions, pseudocode, strings, imports, exports, call relationships, packing, and hashes.
- Decompiles/disassembles individual functions, finds cross-references, and builds call graphs.
- Extracts IOCs and suspicious behaviors, and maps them to a curated subset of MITRE ATT&CK.
- Scans with built-in, ReversingLabs, or custom YARA rules.
- Produces standalone HTML reports and caches results in SQLite.
- Answers questions about an analysis through cloud or local LLMs (`ask`).
- Benchmarks Arael and external AI agents against binary corpora (`benchmark`, `benchmark-agents`).

Arael performs **static** analysis and does not intentionally execute the target. Still handle untrusted files in an isolated VM — parsers process attacker-controlled input.

## Requirements

| Component | Version | Purpose |
|---|---:|---|
| Node.js | 20+ | CLI and MCP server |
| Python | 3.10+ | PyGhidra scripts |
| PyGhidra | 3.0+ | Python access to Ghidra |
| Ghidra | 12.0+ | Decompilation and analysis |
| JDK | 21 (64-bit) | Required by current Ghidra |
| Git | current | Clone the repository |

**Optional:** `yara` (native scanning; falls back to pattern matching), `ghidra-bridge` (live-bridge mode; not needed for headless), an OpenAI/Anthropic/Google key or Ollama server (for `ask`), and Claude Code/Codex/Antigravity/Ollama (for `benchmark-agents`).

Sources: [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases) · [PyGhidra](https://pypi.org/project/pyghidra/) · [Node.js](https://nodejs.org/en/download) · [Python](https://www.python.org/downloads/)

## Installation

Ghidra and Arael are **separate** applications — do not install Arael into the Ghidra directory or as a Ghidra extension. The key requirements are: `GHIDRA_PATH` points to the extracted Ghidra root (the one containing `support/analyzeHeadless[.bat]`), `ARAEL_PYTHON` points to the Python with `pyghidra` installed, and MCP config uses absolute paths (no `~`).

```bash
# 1. JDK 21 (verify)
java -version

# 2. Ghidra: download an official release ZIP (not the source archive),
#    extract to a permanent path, run ghidraRun once to confirm Java is found.

# 3. Clone Arael
git clone https://github.com/raulradulescu/arael.git
cd arael

# 4. Python env + PyGhidra
python3 -m venv .venv            # Windows: py -3 -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install "pyghidra>=3.0"
python -c "import pyghidra; print(pyghidra.__file__)"

# 5. Build (and optionally link as a global command)
npm install
npm run build
npm link          # enables `arael`, `arael-mcp`, `arael-check`
```

Without `npm link`, replace `arael` in examples with `node /absolute/path/to/Arael/dist/cli/index.js`. macOS users may need to build Ghidra's native components (see Ghidra's Getting Started guide).

## Configuration

Set `GHIDRA_PATH` and `ARAEL_PYTHON` either in a repo-local `.env` (loaded from the current working directory) or as OS-level environment variables (needed when running a globally linked `arael` from other directories).

```env
# Windows
GHIDRA_PATH=C:\Tools\ghidra_<version>_PUBLIC
ARAEL_PYTHON=C:\Tools\Arael\.venv\Scripts\python.exe

# Linux / macOS
GHIDRA_PATH=/opt/ghidra_<version>_PUBLIC
ARAEL_PYTHON=/home/you/tools/Arael/.venv/bin/python
```

A single `.env` can hold defaults plus `# WSL` and `# Windows` sections; later platform sections override earlier defaults. In WSL, use a Linux-created venv (a Windows venv cannot run as native WSL Python).

### Selected environment variables

| Variable | Meaning | Default |
|---|---|---|
| `GHIDRA_PATH` | Extracted Ghidra root | Required (headless) |
| `ARAEL_PYTHON` | Python containing PyGhidra | `python` / `python3` |
| `GHIDRA_BRIDGE_HOST` / `_PORT` | Optional bridge endpoint | `127.0.0.1` / `4768` |
| `ARAEL_USE_SYSTEM_STRINGS` | `1` to prefer system `strings` | Unset |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_API_KEY` (or `GEMINI_API_KEY`) | Enable `ask` providers | Unset |
| `OLLAMA_HOST` / `OLLAMA_MODEL` | Ollama URL / default model | `http://localhost:11434` / provider default |

Keep API keys in `.env` or the OS environment; never commit them.

## Verify and first analysis

```bash
npm run build
node dist/cli/check.js          # or: arael-check
```

The checker verifies Node.js, `GHIDRA_PATH`, `analyzeHeadless`, Python, PyGhidra, Java, and the optional bridge. Then try a binary:

```bash
arael context  /absolute/path/to/binary                 # security + functionality overview
arael functions /abs/path --exclude-thunks --exclude-external
arael decompile /abs/path --function main
arael xrefs    /abs/path --address 0x401000 --direction both
arael report   /abs/path --output analysis.html --open
```

Quote paths with spaces. The first analysis is slower (Ghidra startup); later calls reuse the cache.

## CLI commands

Every command supports `arael <command> --help`. Summary:

| Command | Purpose |
|---|---|
| `analyze` | Full Ghidra analysis with caching (`--force`, `--output json\|summary`) |
| `context` | Classification, behaviors, IOCs, ATT&CK, key functions (`--json`) |
| `ask` | Ask a configured LLM about a binary (`--provider`, `--model`) |
| `functions` | List/filter functions (`--filter`, `--exclude-thunks/-external`) |
| `decompile` / `disassemble` | Pseudocode / assembly for one function or address |
| `strings` | Extract printable strings (`--min-length`, `--with-xrefs`) |
| `imports` / `exports` | Symbols plus capability/risk metadata |
| `xrefs` | References to/from an address or function (`--direction`) |
| `callgraph` | Call graph as `json`, `dot`, or `mermaid` (`--root`, `--depth`) |
| `hexdump` | Bytes from an address or file offset (`--length`) |
| `yara` | Scan with builtin/ReversingLabs/custom rules (`--list-rules`, `--json`) |
| `report` | Standalone HTML report (also `--from-json`, `--from-cache`) |
| `shell` | Interactive analysis session for one binary |
| `batch` | Analyze files by glob (`--output`, `--summary`, `--force`) |
| `cache` | Inspect, export, or clear cached analyses |
| `benchmark` | Benchmark Arael against a corpus + optional ground truth |
| `benchmark-agents` | Compare external AI agents with and without Arael MCP |

Providers for `ask` are `openai`, `anthropic`, `google`, `ollama`; built-in question templates include `malicious`, `purpose`, `main`, `network`, `persistence`, `credentials`, `evasion`, `iocs`, `summary`. `report --from-json/--from-cache` and `cache` operations do not start Ghidra.

### `benchmark-agents`

Runs an agent matrix over a directory of challenges and grades results.

| Option | Meaning |
|---|---|
| `--agents <spec>` | Comma-separated `engine:model`; append `+arael` to attach MCP |
| `--runs` / `--concurrency` / `--timeout` | Repeats / parallel processes / per-run seconds (default 1800) |
| `--ground-truth <file>` | JSON mapping challenge IDs to expected flags |
| `--pricing <file>` | Token pricing for estimated USD cost |
| `--prompt <file>` | Prompt used for each run |
| `--force` | Ignore cached per-cell records |
| `--extract-archives` / `--archive-password` / `--extract-output` | Archive handling |
| `--max-challenges <n>` | Limit collected challenge directories |
| `--format` / `--output` | `json\|jsonl\|csv\|variant-csv\|markdown\|html` / report path |
| `--arael-server`, `--codex-bin`, `--claude-bin`, `--antigravity-bin`, `--ollama-host` | Overrides |
| `--dry-run` | Show targets/commands without launching agents |

```bash
arael benchmark-agents ./challenges \
  --agents "claude:claude-opus-4-8,claude:claude-opus-4-8+arael,codex:gpt-5.5,codex:gpt-5.5+arael" \
  --ground-truth ./flags.json --runs 2 --concurrency 2 \
  --format html --output ./.arael/benchmark-results/agents.html
```

Artifacts (manifest, stdout, stderr, run records) are written under `<report>.artifacts/`. Ollama runs are local prompt-based baselines. For the methodology and sample reports from real FLARE-On runs, see [docs/benchmark/](docs/benchmark/README.md).

## MCP setup

The server speaks over stdio; the client starts `node` with the absolute path to `dist/mcp/server.js`. For Claude Code, create `.mcp.json` in the workspace:

```json
{
  "mcpServers": {
    "arael": {
      "command": "node",
      "args": ["C:\\Tools\\Arael\\dist\\mcp\\server.js"],
      "env": {
        "GHIDRA_PATH": "C:\\Tools\\ghidra_<version>_PUBLIC",
        "ARAEL_PYTHON": "C:\\Tools\\Arael\\.venv\\Scripts\\python.exe"
      }
    }
  }
}
```

Use native paths on Linux/macOS. Embedding `env` here is more reliable than `.env`, because the client may start the server from a different directory. Restart the client after changing config, then confirm tools like `arael_analyze`, `arael_functions`, `arael_decompile` are visible.

Tools (all take an absolute `filepath`): `arael_analyze`, `arael_functions`, `arael_decompile`, `arael_disassemble`, `arael_strings`, `arael_imports`, `arael_exports`, `arael_xrefs`, `arael_callgraph`, `arael_hexdump`. Several expose richer arguments than the CLI (size filters, address ranges, byte/reference inclusion, output widths, encodings); the client lists each tool's schema.

## Supported files and architectures

| Format | Architectures |
|---|---|
| ELF | x86-64, x86, ARM, AArch64, MIPS, PowerPC, RISC-V |
| PE | x86-64, x86, ARM, AArch64 |
| Mach-O | x86-64, x86, ARM, AArch64, PowerPC |
| MZ / COM | 16-bit x86 (COM must use `.com`) |
| Raw boot sector | 16-bit x86; `.bin` ending in `55 AA` |

Quality depends on Ghidra's loader and processor module. The most exercised paths are x86/x86-64 ELF and PE.

## Cache and output

SQLite cache lives at `~/.arael/cache/analysis.db` (keyed by file hash + version metadata; `--force` re-analyzes). Default outputs: `batch` → `./arael_output/`, `report` → `./report.html`, `benchmark*` HTML without `--output` → `./.arael/benchmark-results/...`, agent artifacts → `<report>.artifacts/`.

## Troubleshooting

- **`GHIDRA_PATH not set` / `analyzeHeadless not found`** — point `GHIDRA_PATH` at the extracted distribution root (containing `support/analyzeHeadless[.bat]`), not the ZIP, `Ghidra/` subdir, or a source checkout.
- **`pyghidra not installed`** — install into the exact `ARAEL_PYTHON` interpreter: `"<python>" -m pip install "pyghidra>=3.0"`.
- **Java missing / wrong version** — install 64-bit JDK 21, set `JAVA_HOME`, open a new terminal, check `java -version`.
- **No global `arael`** — `npm run build && npm link`, or use `node dist/cli/index.js`.
- **`.env` works in repo but not elsewhere** — set OS env vars or embed them in the MCP config.
- **MCP tools not visible** — confirm the build, that the path is `dist/mcp/server.js`, absolute paths with escaped backslashes on Windows, `GHIDRA_PATH`/`ARAEL_PYTHON` in the MCP env, then restart the client.
- **Slow analysis** — Ghidra startup/decompilation is expensive; allow 10–60s for ordinary files, longer for large/packed ones; reuse the cache and raise benchmark timeouts.

More detail in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Development

```bash
npm install && npm run build
npm run lint
npm test                 # npm run test:unit | test:integration | test:coverage
```

The suite has 288 tests (183 unit, 105 integration). Integration tests require a working Ghidra/PyGhidra setup; unit tests usually do not. Source is organized under `src/` (`analysis`, `benchmark`, `cache`, `cli`, `ghidra`, `llm`, `mcp`, `output`, `utils`) with tests under `tests/`. See also [Installation notes](docs/INSTALLATION.md) and [Local LLM integration](docs/LOCAL_LLM_PROMPT.md).

## Acknowledgments

My thanks to **Lect. Dr. Cristian Cira** for the detailed and continued feedback that shaped both the direction and the quality of this work, and to **Fineas Silaghi** for his technical help and for patiently working through the hard questions about where to take the project.

Tools and data this project builds on:

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) by the National Security Agency
- [PyGhidra](https://pypi.org/project/pyghidra/) · [MITRE ATT&CK](https://attack.mitre.org/) · [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
- [FLARE-On challenges](https://flare-on.com/) by Mandiant (Google Cloud), used as the agent-benchmark corpus

## License

[MIT](LICENSE)
