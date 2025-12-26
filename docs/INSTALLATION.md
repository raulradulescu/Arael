# Arael Installation Guide

## Prerequisites

Before installing Arael, ensure you have the following:

| Requirement | Version | Notes |
|-------------|---------|-------|
| Node.js | 20.x+ | LTS recommended |
| Python | 3.9+ | For ghidra-bridge |
| Java | 17+ | Required by Ghidra |
| Ghidra | 11.0+ | Must be installed separately |

## Step 1: Install Ghidra

Download Ghidra from the official NSA GitHub repository:

```bash
# Download Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip

# Extract
unzip ghidra_11.0_PUBLIC_20231222.zip

# Set environment variable
export GHIDRA_PATH=$PWD/ghidra_11.0_PUBLIC

# Add to your shell profile (~/.bashrc or ~/.zshrc)
echo 'export GHIDRA_PATH=/path/to/ghidra_11.0_PUBLIC' >> ~/.bashrc
```

### WSL (snap)

If you installed Ghidra via snap in WSL:

```bash
sudo snap install ghidra
export GHIDRA_PATH=/snap/ghidra/current/ghidra_11.4_PUBLIC
echo 'export GHIDRA_PATH=/snap/ghidra/current/ghidra_11.4_PUBLIC' >> ~/.bashrc
```

## Step 2: Install ghidra-bridge

```bash
pip install ghidra-bridge
```

## Step 3: Install Arael

### From npm (recommended)

```bash
npm install -g arael-re
```

### From source

```bash
git clone https://github.com/yourusername/arael.git
cd arael
npm install
npm run build
```

## Step 4: Configure Claude Code

Add Arael as an MCP server in Claude Code's configuration:

**Location:** `~/.config/claude-code/mcp.json` (Linux/Mac) or `%APPDATA%/claude-code/mcp.json` (Windows)

```json
{
  "servers": {
    "arael": {
      "command": "arael-mcp",
      "env": {
        "GHIDRA_PATH": "/path/to/ghidra_11.0_PUBLIC"
      }
    }
  }
}
```

Or if installed from source:

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

## Step 5: Verify Installation

```bash
arael-check
```

This will verify:
- Node.js version
- Python availability
- ghidra-bridge installation
- Ghidra path configuration
- Java availability

## Step 6: Start Ghidra Bridge (Optional)

For faster analysis, start Ghidra with the bridge server:

```bash
arael-start-ghidra
# Or from source:
./scripts/start-ghidra-bridge.sh
```

Keep this terminal open. The bridge server provides:
- Persistent Ghidra connection
- ~100ms query latency (vs 15-60s for headless mode)

## Usage Modes

### Bridge Mode (Recommended)

1. Start Ghidra with bridge server
2. Load your target binary in Ghidra
3. Use Arael commands - queries are instant

### Headless Mode (Automatic Fallback)

If the bridge is not available, Arael automatically falls back to headless mode:
- No need to start Ghidra manually
- Each analysis takes 15-60 seconds
- Results are cached for subsequent queries

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_PATH` | Path to Ghidra installation | Required |
| `GHIDRA_BRIDGE_HOST` | Bridge server host | `127.0.0.1` |
| `GHIDRA_BRIDGE_PORT` | Bridge server port | `4768` |
| `GHIDRA_VERSION` | Override Ghidra version in cache | Auto-detect |
| `ARAEL_PYTHON` | Python interpreter for ghidra-bridge | `python3` (Linux), `python` (Windows) |
| `ARAEL_USE_SYSTEM_STRINGS` | Use system `strings` tool instead of Ghidra for extraction | `0` |
| `ARAEL_STRINGS_GREP` | Regex pattern to filter strings (uses `grep -E` when available) | unset |

## Next Steps

- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions
- [Local LLM Integration](LOCAL_LLM.md) - Using Arael with local LLMs
