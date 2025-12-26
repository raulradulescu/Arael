#!/bin/bash
# Arael Installation Script
# This script sets up Arael and its dependencies

set -e

echo "================================"
echo "    Arael Installation Script   "
echo "================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARAEL_ROOT="$(dirname "$SCRIPT_DIR")"

# Check Node.js
echo "Checking Node.js..."
if ! command -v node &> /dev/null; then
    echo "Error: Node.js not found. Please install Node.js 20+."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    echo "Warning: Node.js version is $NODE_VERSION. Recommended: 20+"
fi
echo "  Node.js: $(node -v)"

# Check Python
echo "Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 not found. Please install Python 3.9+."
    exit 1
fi
echo "  Python: $(python3 --version)"

# Check Java
echo "Checking Java..."
if ! command -v java &> /dev/null; then
    echo "Error: Java not found. Please install Java 17+ (required by Ghidra)."
    exit 1
fi
echo "  Java: $(java -version 2>&1 | head -n1)"

# Check GHIDRA_PATH
echo ""
echo "Checking Ghidra..."
if [ -z "$GHIDRA_PATH" ]; then
    echo "Warning: GHIDRA_PATH not set."
    echo "  Set it with: export GHIDRA_PATH=/path/to/ghidra"
    echo "  You can add this to your ~/.bashrc or ~/.zshrc"
else
    if [ -d "$GHIDRA_PATH" ]; then
        echo "  Ghidra found at: $GHIDRA_PATH"
    else
        echo "  Warning: GHIDRA_PATH is set but directory not found"
    fi
fi

# Install ghidra-bridge
echo ""
echo "Installing ghidra-bridge..."
if python3 -c "import ghidra_bridge" 2>/dev/null; then
    echo "  ghidra-bridge already installed"
else
    pip3 install ghidra-bridge
    echo "  ghidra-bridge installed"
fi

# Install npm dependencies
echo ""
echo "Installing npm dependencies..."
cd "$ARAEL_ROOT"
npm install

# Build TypeScript
echo ""
echo "Building Arael..."
npm run build

# Run checks
echo ""
echo "Running installation check..."
npm run cli -- cache --stats 2>/dev/null || true

echo ""
echo "================================"
echo "    Installation Complete!      "
echo "================================"
echo ""
echo "Next steps:"
echo "  1. Set GHIDRA_PATH if not already set:"
echo "     export GHIDRA_PATH=/path/to/ghidra"
echo ""
echo "  2. Start Ghidra with bridge server:"
echo "     ./scripts/start-ghidra-bridge.sh"
echo ""
echo "  3. Configure Claude Code (add to ~/.config/claude-code/mcp.json):"
echo "     {"
echo "       \"servers\": {"
echo "         \"arael\": {"
echo "           \"command\": \"node\","
echo "           \"args\": [\"$ARAEL_ROOT/dist/mcp/server.js\"],"
echo "           \"env\": { \"GHIDRA_PATH\": \"$GHIDRA_PATH\" }"
echo "         }"
echo "       }"
echo "     }"
echo ""
echo "  4. Verify installation:"
echo "     npx arael-check"
echo ""
