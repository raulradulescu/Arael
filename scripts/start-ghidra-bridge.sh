#!/bin/bash
# Start Ghidra with ghidra-bridge server
# Usage: ./start-ghidra-bridge.sh [GHIDRA_PATH]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARAEL_ROOT="$(dirname "$SCRIPT_DIR")"

# Use provided path or environment variable
GHIDRA_PATH="${1:-$GHIDRA_PATH}"

if [ -z "$GHIDRA_PATH" ]; then
    echo "Error: GHIDRA_PATH not set"
    echo "Usage: $0 [GHIDRA_PATH]"
    echo "   or: GHIDRA_PATH=/path/to/ghidra $0"
    exit 1
fi

if [ ! -d "$GHIDRA_PATH" ]; then
    echo "Error: Ghidra not found at $GHIDRA_PATH"
    exit 1
fi

GHIDRA_RUN="$GHIDRA_PATH/ghidraRun"
if [ ! -x "$GHIDRA_RUN" ]; then
    echo "Error: ghidraRun not found or not executable at $GHIDRA_RUN"
    exit 1
fi

# Check if ghidra-bridge is installed
if ! python3 -c "import ghidra_bridge" 2>/dev/null; then
    echo "Error: ghidra-bridge not installed"
    echo "Run: pip install ghidra-bridge"
    exit 1
fi

# Create startup script for bridge server
BRIDGE_SCRIPT="$ARAEL_ROOT/src/ghidra/scripts/start_bridge.py"

if [ ! -f "$BRIDGE_SCRIPT" ]; then
    cat > "$BRIDGE_SCRIPT" << 'EOF'
# start_bridge.py - Start ghidra-bridge server
# Run this in Ghidra's Script Manager or via ghidraRun

import ghidra_bridge_server

print("[Arael] Starting ghidra-bridge server on localhost:4768...")
server = ghidra_bridge_server.GhidraBridgeServer(
    address=("127.0.0.1", 4768),
    background=True
)
print("[Arael] Bridge server started. Ready for connections.")
print("[Arael] Keep this Ghidra instance running to accept queries.")
EOF
fi

echo "[Arael] Starting Ghidra with bridge server..."
echo "[Arael] Script path: $ARAEL_ROOT/src/ghidra/scripts"
echo ""

# Start Ghidra with the bridge script
"$GHIDRA_RUN" \
    -scriptPath "$ARAEL_ROOT/src/ghidra/scripts" \
    -postScript start_bridge.py

echo ""
echo "[Arael] Ghidra closed."
