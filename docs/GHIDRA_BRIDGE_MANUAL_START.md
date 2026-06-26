# How to Start Ghidra Bridge for Arael (Windows)

## Problem
The `-postScript` option may not execute scripts properly in Ghidra GUI mode.

## Solution: Manual Bridge Startup

### Option 1: Run Script from Ghidra GUI (RECOMMENDED)

1. **Start Ghidra normally:**
   ```powershell
   .\ghidra-master\ghidra_12.0_PUBLIC\ghidraRun.bat
   ```

2. **Set environment variable** (in PowerShell BEFORE starting Ghidra):
   ```powershell
   $env:GHIDRA_BRIDGE_PORT = '4768'
   ```

3. **In Ghidra GUI:**
   - Go to **Window → Script Manager**
   - In the filter box, type: `start_bridge`
   - Find `start_bridge.py` in the list
   - Double-click or click **Run Script** button
   - Check console for success message

4. **Verify bridge is running:**
   ```powershell
   Test-NetConnection -ComputerName 127.0.0.1 -Port 4768
   ```
   Should show `TcpTestSucceeded: True`

### Option 2: Use Headless Mode (Alternative)

If GUI script doesn't work, Arael will automatically fall back to headless mode.
No bridge needed - but slower for repeated operations.

### Option 3: Python Script to Start Bridge

Create a Windows batch file to set environment and start Ghidra:

```bat
@echo off
set GHIDRA_BRIDGE_PORT=4768
set ARAEL_PYTHON=C:\Python313\python.exe
start "Ghidra" "C:\path\to\ghidra_12.0_PUBLIC\ghidraRun.bat"
echo.
echo After Ghidra opens:
echo 1. Go to Window -^> Script Manager
echo 2. Run start_bridge.py
echo.
pause
```

## Verifying Bridge is Working

```powershell
# Test connection
Test-NetConnection 127.0.0.1 -Port 4768

# If successful, test Arael
arael analyze path\to\binary.exe
```

## Troubleshooting

### Bridge not starting from Script Manager

1. Check Ghidra console for errors
2. Verify ghidra-bridge is installed:
   ```powershell
   python -c "import ghidra_bridge; print('OK')"
   ```
3. Install if missing:
   ```powershell
   pip install ghidra-bridge
   ```

### Port already in use

```powershell
# Find what's using port 4768
netstat -ano | findstr "4768"

# Kill the process (replace PID)
taskkill /PID <PID> /F
```

### Script not appearing in Script Manager

1. Verify script location: `src\ghidra\scripts\start_bridge.py`
2. In Ghidra: Script Manager → Manage Script Directories
3. Add the `src\ghidra\scripts` directory
4. Click Refresh button

## Quick Reference

| Command | Purpose |
|---------|---------|
| `Test-NetConnection 127.0.0.1 -Port 4768` | Check if bridge is running |
| `Get-Process java \| Stop-Process -Force` | Stop all Ghidra instances |
| `arael analyze <file>` | Use Arael with bridge |

## Why This Happens

Ghidra's `-postScript` option is designed for headless analysis mode (`analyzeHeadless`), not GUI mode. When Ghidra opens in GUI mode, post-scripts may not execute automatically. The manual approach ensures the bridge starts reliably.
