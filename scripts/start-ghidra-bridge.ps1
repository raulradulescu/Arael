<#
.SYNOPSIS
  Start Ghidra on Windows with the Arael ghidra-bridge post-script.

.PARAMETER GhidraPath
  Optional path to a Ghidra installation (folder containing ghidraRun.bat).

.PARAMETER Python
  Optional path to Python executable to use for ghidra-bridge checks.

.PARAMETER NoVerify
  Skip verification of python/ghidra-bridge (useful for CI or when already satisfied).

.EXAMPLE
  .\scripts\start-ghidra-bridge.ps1 -GhidraPath "C:\ghidra_12.0_PUBLIC"

Notes:
- Uses GHIDRA_PATH env or parses the Windows section of .env if present.
- Sets ARAEL_PYTHON and GHIDRA_BRIDGE_PORT for the launched Ghidra process.
- Bridge ALWAYS runs on port 4768 (Arael's required port - NOT configurable).
#>

[CmdletBinding()]
param(
    [Parameter()][string]$GhidraPath,
    [Parameter()][string]$Python,
    [Parameter()][switch]$NoVerify
)


# ENFORCE: Always use port 4768 (Arael's required bridge port)
$Port = 4768

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvFromDotEnv {
    <#
    .SYNOPSIS
    Parse .env file and extract value from Windows section.
    #>
    param([Parameter(Mandatory)][string]$Key)
    
    $envPath = Join-Path $PSScriptRoot '..\.env'
    if (-not (Test-Path $envPath)) { return $null }
    
    $lines = Get-Content $envPath
    $inWindowsSection = $false
    
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        
        # Detect section headers
        if ($trimmed -match '^\s*#\s*Windows\s*$') {
            $inWindowsSection = $true
            continue
        }
        if ($trimmed -match '^\s*#\s*(WSL|Linux|macOS|Default)') {
            $inWindowsSection = $false
            continue
        }
        
        # Parse key=value in Windows section
        if ($inWindowsSection -and $trimmed -match '^([A-Za-z0-9_]+)\s*=\s*(.+)$') {
            if ($Matches[1] -eq $Key) {
                return $Matches[2].Trim().Trim('"').Trim("'")
            }
        }
    }
    
    return $null
}

# Resolve Ghidra path (priority: parameter > env var > .env)
if (-not $GhidraPath) {
    $GhidraPath = if ($env:GHIDRA_PATH) { 
        $env:GHIDRA_PATH 
    } else { 
        Get-EnvFromDotEnv -Key 'GHIDRA_PATH' 
    }
}

if (-not $GhidraPath) {
    throw "Ghidra path not provided. Set -GhidraPath, GHIDRA_PATH env var, or add to .env (# Windows section)."
}

try {
    $GhidraPath = (Resolve-Path $GhidraPath).ProviderPath
} catch {
    throw "Ghidra path '$GhidraPath' does not exist."
}

$ghidraRun = Join-Path $GhidraPath 'ghidraRun.bat'
if (-not (Test-Path $ghidraRun)) {
    throw "ghidraRun.bat not found at '$ghidraRun'. Verify GHIDRA_PATH points to a valid Ghidra installation."
}

# Resolve Python (priority: parameter, env var, .env, PATH)
if (-not $Python) {
    $Python = if ($env:ARAEL_PYTHON) {
        $env:ARAEL_PYTHON
    } elseif ($dotEnvPython = Get-EnvFromDotEnv -Key 'ARAEL_PYTHON') {
        $dotEnvPython
    } elseif ($pyCmd = Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $pyCmd.Path
    }
}

if (-not $Python) {
    Write-Warning "Python not found. Ghidra bridge requires Python with ghidra-bridge installed. Set -Python or ARAEL_PYTHON."
}

# Locate Arael scripts directory
$scriptPath = Join-Path $PSScriptRoot '..\src\ghidra\scripts' | Resolve-Path -ErrorAction SilentlyContinue
if (-not $scriptPath) {
    Write-Warning "Could not find src/ghidra/scripts. Bridge auto-start may fail."
}

$startScript = if ($scriptPath) { Join-Path $scriptPath 'start_bridge.py' }
if ($startScript -and -not (Test-Path $startScript)) {
    Write-Warning "start_bridge.py not found. Bridge will not auto-start."
    $startScript = $null
}

# Verify ghidra-bridge is installed
if (-not $NoVerify -and $Python) {
    Write-Verbose "Verifying ghidra-bridge installation..."
    $checkResult = & $Python -c @'
try:
    import ghidra_bridge
    print('OK')
except ImportError:
    print('MISSING')
    exit(1)
'@ 2>$null

    if ($LASTEXITCODE -ne 0) {
        Write-Warning @"
ghidra-bridge not installed in Python ($Python).
Install with: $Python -m pip install ghidra-bridge
"@
    } else {
        Write-Host "[OK] $checkResult" -ForegroundColor Green
    }
}

# Set ARAEL_PYTHON and GHIDRA_BRIDGE_PORT for Ghidra scripts
if ($Python) { 
    $env:ARAEL_PYTHON = $Python 
    Write-Verbose "Set ARAEL_PYTHON=$Python"
}

# ENFORCE: Bridge must run on port 4768 (Arael requirement)
$env:GHIDRA_BRIDGE_PORT = '4768'
Write-Host "Bridge port: 4768 (enforced)" -ForegroundColor Cyan

# Build Ghidra arguments
$ghidraArgs = @()
if ($scriptPath) { 
    $ghidraArgs += '-scriptPath', $scriptPath 
}
if ($startScript) { 
    $ghidraArgs += '-postScript', 'start_bridge.py' 
}

# Launch Ghidra
Write-Host "`nStarting Ghidra..." -ForegroundColor Cyan
Write-Host "  Path: $GhidraPath" -ForegroundColor Gray
Write-Host "  Bridge Port: 4768 (ENFORCED)" -ForegroundColor Yellow
if ($ghidraArgs.Count -gt 0) {
    Write-Host "  Args: $($ghidraArgs -join ' ')" -ForegroundColor Gray
}

try {
    $proc = Start-Process -FilePath $ghidraRun -ArgumentList $ghidraArgs -PassThru
    Write-Host "`n[OK] Ghidra started (PID: $($proc.Id))" -ForegroundColor Green
    Write-Host "  Bridge will listen on 0.0.0.0:4768" -ForegroundColor Gray
    Write-Host "  Connect via: 127.0.0.1:4768" -ForegroundColor Gray
} catch {
    throw "Failed to start Ghidra: $_"
}