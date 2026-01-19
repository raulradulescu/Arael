# Arael v2.5 - Live Demo Script (PowerShell)
# Run sections individually for presentation

param(
    [Parameter(Position=0)]
    [string]$Command = "help",

    [Parameter(Position=1)]
    [string]$BinaryPath = ""
)

$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "=======================================================================" -ForegroundColor Blue
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "=======================================================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-Cmd {
    param([string]$Cmd)
    Write-Host "$ $Cmd" -ForegroundColor Green
}

function Pause-Demo {
    Write-Host ""
    Read-Host "Press Enter to continue"
    Write-Host ""
}

# Demo 1: Version and Help
function Demo-Intro {
    Write-Header "DEMO 1: Arael Introduction"

    Write-Cmd "arael --version"
    arael --version
    Pause-Demo

    Write-Cmd "arael --help"
    arael --help
    Pause-Demo
}

# Demo 2: YARA Scanning
function Demo-Yara {
    param([string]$Binary)

    Write-Header "DEMO 2: YARA Rule Scanning"

    Write-Cmd "arael yara --list-rules"
    arael yara --list-rules
    Pause-Demo

    if ($Binary -and (Test-Path $Binary)) {
        Write-Cmd "arael yara $Binary"
        arael yara $Binary
        Pause-Demo

        Write-Cmd "arael yara $Binary --ruleset all"
        arael yara $Binary --ruleset all
        Pause-Demo
    }
}

# Demo 3: Basic Analysis
function Demo-Analyze {
    param([string]$Binary)

    Write-Header "DEMO 3: Binary Analysis"

    if ($Binary -and (Test-Path $Binary)) {
        Write-Cmd "arael analyze $Binary -o summary"
        arael analyze $Binary -o summary
        Pause-Demo

        Write-Host "Running again to show caching (should be instant):" -ForegroundColor Yellow
        Write-Cmd "arael analyze $Binary -o summary"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        arael analyze $Binary -o summary
        $sw.Stop()
        Write-Host "Time: $($sw.ElapsedMilliseconds)ms" -ForegroundColor Cyan
        Pause-Demo
    }
}

# Demo 4: Function Analysis
function Demo-Functions {
    param([string]$Binary)

    Write-Header "DEMO 4: Function Analysis"

    if ($Binary -and (Test-Path $Binary)) {
        Write-Cmd "arael functions $Binary --exclude-thunks --exclude-external"
        arael functions $Binary --exclude-thunks --exclude-external
        Pause-Demo

        Write-Cmd "arael decompile $Binary --function main"
        arael decompile $Binary --function main
        Pause-Demo
    }
}

# Demo 5: Cross-References
function Demo-Xrefs {
    param([string]$Binary)

    Write-Header "DEMO 5: Cross-References & Call Graph"

    if ($Binary -and (Test-Path $Binary)) {
        Write-Cmd "arael xrefs $Binary --address main"
        arael xrefs $Binary --address main
        Pause-Demo

        Write-Cmd "arael callgraph $Binary --root main --format mermaid --depth 3"
        arael callgraph $Binary --root main --format mermaid --depth 3
        Pause-Demo
    }
}

# Demo 6: Strings and Imports
function Demo-Strings {
    param([string]$Binary)

    Write-Header "DEMO 6: Strings & Import Analysis"

    if ($Binary -and (Test-Path $Binary)) {
        Write-Cmd "arael strings $Binary --min-length 8"
        arael strings $Binary --min-length 8
        Pause-Demo

        Write-Cmd "arael imports $Binary"
        arael imports $Binary
        Pause-Demo
    }
}

# Demo 7: HTML Report
function Demo-Report {
    param([string]$Binary)

    Write-Header "DEMO 7: HTML Report Generation"

    if ($Binary -and (Test-Path $Binary)) {
        $reportPath = "$env:TEMP\demo_report.html"
        Write-Cmd "arael report $Binary --output $reportPath"
        arael report $Binary --output $reportPath
        Write-Host "Report generated at $reportPath" -ForegroundColor Green
        Write-Host "Opening in browser..." -ForegroundColor Cyan
        Start-Process $reportPath
        Pause-Demo
    }
}

# Demo 8: Interactive Shell
function Demo-Shell {
    param([string]$Binary)

    Write-Header "DEMO 8: Interactive Shell"

    if ($Binary -and (Test-Path $Binary)) {
        Write-Host "Starting interactive shell..." -ForegroundColor Yellow
        Write-Host "Try: functions, decompile main, strings, quit" -ForegroundColor Yellow
        Write-Cmd "arael shell $Binary"
        arael shell $Binary
    }
}

# Full demo
function Run-FullDemo {
    param([string]$Binary)

    Write-Header "ARAEL v2.5 - FULL DEMO"
    Write-Host "Using binary: $Binary"
    Pause-Demo

    Demo-Intro
    Demo-Yara -Binary $Binary
    Demo-Analyze -Binary $Binary
    Demo-Functions -Binary $Binary
    Demo-Xrefs -Binary $Binary
    Demo-Strings -Binary $Binary
    Demo-Report -Binary $Binary

    Write-Header "DEMO COMPLETE"
    Write-Host "Thank you for watching!"
}

# Usage
function Show-Usage {
    Write-Host @"
Arael Demo Script (PowerShell)

Usage: .\demo.ps1 <command> [binary_path]

Commands:
  full      - Run complete demo
  intro     - Version and help
  yara      - YARA scanning demo
  analyze   - Analysis demo
  functions - Function analysis demo
  xrefs     - Cross-references demo
  strings   - Strings and imports demo
  report    - HTML report demo
  shell     - Interactive shell demo
  help      - Show this help

Example:
  .\demo.ps1 full .\malware.exe
  .\demo.ps1 yara .\sample.bin
  .\demo.ps1 intro
"@
}

# Main
switch ($Command.ToLower()) {
    "full"      { Run-FullDemo -Binary $BinaryPath }
    "intro"     { Demo-Intro }
    "yara"      { Demo-Yara -Binary $BinaryPath }
    "analyze"   { Demo-Analyze -Binary $BinaryPath }
    "functions" { Demo-Functions -Binary $BinaryPath }
    "xrefs"     { Demo-Xrefs -Binary $BinaryPath }
    "strings"   { Demo-Strings -Binary $BinaryPath }
    "report"    { Demo-Report -Binary $BinaryPath }
    "shell"     { Demo-Shell -Binary $BinaryPath }
    default     { Show-Usage }
}
