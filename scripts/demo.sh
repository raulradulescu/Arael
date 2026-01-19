#!/bin/bash
# Arael v2.5 - Live Demo Script
# Run sections individually for presentation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_cmd() {
    echo -e "${GREEN}$ $1${NC}"
}

pause() {
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

# Demo 1: Version and Help
demo_intro() {
    print_header "DEMO 1: Arael Introduction"

    print_cmd "arael --version"
    arael --version
    pause

    print_cmd "arael --help"
    arael --help
    pause
}

# Demo 2: YARA Scanning
demo_yara() {
    print_header "DEMO 2: YARA Rule Scanning"

    print_cmd "arael yara --list-rules"
    arael yara --list-rules
    pause

    if [ -f "$1" ]; then
        print_cmd "arael yara $1"
        arael yara "$1"
        pause

        print_cmd "arael yara $1 --ruleset all --json | head -50"
        arael yara "$1" --ruleset all --json | head -50
        pause
    fi
}

# Demo 3: Basic Analysis
demo_analyze() {
    print_header "DEMO 3: Binary Analysis"

    if [ -f "$1" ]; then
        print_cmd "arael analyze $1 -o summary"
        arael analyze "$1" -o summary
        pause

        echo -e "${YELLOW}Running again to show caching (should be instant):${NC}"
        print_cmd "arael analyze $1 -o summary"
        time arael analyze "$1" -o summary
        pause
    fi
}

# Demo 4: Function Analysis
demo_functions() {
    print_header "DEMO 4: Function Analysis"

    if [ -f "$1" ]; then
        print_cmd "arael functions $1 --exclude-thunks --exclude-external"
        arael functions "$1" --exclude-thunks --exclude-external | head -30
        pause

        print_cmd "arael decompile $1 --function main"
        arael decompile "$1" --function main
        pause
    fi
}

# Demo 5: Cross-References
demo_xrefs() {
    print_header "DEMO 5: Cross-References & Call Graph"

    if [ -f "$1" ]; then
        print_cmd "arael xrefs $1 --address main"
        arael xrefs "$1" --address main
        pause

        print_cmd "arael callgraph $1 --root main --format mermaid --depth 3"
        arael callgraph "$1" --root main --format mermaid --depth 3
        pause
    fi
}

# Demo 6: Strings and Imports
demo_strings() {
    print_header "DEMO 6: Strings & Import Analysis"

    if [ -f "$1" ]; then
        print_cmd "arael strings $1 --min-length 8 | head -20"
        arael strings "$1" --min-length 8 | head -20
        pause

        print_cmd "arael imports $1 | head -30"
        arael imports "$1" | head -30
        pause
    fi
}

# Demo 7: HTML Report
demo_report() {
    print_header "DEMO 7: HTML Report Generation"

    if [ -f "$1" ]; then
        print_cmd "arael report $1 --output /tmp/demo_report.html"
        arael report "$1" --output /tmp/demo_report.html
        echo -e "${GREEN}Report generated at /tmp/demo_report.html${NC}"
        pause
    fi
}

# Demo 8: Interactive Shell
demo_shell() {
    print_header "DEMO 8: Interactive Shell"

    if [ -f "$1" ]; then
        echo -e "${YELLOW}Starting interactive shell...${NC}"
        echo -e "${YELLOW}Try: functions, decompile main, strings, quit${NC}"
        print_cmd "arael shell $1"
        arael shell "$1"
    fi
}

# Full demo
run_full_demo() {
    BINARY="${1:-./tests/fixtures/hello_world}"

    print_header "ARAEL v2.5 - FULL DEMO"
    echo "Using binary: $BINARY"
    pause

    demo_intro
    demo_yara "$BINARY"
    demo_analyze "$BINARY"
    demo_functions "$BINARY"
    demo_xrefs "$BINARY"
    demo_strings "$BINARY"
    demo_report "$BINARY"

    print_header "DEMO COMPLETE"
    echo "Thank you for watching!"
}

# Usage
show_usage() {
    echo "Arael Demo Script"
    echo ""
    echo "Usage: $0 <command> [binary_path]"
    echo ""
    echo "Commands:"
    echo "  full      - Run complete demo"
    echo "  intro     - Version and help"
    echo "  yara      - YARA scanning demo"
    echo "  analyze   - Analysis demo"
    echo "  functions - Function analysis demo"
    echo "  xrefs     - Cross-references demo"
    echo "  strings   - Strings and imports demo"
    echo "  report    - HTML report demo"
    echo "  shell     - Interactive shell demo"
    echo ""
    echo "Example:"
    echo "  $0 full ./malware.exe"
    echo "  $0 yara ./sample.bin"
}

# Main
case "${1:-}" in
    full)      run_full_demo "$2" ;;
    intro)     demo_intro ;;
    yara)      demo_yara "$2" ;;
    analyze)   demo_analyze "$2" ;;
    functions) demo_functions "$2" ;;
    xrefs)     demo_xrefs "$2" ;;
    strings)   demo_strings "$2" ;;
    report)    demo_report "$2" ;;
    shell)     demo_shell "$2" ;;
    *)         show_usage ;;
esac
