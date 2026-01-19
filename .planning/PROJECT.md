# Arael - Reverse Engineering Assistant

## Vision

Arael is an MCP (Model Context Protocol) server that bridges Ghidra's powerful binary analysis capabilities with Claude Code. It enables AI-assisted reverse engineering by exposing decompilation, disassembly, and binary analysis through structured JSON APIs.

**Bachelor's Thesis Project for 2026 by Raul Radulescu**

## Problem Statement

Reverse engineering malware and CTF challenges requires deep technical expertise and is time-consuming. While Ghidra provides powerful analysis, the process of:
- Understanding binary behavior
- Identifying malicious indicators
- Mapping to ATT&CK techniques
- Extracting IOCs

...remains manual and error-prone.

## Solution

Arael automates binary analysis and provides LLM-optimized output that enables AI assistants to:
1. Understand binary behavior at a high level
2. Detect malicious patterns and behaviors
3. Extract actionable intelligence (IOCs, ATT&CK mapping)
4. Answer natural language questions about binaries

## Current State (v2.5)

Arael v2.5 is **production-ready** with:
- 10 MCP tools (analyze, decompile, disassemble, functions, strings, imports, exports, xrefs, callgraph, hexdump)
- Multi-format support (ELF, PE, Mach-O, MZ/COM/RAW, ARM)
- Interactive shell, batch analysis, YARA scanning, HTML reports
- 353 YARA rules (43 built-in + 310 ReversingLabs)
- 271 tests (168 integration + 103 unit)

## Target State (v2.6)

The "LLM Context Layer" - making analysis output optimal for AI-assisted reverse engineering:

1. **`arael context`** - LLM-optimized analysis summary with behavioral classification
2. **`arael ask`** - Natural language queries about binaries
3. **Enhanced import analysis** - 500+ function capability database
4. **IOC extraction** - IPs, domains, URLs, registry keys, mutexes
5. **Behavior detection** - Automated behavioral classification
6. **MITRE ATT&CK mapping** - Technique identification from imports/behaviors

## Success Metrics

| Metric | Target |
|--------|--------|
| Import recognition rate | >80% |
| String xref coverage | >90% |
| Context generation time | <5s |
| LLM query accuracy | >85% |

## Tech Stack

- **Runtime:** Node.js 20+ / TypeScript 5.9
- **Analysis Engine:** Ghidra 12.0 / PyGhidra 3.0
- **Cache:** SQLite (better-sqlite3)
- **Testing:** Vitest (migrating from Jest)
- **Python:** 3.10+

## Repository

- GitHub: https://github.com/raulradulescu/arael
- Author: Raul Radulescu
