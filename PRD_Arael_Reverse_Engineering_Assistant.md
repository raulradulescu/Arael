# Product Requirements Document: Arael

## Reverse Engineering Assistant for Cybersecurity Professionals

**Document Version:** 1.0.0  
**Status:** Draft  
**Created:** 2024-12-25  
**Target Release:** TBD

---

## Document Purpose & Agent Instructions

This document serves dual purposes:

1. **Product Requirements Document** - Defining what Arael should accomplish
2. **AI Coding Agent Prompt** - Executable instructions for Claude Code or local LLMs

### Agent Execution Protocol

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RECURSIVE DEVELOPMENT LOOP                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                 │
│   │  1. READ     │───▶│  2. SPEC     │───▶│  3. TEST     │                 │
│   │  Requirements│    │  Define      │    │  Write First │                 │
│   └──────────────┘    └──────────────┘    └──────────────┘                 │
│          ▲                                       │                          │
│          │                                       ▼                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                 │
│   │  6. VERIFY   │◀───│  5. COMMIT   │◀───│  4. IMPLEMENT│                 │
│   │  Past Tests  │    │  git commit  │    │  Code Feature│                 │
│   └──────────────┘    └──────────────┘    └──────────────┘                 │
│          │                                                                  │
│          └──────────────────────────────────────────────────────────────────┤
│                              REPEAT UNTIL COMPLETE                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Comment Sections

Throughout this document, sections marked with `<!-- AGENT:NOTES -->` are reserved for the implementing agent to leave comments, decisions, and references for future iterations.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Solution Overview](#3-solution-overview)
4. [Architecture](#4-architecture)
5. [Feature Specifications](#5-feature-specifications)
6. [JSON Output Schema](#6-json-output-schema)
7. [Test Specifications](#7-test-specifications)
8. [Implementation Phases](#8-implementation-phases)
9. [Success Criteria](#9-success-criteria)
10. [Git Workflow](#10-git-workflow)
11. [XML Prompt Document for Local LLMs](#11-xml-prompt-document-for-local-llms)
12. [Agent Scratchpad](#12-agent-scratchpad)

---

## 1. Executive Summary

**Arael** is a reverse engineering assistant that bridges Ghidra's powerful analysis capabilities with Claude Code (and compatible local LLMs) through an MCP (Model Context Protocol) interface. Users invoke Arael via a simple slash command (`/arael <executable>`) to perform comprehensive binary analysis, with results structured as JSON objects for easy consumption and display.

### Key Value Propositions

- **Speed**: Expose Ghidra's tools directly to AI agents, eliminating manual copy-paste workflows
- **Structure**: All analysis outputs conform to a consistent JSON schema
- **Intelligence**: AI agents interpret raw data and provide semantic understanding
- **Extensibility**: Architecture supports additional architectures, formats, and analysis modules

---

## 2. Problem Statement

### Current Pain Points

Reverse engineering workflows today involve significant friction:

1. **Context Switching**: Analysts bounce between Ghidra GUI, terminal, and AI assistants
2. **Manual Data Transfer**: Copying disassembly, hexdumps, and decompilation by hand
3. **Unstructured Output**: Analysis notes scattered across files with no standard format
4. **No AI Integration**: Ghidra lacks native LLM integration for semantic analysis
5. **Repetitive Tasks**: Common analysis patterns require manual repetition

### Target Users

- Cybersecurity professionals performing malware analysis
- CTF competitors requiring rapid binary analysis
- Security researchers analyzing vulnerabilities
- Reverse engineers documenting binary behavior

---

## 3. Solution Overview

### What Arael Does

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER WORKFLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   $ claude                                                                  │
│   > /arael ./suspicious_binary.exe                                         │
│                                                                             │
│   [Arael] Importing binary into Ghidra...                                  │
│   [Arael] Running auto-analysis...                                         │
│   [Arael] Extracting functions (47 found)...                               │
│   [Arael] Building analysis JSON...                                        │
│   [Arael] AI agent analyzing semantics...                                  │
│                                                                             │
│   ✓ Analysis complete: ./arael_output/suspicious_binary_analysis.json      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Fresh Bridge Architecture

Rather than relying on Ghidra's existing Python/Java scripting with its limitations, Arael implements a **fresh bridge** approach:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│   Claude Code   │◀───▶│  Arael Bridge   │◀───▶│  Ghidra         │
│   (or Local LLM)│ MCP │  (Node.js/Rust) │ API │  (Headless)     │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │                       │                       │
        ▼                       ▼                       ▼
   Natural Language      JSON Structured         Binary Analysis
   Understanding         Data Pipeline           Engine
```

**Why Fresh Bridge?**

| Aspect | Ghidra Scripts | Fresh Bridge |
|--------|---------------|--------------|
| Performance | Script startup overhead per call | Persistent connection, fast queries |
| Protocol | File-based IPC, custom parsing | Native MCP, standardized JSON |
| State | Stateless, re-analyze each time | Stateful, cached analysis |
| Extensibility | Limited to Ghidra's API | Custom analysis modules |
| Error Handling | Stack traces in Jython | Structured error responses |

---

## 4. Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARAEL SYSTEM ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         MCP SERVER LAYER                              │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │  │   /arael    │  │  /arael     │  │  /arael     │  │  /arael     │  │  │
│  │  │   analyze   │  │  functions  │  │  decompile  │  │  strings    │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                       ARAEL CORE ENGINE                               │  │
│  │                                                                       │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐       │  │
│  │  │ Binary Loader   │  │ Analysis Cache  │  │ JSON Builder    │       │  │
│  │  │ - PE Parser     │  │ - Function DB   │  │ - Schema Valid  │       │  │
│  │  │ - ELF Parser    │  │ - Xref Index    │  │ - Incremental   │       │  │
│  │  │ - Mach-O Parser │  │ - String Table  │  │ - Streaming     │       │  │
│  │  │ - Raw/Firmware  │  │ - Type Recovery │  │                 │       │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘       │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      GHIDRA HEADLESS LAYER                            │  │
│  │                                                                       │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐       │  │
│  │  │ analyzeHeadless │  │ Ghidra Scripts  │  │ Project Manager │       │  │
│  │  │ - Auto-analysis │  │ - Decompiler    │  │ - Binary Import │       │  │
│  │  │ - Plugin Load   │  │ - Disassembler  │  │ - State Persist │       │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘       │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
arael/
├── src/
│   ├── mcp/                    # MCP server implementation
│   │   ├── server.ts           # Main MCP server
│   │   ├── tools/              # Tool definitions
│   │   │   ├── analyze.ts
│   │   │   ├── functions.ts
│   │   │   ├── decompile.ts
│   │   │   ├── disassemble.ts
│   │   │   ├── strings.ts
│   │   │   ├── xrefs.ts
│   │   │   ├── imports.ts
│   │   │   ├── exports.ts
│   │   │   └── hexdump.ts
│   │   └── resources/          # Resource providers
│   ├── ghidra/                 # Ghidra bridge
│   │   ├── headless.ts         # Headless Ghidra controller
│   │   ├── scripts/            # Ghidra Python scripts
│   │   │   ├── extract_functions.py
│   │   │   ├── decompile_function.py
│   │   │   ├── get_xrefs.py
│   │   │   └── analyze_binary.py
│   │   └── project.ts          # Ghidra project management
│   ├── analysis/               # Analysis modules
│   │   ├── cache.ts            # Analysis caching
│   │   ├── json_builder.ts     # JSON output construction
│   │   └── semantic.ts         # AI semantic analysis hooks
│   ├── parsers/                # Binary format parsers
│   │   ├── pe.ts
│   │   ├── elf.ts
│   │   ├── macho.ts
│   │   └── raw.ts
│   └── utils/
│       ├── hexdump.ts
│       └── logger.ts
├── tests/                      # Test suite (TDD)
│   ├── unit/
│   │   ├── mcp/
│   │   ├── ghidra/
│   │   ├── analysis/
│   │   └── parsers/
│   ├── integration/
│   │   ├── full_analysis.test.ts
│   │   ├── ghidra_bridge.test.ts
│   │   └── mcp_protocol.test.ts
│   ├── fixtures/               # Test binaries
│   │   ├── pe/
│   │   ├── elf/
│   │   ├── macho/
│   │   └── packed/
│   └── snapshots/              # Expected JSON outputs
├── schemas/                    # JSON schemas
│   ├── analysis_output.schema.json
│   ├── function.schema.json
│   └── binary_info.schema.json
├── docs/
│   ├── LOCAL_LLM_PROMPT.xml    # XML prompt for local LLMs
│   └── API.md
├── package.json
├── tsconfig.json
└── README.md
```

<!-- AGENT:NOTES
Architecture decisions and rationale:
- [ ] Decision: Language choice (TypeScript vs Rust for bridge)
- [ ] Decision: Ghidra communication method (headless scripts vs plugin)
- [ ] Notes: Performance considerations
- [ ] Notes: Memory management for large binaries
-->

---

## 5. Feature Specifications

Features are listed in priority order. Each feature must have tests written BEFORE implementation.

### 5.1 Core Features (P0 - Must Have)

#### 5.1.1 Decompilation (C Pseudocode Output)

**Description**: Extract Ghidra's decompiled C pseudocode for functions.

**User Story**: As a reverse engineer, I want to see decompiled C code for any function so I can understand its logic without reading assembly.

**Success Criteria (Define BEFORE implementation)**:
```
□ SC-1.1.1: Decompile single function by name returns valid C code
□ SC-1.1.2: Decompile single function by address returns valid C code  
□ SC-1.1.3: Decompile all functions returns array of function objects
□ SC-1.1.4: Output includes function signature, local variables, body
□ SC-1.1.5: Handles functions that fail to decompile gracefully
□ SC-1.1.6: Performance: <2s for single function, <30s for full binary
```

**Test Specification** (Write FIRST):
```typescript
// tests/unit/ghidra/decompile.test.ts

describe('Decompilation', () => {
  describe('decompileFunction', () => {
    it('should return C pseudocode for function by name', async () => {
      const result = await decompileFunction('main', testBinaryPath);
      expect(result.pseudocode).toContain('int main(');
      expect(result.signature).toBeDefined();
      expect(result.localVariables).toBeInstanceOf(Array);
    });

    it('should return C pseudocode for function by address', async () => {
      const result = await decompileFunctionAt(0x401000, testBinaryPath);
      expect(result.pseudocode).toBeTruthy();
      expect(result.address).toBe('0x401000');
    });

    it('should handle non-existent function gracefully', async () => {
      const result = await decompileFunction('nonexistent', testBinaryPath);
      expect(result.error).toBe('FUNCTION_NOT_FOUND');
      expect(result.pseudocode).toBeNull();
    });

    it('should complete within performance budget', async () => {
      const start = Date.now();
      await decompileFunction('main', testBinaryPath);
      expect(Date.now() - start).toBeLessThan(2000);
    });
  });
});
```

**Implementation Notes**:
```
<!-- AGENT:NOTES
Implementation tracking:
- [ ] Tests written
- [ ] Tests failing (red)
- [ ] Implementation complete
- [ ] Tests passing (green)
- [ ] Refactored
- [ ] Git commit made
- [ ] Integration tests passing
-->
```

---

#### 5.1.2 Disassembly (Assembly Listing)

**Description**: Extract assembly instructions for functions or address ranges.

**Success Criteria**:
```
□ SC-1.2.1: Disassemble function returns instruction array
□ SC-1.2.2: Each instruction includes address, bytes, mnemonic, operands
□ SC-1.2.3: Supports x86, x64, ARM, ARM64, MIPS architectures
□ SC-1.2.4: Address range disassembly works correctly
□ SC-1.2.5: Invalid address ranges return appropriate errors
```

**Test Specification**:
```typescript
// tests/unit/ghidra/disassemble.test.ts

describe('Disassembly', () => {
  it('should return instruction array for function', async () => {
    const result = await disassembleFunction('main', testBinaryPath);
    expect(result.instructions).toBeInstanceOf(Array);
    expect(result.instructions[0]).toMatchObject({
      address: expect.stringMatching(/^0x[0-9a-f]+$/i),
      bytes: expect.stringMatching(/^([0-9a-f]{2}\s?)+$/i),
      mnemonic: expect.any(String),
      operands: expect.any(String)
    });
  });

  it('should support multiple architectures', async () => {
    const elfResult = await disassembleFunction('main', elfBinaryPath);
    const peResult = await disassembleFunction('main', peBinaryPath);
    expect(elfResult.architecture).toBe('x86_64');
    expect(peResult.architecture).toBe('x86');
  });
});
```

---

#### 5.1.3 Function Discovery & Call Graphs

**Description**: Identify all functions and their call relationships.

**Success Criteria**:
```
□ SC-1.3.1: List all functions with name, address, size
□ SC-1.3.2: Identify entry point function
□ SC-1.3.3: Build call graph (caller -> callee relationships)
□ SC-1.3.4: Detect recursive functions
□ SC-1.3.5: Identify library vs user-defined functions
□ SC-1.3.6: Export call graph in DOT format for visualization
```

**Test Specification**:
```typescript
// tests/unit/analysis/functions.test.ts

describe('Function Discovery', () => {
  it('should discover all functions in binary', async () => {
    const functions = await discoverFunctions(testBinaryPath);
    expect(functions.length).toBeGreaterThan(0);
    expect(functions.find(f => f.name === 'main')).toBeDefined();
  });

  it('should build accurate call graph', async () => {
    const callGraph = await buildCallGraph(testBinaryPath);
    const mainCalls = callGraph.getCallees('main');
    expect(mainCalls).toContain('printf');
  });

  it('should detect recursive functions', async () => {
    const functions = await discoverFunctions(recursiveBinaryPath);
    const recursive = functions.filter(f => f.isRecursive);
    expect(recursive.length).toBeGreaterThan(0);
  });
});
```

---

#### 5.1.4 String Extraction

**Description**: Extract all strings from binary with references.

**Success Criteria**:
```
□ SC-1.4.1: Extract ASCII strings (min length configurable)
□ SC-1.4.2: Extract Unicode strings (UTF-16LE, UTF-16BE)
□ SC-1.4.3: Include string address and section location
□ SC-1.4.4: Include cross-references (which functions use string)
□ SC-1.4.5: Categorize strings (URLs, paths, registry keys, etc.)
```

**Test Specification**:
```typescript
// tests/unit/analysis/strings.test.ts

describe('String Extraction', () => {
  it('should extract ASCII strings', async () => {
    const strings = await extractStrings(testBinaryPath, { minLength: 4 });
    expect(strings.some(s => s.value === 'Hello, World!')).toBe(true);
  });

  it('should include cross-references', async () => {
    const strings = await extractStrings(testBinaryPath);
    const helloString = strings.find(s => s.value.includes('Hello'));
    expect(helloString.xrefs).toBeInstanceOf(Array);
    expect(helloString.xrefs.length).toBeGreaterThan(0);
  });

  it('should categorize strings', async () => {
    const strings = await extractStrings(malwareSamplePath);
    const urls = strings.filter(s => s.category === 'URL');
    const regKeys = strings.filter(s => s.category === 'REGISTRY_KEY');
    expect(urls.length + regKeys.length).toBeGreaterThan(0);
  });
});
```

---

#### 5.1.5 Cross-References (Xrefs)

**Description**: Find all references to/from addresses, functions, or data.

**Success Criteria**:
```
□ SC-1.5.1: Find all callers of a function
□ SC-1.5.2: Find all callees of a function
□ SC-1.5.3: Find data references (reads/writes)
□ SC-1.5.4: Distinguish call vs jump vs data reference types
□ SC-1.5.5: Support address and symbol name lookups
```

---

#### 5.1.6 Symbol/Import/Export Analysis

**Description**: Analyze imported and exported symbols.

**Success Criteria**:
```
□ SC-1.6.1: List all imports with library and function name
□ SC-1.6.2: List all exports with address and ordinal
□ SC-1.6.3: Identify suspicious imports (e.g., VirtualAlloc, CreateRemoteThread)
□ SC-1.6.4: Map imports to MITRE ATT&CK techniques where applicable
□ SC-1.6.5: Support PE, ELF, Mach-O import tables
```

---

#### 5.1.7 Data Type Recovery

**Description**: Recover and apply data types to variables and structures.

**Success Criteria**:
```
□ SC-1.7.1: Identify basic types (int, char*, structs)
□ SC-1.7.2: Recover struct layouts from usage patterns
□ SC-1.7.3: Apply known types from signature databases
□ SC-1.7.4: Export recovered types in C header format
```

---

#### 5.1.8 Hexdump Generation

**Description**: Generate formatted hexdump for any address range.

**Success Criteria**:
```
□ SC-1.8.1: Generate hexdump with configurable width (8, 16, 32 bytes)
□ SC-1.8.2: Include ASCII representation
□ SC-1.8.3: Highlight specific byte patterns
□ SC-1.8.4: Support virtual and file offset addressing
```

---

### 5.2 Extended Features (P1 - Should Have)

#### 5.2.1 Packed/Obfuscated Binary Support

**Description**: Detect and handle packed or obfuscated binaries.

**Success Criteria**:
```
□ SC-2.1.1: Detect common packers (UPX, ASPack, Themida, VMProtect)
□ SC-2.1.2: Auto-unpack UPX binaries
□ SC-2.1.3: Identify obfuscation patterns (junk code, opaque predicates)
□ SC-2.1.4: Calculate entropy per section
□ SC-2.1.5: Flag high-entropy sections as potentially packed
```

**Test Specification**:
```typescript
// tests/unit/analysis/packing.test.ts

describe('Packing Detection', () => {
  it('should detect UPX packed binary', async () => {
    const analysis = await analyzeBinary(upxPackedPath);
    expect(analysis.packing.detected).toBe(true);
    expect(analysis.packing.packer).toBe('UPX');
  });

  it('should calculate section entropy', async () => {
    const analysis = await analyzeBinary(packedBinaryPath);
    const textSection = analysis.sections.find(s => s.name === '.text');
    expect(textSection.entropy).toBeGreaterThan(7.0); // High entropy
  });

  it('should auto-unpack UPX', async () => {
    const unpacked = await unpackBinary(upxPackedPath);
    expect(unpacked.success).toBe(true);
    expect(unpacked.unpackedPath).toBeTruthy();
  });
});
```

---

#### 5.2.2 Binary Diffing

**Description**: Compare two binaries to identify changes.

**Success Criteria**:
```
□ SC-2.2.1: Diff functions between two binary versions
□ SC-2.2.2: Identify added/removed/modified functions
□ SC-2.2.3: Calculate similarity scores
□ SC-2.2.4: Highlight specific instruction changes
```

---

#### 5.2.3 Signature Matching

**Description**: Match against known patterns and signatures.

**Success Criteria**:
```
□ SC-2.3.1: YARA rule scanning support
□ SC-2.3.2: FLIRT signature matching for library identification
□ SC-2.3.3: Custom pattern definition support
□ SC-2.3.4: Report matches with confidence scores
```

---

#### 5.2.4 Control Flow Graph Generation

**Description**: Generate visual control flow graphs.

**Success Criteria**:
```
□ SC-2.4.1: Generate CFG for any function
□ SC-2.4.2: Export as DOT, SVG, or PNG
□ SC-2.4.3: Highlight loops and branches
□ SC-2.4.4: Interactive zoom in JSON output
```

---

### 5.3 Future Features (P2 - Nice to Have)

- Symbolic execution integration
- Emulation support (Unicorn integration)
- Collaborative analysis sessions
- Plugin marketplace
- Custom decompiler rules

---

## 6. JSON Output Schema

All Arael outputs conform to this schema for consistency and easy display.

### 6.1 Root Analysis Object

```json
{
  "$schema": "https://arael.dev/schemas/analysis_output.schema.json",
  "version": "1.0.0",
  "metadata": {
    "analysisId": "uuid-v4",
    "timestamp": "ISO-8601",
    "arealVersion": "1.0.0",
    "ghidraVersion": "11.0",
    "analysisTime": 12345,
    "agentNotes": ""
  },
  "binary": {
    "filename": "suspicious.exe",
    "filepath": "/path/to/suspicious.exe",
    "size": 102400,
    "hashes": {
      "md5": "...",
      "sha1": "...",
      "sha256": "...",
      "ssdeep": "..."
    },
    "format": "PE",
    "architecture": "x86_64",
    "endianness": "little",
    "entryPoint": "0x401000",
    "baseAddress": "0x400000",
    "sections": [],
    "packing": {
      "detected": false,
      "packer": null,
      "entropy": 5.2
    }
  },
  "functions": [],
  "strings": [],
  "imports": [],
  "exports": [],
  "xrefs": {},
  "callGraph": {},
  "aiAnalysis": {
    "summary": "",
    "suspiciousIndicators": [],
    "behaviorHypothesis": "",
    "recommendations": []
  }
}
```

### 6.2 Function Object Schema

```json
{
  "name": "main",
  "address": "0x401000",
  "size": 256,
  "callingConvention": "cdecl",
  "signature": "int main(int argc, char** argv)",
  "returnType": "int",
  "parameters": [
    { "name": "argc", "type": "int", "location": "stack" },
    { "name": "argv", "type": "char**", "location": "stack" }
  ],
  "localVariables": [
    { "name": "local_8", "type": "int", "stackOffset": -8 }
  ],
  "hexdump": {
    "startAddress": "0x401000",
    "endAddress": "0x401100",
    "bytes": "55 89 e5 83 ec 18...",
    "formatted": "00401000  55 89 e5 83 ec 18 c7 45  f8 00 00 00 00 eb 0f 8b  |U......E........|"
  },
  "disassembly": [
    {
      "address": "0x401000",
      "bytes": "55",
      "mnemonic": "push",
      "operands": "ebp",
      "comment": ""
    }
  ],
  "pseudocode": "int main(int argc, char **argv) {\n  int result;\n  ...\n  return result;\n}",
  "callees": ["printf", "malloc", "free"],
  "callers": ["__libc_start_main"],
  "xrefs": {
    "code": ["0x401200", "0x401350"],
    "data": ["0x404000"]
  },
  "flags": {
    "isEntryPoint": true,
    "isRecursive": false,
    "isThunk": false,
    "isLibrary": false
  },
  "agentAnalysis": {
    "purpose": "",
    "semanticName": "",
    "securityNotes": "",
    "confidence": 0.0
  }
}
```

### 6.3 AI Analysis Section

The `agentAnalysis` fields are filled by the MCP-capable agent (Claude Code or local LLM) after reviewing raw data:

```json
{
  "agentAnalysis": {
    "purpose": "This function appears to be the main entry point that parses command-line arguments and initializes the application.",
    "semanticName": "parseArgsAndInit",
    "securityNotes": "No obvious vulnerabilities. Uses safe string handling.",
    "confidence": 0.85,
    "relatedFunctions": ["initConfig", "loadPlugins"],
    "possibleMaliciousBehavior": null
  }
}
```

---

## 7. Test Specifications

### 7.1 Test-First Development Protocol

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TEST-FIRST DEVELOPMENT FLOW                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  FOR EACH FEATURE:                                                          │
│                                                                             │
│  1. ❌ Write failing unit tests based on Success Criteria                   │
│  2. ❌ Write failing integration tests                                      │
│  3. 🔨 Implement minimum code to pass ONE test                              │
│  4. ✅ Verify that ONE test passes                                          │
│  5. 🔨 Implement code to pass NEXT test                                     │
│  6. ✅ Verify ALL tests still pass (no regressions)                         │
│  7. 🔄 Refactor while keeping tests green                                   │
│  8. 📝 Git commit with test + implementation                                │
│  9. 🔍 Run FULL test suite to verify no regressions                         │
│  10. 📋 Update agent notes in this document                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Test Categories

#### Unit Tests (`tests/unit/`)
- Test individual functions in isolation
- Mock Ghidra interactions
- Fast execution (<1s per test)

#### Integration Tests (`tests/integration/`)
- Test complete workflows
- Use real Ghidra headless
- Test with actual binaries
- Slower execution (acceptable <30s per test)

#### Snapshot Tests (`tests/snapshots/`)
- Compare JSON output against known-good baselines
- Detect unexpected output changes
- Update snapshots explicitly when schema changes

### 7.3 Test Fixtures

Required test binaries (must be created/obtained):

| Fixture | Format | Purpose |
|---------|--------|---------|
| `hello_world.exe` | PE/x86 | Basic Windows binary |
| `hello_world` | ELF/x64 | Basic Linux binary |
| `hello_world.macho` | Mach-O/ARM64 | Basic macOS binary |
| `upx_packed.exe` | PE/x86 | UPX-packed binary |
| `recursive_functions` | ELF/x64 | Binary with recursion |
| `malware_sample` | PE/x86 | Suspicious import patterns |
| `stripped_binary` | ELF/x64 | No symbols |

### 7.4 Regression Testing Protocol

After EVERY new feature implementation:

```bash
# Run full test suite
npm test

# Run specific regression check
npm run test:regression

# Verify no snapshot changes (unless intentional)
npm run test:snapshots -- --ci

# Check test coverage
npm run test:coverage
```

---

## 8. Implementation Phases

### Phase 1: Foundation (Weeks 1-2)

**Goal**: Establish project structure, Ghidra bridge, and basic MCP server.

**Features**:
- [ ] Project scaffolding with TypeScript
- [ ] Ghidra headless integration
- [ ] MCP server skeleton
- [ ] Basic binary loading
- [ ] JSON schema definitions

**Success Gate**:
```
✓ Can load binary into Ghidra headlessly
✓ MCP server responds to ping
✓ All Phase 1 tests pass
✓ Git history shows TDD commits
```

**Git Commits Expected**:
```
feat(scaffold): initialize project structure
test(ghidra): add headless connection tests
feat(ghidra): implement headless bridge
test(mcp): add server initialization tests
feat(mcp): implement basic MCP server
test(loader): add binary loading tests
feat(loader): implement binary loader
docs: update implementation notes
```

<!-- AGENT:NOTES
Phase 1 Progress:
- [ ] Scaffolding complete
- [ ] Ghidra bridge working
- [ ] MCP server responding
- [ ] All tests passing
- [ ] Blockers:
- [ ] Decisions made:
-->

---

### Phase 2: Core Analysis (Weeks 3-4)

**Goal**: Implement P0 features (decompilation, disassembly, functions).

**Features**:
- [ ] Function discovery
- [ ] Decompilation
- [ ] Disassembly
- [ ] String extraction

**Success Gate**:
```
✓ /arael analyze produces valid JSON
✓ Decompilation returns C pseudocode
✓ All P0 success criteria met
✓ Integration tests pass
```

---

### Phase 3: Extended Analysis (Weeks 5-6)

**Goal**: Implement remaining P0 and P1 features.

**Features**:
- [ ] Cross-references
- [ ] Import/Export analysis
- [ ] Hexdump generation
- [ ] Packing detection

---

### Phase 4: AI Integration (Weeks 7-8)

**Goal**: Agent semantic analysis and polish.

**Features**:
- [ ] AI analysis field population
- [ ] Local LLM prompt document
- [ ] Performance optimization
- [ ] Documentation

---

## 9. Success Criteria

### 9.1 Overall Project Success

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PROJECT SUCCESS CRITERIA                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  FUNCTIONALITY                                                              │
│  □ User can run `/arael ./binary` and receive complete JSON analysis        │
│  □ All P0 features implemented and tested                                   │
│  □ Supports PE, ELF, and Mach-O formats                                     │
│  □ Works with Claude Code via MCP                                           │
│  □ Works with local LLMs via XML prompt                                     │
│                                                                             │
│  QUALITY                                                                    │
│  □ >80% test coverage                                                       │
│  □ All success criteria checkboxes completed                                │
│  □ No critical bugs in issue tracker                                        │
│  □ Documentation complete                                                   │
│                                                                             │
│  PERFORMANCE                                                                │
│  □ Analysis of 1MB binary completes in <60 seconds                          │
│  □ Single function decompile <2 seconds                                     │
│  □ Memory usage <2GB for typical binaries                                   │
│                                                                             │
│  PROCESS                                                                    │
│  □ Git history demonstrates TDD (test commits before implementation)        │
│  □ All phases completed with success gates met                              │
│  □ Agent notes filled in throughout document                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Feature-Level Success Verification

For each feature, verify:

1. **Tests Exist**: Unit and integration tests written
2. **Tests Pass**: All tests green
3. **Criteria Met**: All success criteria checkboxes checked
4. **Documented**: Agent notes updated
5. **Committed**: Git commit with descriptive message
6. **Regression-Free**: Full test suite still passes

---

## 10. Git Workflow

### 10.1 Commit Convention

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `test`: Adding tests
- `docs`: Documentation
- `refactor`: Code refactoring
- `perf`: Performance improvement

**Examples**:
```
test(decompile): add unit tests for function decompilation

- Test decompile by name
- Test decompile by address
- Test error handling for missing functions
- Add performance benchmark test

Refs: SC-1.1.1, SC-1.1.2, SC-1.1.5, SC-1.1.6
```

```
feat(decompile): implement function decompilation

- Add Ghidra script for decompilation
- Implement TypeScript wrapper
- Add caching for repeated calls

All tests passing. Closes #12
```

### 10.2 Commit Triggers

**MUST commit after**:
- Writing tests for a feature (before implementation)
- Implementing feature (all tests pass)
- Fixing a bug (with regression test)
- Refactoring (tests still pass)
- Documentation updates

### 10.3 Branching Strategy

```
main
  └── develop
        ├── feature/phase-1-foundation
        ├── feature/phase-2-core-analysis
        ├── feature/decompilation
        └── fix/ghidra-timeout
```

### 10.4 Post-Commit Verification

After EVERY commit:

```bash
# Verify commit
git log -1 --oneline

# Run full test suite
npm test

# Check for regressions
npm run test:regression

# Update this document's agent notes
```

---

## 11. XML Prompt Document for Local LLMs

The following XML document can be used to enable local LLMs to provide the same functionality as Claude Code. Save this as `docs/LOCAL_LLM_PROMPT.xml`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<arael_system_prompt version="1.0.0">
  <meta>
    <name>Arael Reverse Engineering Assistant</name>
    <description>
      System prompt for local LLMs to function as a reverse engineering 
      assistant using Ghidra tools via MCP protocol.
    </description>
    <target_models>
      <model>Llama 3.1 70B+</model>
      <model>Mixtral 8x22B</model>
      <model>Qwen 2.5 72B</model>
      <model>DeepSeek Coder 33B+</model>
    </target_models>
  </meta>

  <identity>
    <role>Expert Reverse Engineering Assistant</role>
    <persona>
      You are Arael, an expert reverse engineering assistant specialized in 
      binary analysis. You have deep knowledge of:
      - x86, x64, ARM, ARM64, MIPS assembly languages
      - PE, ELF, Mach-O binary formats
      - Windows, Linux, macOS internals
      - Malware analysis techniques
      - Vulnerability research
      - Ghidra and other RE tools
    </persona>
  </identity>

  <capabilities>
    <capability name="binary_analysis">
      <description>Analyze executable files to understand their behavior</description>
      <tools>
        <tool name="arael_analyze">
          <description>Perform full analysis of a binary</description>
          <parameters>
            <param name="filepath" type="string" required="true">Path to binary file</param>
            <param name="options" type="object" required="false">Analysis options</param>
          </parameters>
          <returns>Complete analysis JSON object</returns>
        </tool>
        
        <tool name="arael_decompile">
          <description>Decompile a function to C pseudocode</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
            <param name="function" type="string" required="true">Function name or address</param>
          </parameters>
          <returns>Function object with pseudocode</returns>
        </tool>
        
        <tool name="arael_disassemble">
          <description>Disassemble a function or address range</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
            <param name="target" type="string" required="true">Function name, address, or range</param>
          </parameters>
          <returns>Array of instruction objects</returns>
        </tool>
        
        <tool name="arael_functions">
          <description>List all functions in binary</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
            <param name="filter" type="object" required="false">Filter criteria</param>
          </parameters>
          <returns>Array of function summaries</returns>
        </tool>
        
        <tool name="arael_strings">
          <description>Extract strings from binary</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
            <param name="min_length" type="integer" required="false">Minimum string length (default: 4)</param>
          </parameters>
          <returns>Array of string objects with xrefs</returns>
        </tool>
        
        <tool name="arael_xrefs">
          <description>Find cross-references to/from address</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
            <param name="address" type="string" required="true">Target address or symbol</param>
            <param name="direction" type="string" required="false">to, from, or both</param>
          </parameters>
          <returns>Xref objects</returns>
        </tool>
        
        <tool name="arael_imports">
          <description>List imported functions</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
          </parameters>
          <returns>Array of import objects</returns>
        </tool>
        
        <tool name="arael_exports">
          <description>List exported functions</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
          </parameters>
          <returns>Array of export objects</returns>
        </tool>
        
        <tool name="arael_hexdump">
          <description>Generate hexdump for address range</description>
          <parameters>
            <param name="binary" type="string" required="true">Path to binary</param>
            <param name="start" type="string" required="true">Start address</param>
            <param name="length" type="integer" required="true">Number of bytes</param>
          </parameters>
          <returns>Formatted hexdump string</returns>
        </tool>
      </tools>
    </capability>
  </capabilities>

  <behavioral_instructions>
    <instruction priority="high">
      When analyzing binaries, always start with a high-level overview before 
      diving into specific functions. Identify the binary format, architecture, 
      and entry point first.
    </instruction>
    
    <instruction priority="high">
      For each function you analyze, fill in the agentAnalysis fields:
      - purpose: What does this function do?
      - semanticName: A better name than the default
      - securityNotes: Any security-relevant observations
      - confidence: Your confidence level (0.0-1.0)
    </instruction>
    
    <instruction priority="high">
      When you identify suspicious patterns (shellcode, API hooking, process 
      injection, etc.), immediately flag them in your analysis with specific 
      evidence from the code.
    </instruction>
    
    <instruction priority="medium">
      Cross-reference your findings. If a string references a suspicious URL, 
      find which functions use that string. If a function calls VirtualAlloc, 
      trace what gets written to that memory.
    </instruction>
    
    <instruction priority="medium">
      Structure your output to match the JSON schema exactly. The agentAnalysis 
      sections are where you add your interpretations.
    </instruction>
    
    <instruction priority="low">
      When uncertain, state your confidence level and explain what additional 
      analysis would help clarify the behavior.
    </instruction>
  </behavioral_instructions>

  <output_format>
    <format_instruction>
      All analysis output must conform to the Arael JSON schema. Your semantic 
      analysis goes in the designated agentAnalysis fields within each object.
    </format_instruction>
    
    <example_output>
      <![CDATA[
{
  "functions": [{
    "name": "sub_401000",
    "address": "0x401000",
    "pseudocode": "void sub_401000(void) { ... }",
    "agentAnalysis": {
      "purpose": "This function decodes an XOR-encrypted configuration blob stored at 0x404000. The XOR key is 0x5A repeated.",
      "semanticName": "decodeConfig",
      "securityNotes": "XOR encoding is often used to hide malicious configurations. The decoded data should be examined for C2 addresses.",
      "confidence": 0.9
    }
  }]
}
      ]]>
    </example_output>
  </output_format>

  <security_analysis_patterns>
    <pattern name="process_injection">
      <indicators>
        <indicator>OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread</indicator>
        <indicator>NtCreateThreadEx or RtlCreateUserThread</indicator>
      </indicators>
      <severity>high</severity>
    </pattern>
    
    <pattern name="shellcode_execution">
      <indicators>
        <indicator>VirtualAlloc with PAGE_EXECUTE_READWRITE</indicator>
        <indicator>Memory copy followed by call/jmp to allocated region</indicator>
      </indicators>
      <severity>high</severity>
    </pattern>
    
    <pattern name="api_hooking">
      <indicators>
        <indicator>GetProcAddress for ntdll functions</indicator>
        <indicator>Modification of function prologues</indicator>
      </indicators>
      <severity>medium</severity>
    </pattern>
    
    <pattern name="persistence">
      <indicators>
        <indicator>Registry key creation (Run, RunOnce)</indicator>
        <indicator>Scheduled task creation</indicator>
        <indicator>Service installation</indicator>
      </indicators>
      <severity>medium</severity>
    </pattern>
    
    <pattern name="evasion">
      <indicators>
        <indicator>IsDebuggerPresent, CheckRemoteDebuggerPresent</indicator>
        <indicator>NtQueryInformationProcess</indicator>
        <indicator>CPUID checks for VM detection</indicator>
        <indicator>Timing checks</indicator>
      </indicators>
      <severity>medium</severity>
    </pattern>
  </security_analysis_patterns>

  <workflow_example>
    <step order="1">
      User: /arael ./suspicious.exe
    </step>
    <step order="2">
      Agent: [Calls arael_analyze to get full analysis]
    </step>
    <step order="3">
      Agent: [Reviews binary metadata, identifies PE/x86]
    </step>
    <step order="4">
      Agent: [Examines imports for suspicious APIs]
    </step>
    <step order="5">
      Agent: [Decompiles entry point and key functions]
    </step>
    <step order="6">
      Agent: [Fills in agentAnalysis for each function]
    </step>
    <step order="7">
      Agent: [Produces final JSON with complete analysis]
    </step>
  </workflow_example>
</arael_system_prompt>
```

---

## 12. Agent Scratchpad

This section is reserved for the implementing agent to track progress, make notes, and leave comments for future iterations.

### 12.1 Implementation Log

```
<!-- AGENT:LOG
Date       | Action                              | Commit Hash | Notes
-----------|-------------------------------------|-------------|------
           |                                     |             |
           |                                     |             |
           |                                     |             |
-->
```

### 12.2 Decisions Made

```
<!-- AGENT:DECISIONS
ID  | Decision                                    | Rationale
----|---------------------------------------------|---------------------------
D1  |                                             |
D2  |                                             |
D3  |                                             |
-->
```

### 12.3 Blockers & Questions

```
<!-- AGENT:BLOCKERS
ID  | Blocker/Question                            | Status    | Resolution
----|---------------------------------------------|-----------|------------
B1  |                                             |           |
B2  |                                             |           |
-->
```

### 12.4 Test Results Tracking

```
<!-- AGENT:TEST_RESULTS
Run # | Date       | Pass | Fail | Skip | Coverage | Notes
------|------------|------|------|------|----------|------
      |            |      |      |      |          |
      |            |      |      |      |          |
-->
```

### 12.5 Regression Notes

```
<!-- AGENT:REGRESSIONS
After implementing feature X, the following tests failed:
- 
- 

Resolution:
- 
-->
```

### 12.6 Future Improvements

```
<!-- AGENT:IMPROVEMENTS
Ideas for future iterations:
- 
- 
- 
-->
```

---

## Appendix A: Ghidra Headless Commands Reference

```bash
# Basic analysis
analyzeHeadless <project_dir> <project_name> \
  -import <binary> \
  -postScript <script.py> \
  -scriptPath <scripts_dir>

# With specific processor
analyzeHeadless <project_dir> <project_name> \
  -import <binary> \
  -processor x86:LE:64:default

# Run script on existing project
analyzeHeadless <project_dir> <project_name> \
  -process <binary_name> \
  -postScript <script.py>
```

---

## Appendix B: MCP Tool Definitions

```typescript
// Example MCP tool definition
const arael_analyze: Tool = {
  name: "arael_analyze",
  description: "Perform comprehensive analysis of an executable binary",
  inputSchema: {
    type: "object",
    properties: {
      filepath: {
        type: "string",
        description: "Path to the binary file to analyze"
      },
      options: {
        type: "object",
        properties: {
          decompile: { type: "boolean", default: true },
          strings: { type: "boolean", default: true },
          imports: { type: "boolean", default: true },
          exports: { type: "boolean", default: true }
        }
      }
    },
    required: ["filepath"]
  }
};
```

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2024-12-25 | Initial | Initial PRD creation |

---

**End of Document**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  This PRD is a living document. The implementing agent should update the    │
│  Agent Scratchpad sections throughout development to maintain continuity    │
│  across sessions.                                                           │
│                                                                             │
│  Remember: TEST FIRST, IMPLEMENT SECOND, COMMIT ALWAYS                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
