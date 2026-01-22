# AGENTS.md - Arael Project Guide for AI Coding Agents

## Project Overview

**Arael** is a reverse engineering assistant that bridges Ghidra with Claude Code via the Model Context Protocol (MCP). It enables LLMs to analyze binaries by invoking CLI commands and interpreting JSON output.

**Current Version:** v2.6.0
**Test Status:** 131/131 tests passing
**Stack:** TypeScript + Python (PyGhidra 3.0+)

## Quick Start

```bash
# Install dependencies
npm install

# Build project
npm run build

# Run all tests
npm test

# Run specific test suite
npm run test:unit
npm run test:integration
```

## Environment Setup

Create a `.env` file in project root. The file supports **platform-specific sections** using `# WSL` and `# Windows` comments as section headers:

```env
# Default settings (used on Linux/macOS)
GHIDRA_PATH=/opt/ghidra_12.0_PUBLIC
ARAEL_PYTHON=python3

# WSL
GHIDRA_PATH=/mnt/c/path/to/ghidra_12.0_PUBLIC
ARAEL_PYTHON=/mnt/c/path/to/.venv/bin/python

# Windows
GHIDRA_PATH=C:\path\to\ghidra_12.0_PUBLIC
ARAEL_PYTHON=C:\Python313\python.exe
```

The loader (`src/utils/env.ts`) auto-detects the platform and applies the correct section.

**Requirements:**
- Node.js 20+
- Python 3.10+ with `pip install pyghidra`
- Ghidra 12.0+

## Project Structure

```
src/
├── mcp/
│   ├── server.ts           # MCP server entry point
│   └── handlers/           # Tool handlers (one per MCP tool)
│       ├── analyze.ts      # arael_analyze
│       ├── decompile.ts    # arael_decompile
│       ├── disassemble.ts  # arael_disassemble
│       ├── functions.ts    # arael_functions
│       ├── imports.ts      # arael_imports
│       ├── exports.ts      # arael_exports
│       ├── strings.ts      # arael_strings
│       ├── hexdump.ts      # arael_hexdump
│       ├── xrefs.ts        # arael_xrefs
│       └── callgraph.ts    # arael_callgraph
├── ghidra/
│   ├── connection.ts       # Ghidra connection abstraction
│   ├── headless.ts         # Headless mode (spawns Python scripts)
│   ├── bridge.ts           # Bridge mode (persistent connection)
│   └── scripts/            # Python scripts for Ghidra
│       ├── project_loader.py   # Shared PyGhidra loader
│       ├── run_analysis.py     # Full binary analysis
│       ├── arael_extract.py    # Decompilation & extraction
│       ├── disassemble.py      # Assembly listing
│       ├── xrefs.py            # Cross-reference analysis
│       ├── exports.py          # Symbol exports
│       └── callgraph.py        # Call graph generation
├── output/
│   ├── schema.ts           # TypeScript interfaces for output
│   └── builder.ts          # AnalysisBuilder class
├── cache/
│   ├── store.ts            # SQLite cache for analysis results
│   └── keys.ts             # Cache key generation
├── utils/
│   ├── packing.ts          # Packer detection (UPX, PyInstaller, etc.)
│   ├── sections.ts         # Section analysis (entropy, permissions)
│   ├── import-analysis.ts  # Import categorization & risk levels
│   ├── preflight.ts        # Binary validation
│   ├── env.ts              # Environment loading
│   └── logger.ts           # Logging utility
└── cli/
    ├── index.ts            # CLI entry point
    └── check.ts            # Environment checker

tests/
├── unit/                   # Unit tests (no Ghidra needed)
├── integration/            # Integration tests (need Ghidra)
├── fixtures/               # Test binaries
└── mocks/                  # Mock Ghidra responses
```

## Key Patterns

### 1. Handler Pattern (MCP Tools)

Each MCP tool follows this pattern in `src/mcp/handlers/`:

```typescript
// src/mcp/handlers/example.ts
import { getConnection } from '../../ghidra/connection';
import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { logger } from '../../utils/logger';

export interface ExampleArgs {
  filepath: string;
  // ... other args
}

export interface ExampleResult {
  data: SomeType | null;
  error?: string;
}

export async function exampleHandler(args: ExampleArgs): Promise<ExampleResult> {
  // 1. Validate binary
  await validateBinary(args.filepath);

  // 2. Log operation
  logger.info('Example operation', { filepath: args.filepath });

  // 3. Get connection and call Ghidra
  const connection = getConnection();
  const result = await connection.example(args.filepath, ...);

  // 4. Return structured result
  return { data: result };
}
```

### 2. Python Script Pattern (Ghidra Integration)

Python scripts in `src/ghidra/scripts/` follow this pattern:

```python
#!/usr/bin/env python3
"""
Script description
"""
import sys
import json
import argparse
import os
from pathlib import Path
from project_loader import load_program, format_address

try:
    import pyghidra
except ImportError:
    print("ERROR: pyghidra not installed", file=sys.stderr)
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='...')
    parser.add_argument('binary_path', help='Path to binary')
    # ... more args
    args = parser.parse_args()

    ghidra_path = os.environ.get('GHIDRA_PATH')
    if not ghidra_path:
        print(json.dumps({'error': 'GHIDRA_PATH not set'}))
        sys.exit(1)

    pyghidra.start(install_dir=ghidra_path)

    try:
        with load_program(Path(args.binary_path)) as program:
            # Do analysis work
            result = analyze(program, ...)
            print(json.dumps({'data': result}))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### 3. Shared PyGhidra Loader

Always use `project_loader.py` for loading programs:

```python
from project_loader import load_program, format_address

with load_program(binary_path) as program:
    # program is a Ghidra Program object
    func_manager = program.getFunctionManager()
    listing = program.getListing()
    # ...
```

### 4. Test Pattern

```typescript
// tests/integration/example.test.ts
import { loadEnvFromFile } from '../../src/utils/env';
loadEnvFromFile();  // MUST be before other imports

import { describeOrSkip, testBinary } from './helpers';
import { exampleHandler } from '../../src/mcp/handlers/example';

describeOrSkip('Example Handler', () => {
  it('should do something', async () => {
    const result = await exampleHandler({ filepath: testBinary });
    expect(result.data).toBeDefined();
  }, 120000);  // 2 minute timeout for Ghidra
});
```

## Adding New Features

### Adding a New MCP Tool

1. **Create handler** in `src/mcp/handlers/newtool.ts`
2. **Create Python script** in `src/ghidra/scripts/newtool.py` (if needs Ghidra)
3. **Add to connection** in `src/ghidra/connection.ts` and `src/ghidra/headless.ts`
4. **Register in server** in `src/mcp/server.ts`
5. **Add tests** in `tests/integration/newtool.test.ts`
6. **Run build**: `npm run build`

### Connection Methods

Add methods to both files:

```typescript
// src/ghidra/connection.ts
export interface GhidraConnection {
  // ... existing methods
  newTool(filepath: string, ...args): Promise<ResultType>;
}

// src/ghidra/headless.ts
export class GhidraHeadless implements GhidraConnection {
  async newTool(filepath: string, ...args): Promise<ResultType> {
    const result = await this.runScript('newtool.py', [
      filepath,
      '--arg1', String(arg1),
    ]);
    return JSON.parse(result).data;
  }
}
```

## Testing Guidelines

- **Unit tests**: No Ghidra needed, test pure logic
- **Integration tests**: Require Ghidra, use `describeOrSkip`
- **TDD tests**: Use `describe.skip` for unimplemented features
- **Timeouts**: Use 120000ms (2 min) for Ghidra operations
- **Test fixtures**: Place binaries in `tests/fixtures/`

```bash
# Run specific test file
npx jest tests/integration/disassemble.test.ts

# Run with verbose output
npx jest --verbose

# Run single test
npx jest -t "should disassemble function"
```

## Current TDD Tests (Ready for Implementation)

These test files are skipped but ready for implementation:

| Feature | Test File | Module to Create |
|---------|-----------|------------------|
| .pyc Decompilation | `tests/unit/pyc-decompilation.test.ts` | `src/utils/pyc-decompiler.ts` |
| x86 32-bit Support | `tests/integration/arch-x86-32bit.test.ts` | Processor config |
| x86 16-bit Support | `tests/integration/arch-x86-16bit.test.ts` | Processor config |

## Important Conventions

1. **Never use deprecated APIs**: Use `pyghidra.open_program()` not `from pyghidra import project`
2. **Always validate binaries**: Call `validateBinary()` before analysis
3. **Use structured output**: Return `{ data, error }` from handlers
4. **Log operations**: Use `logger.info()` for traceability
5. **Handle errors gracefully**: Return error in result, don't throw
6. **Test binary location**: `tests/fixtures/hello_world` (ELF x86-64)

## Common Ghidra APIs

```python
# Function iteration
func_manager = program.getFunctionManager()
for func in func_manager.getFunctions(True):  # True = forward order
    name = func.getName()
    entry = func.getEntryPoint()
    body = func.getBody()  # AddressSetView

# Instruction listing
listing = program.getListing()
inst = listing.getInstructionAt(address)
mnemonic = inst.getMnemonicString()
operands = [inst.getDefaultOperandRepresentation(i) for i in range(inst.getNumOperands())]

# References
ref_manager = program.getReferenceManager()
refs_from = ref_manager.getReferencesFrom(address)
refs_to = ref_manager.getReferencesTo(address)

# Symbols
symbol_table = program.getSymbolTable()
symbols = symbol_table.getSymbols(address)

# Memory
memory = program.getMemory()
blocks = memory.getBlocks()
```

## Build & Publish

```bash
npm run build          # Compile TypeScript + copy Python scripts
npm run lint           # Check code style
npm run lint:fix       # Auto-fix style issues
npm test               # Run all tests
npm run prepublishOnly # Build before publish
```

## Debugging

1. **Check environment**: `npx ts-node src/cli/check.ts`
2. **Test Ghidra connection**: `npm run test:connection`
3. **Enable verbose logging**: Set `DEBUG=arael:*` environment variable
4. **Python script errors**: Check stderr output in test failures

## Files You Should Not Modify

- `tests/fixtures/*` - Test binaries
- `package-lock.json` - Auto-generated
- `dist/*` - Build output

## Files Safe to Modify

- `src/**/*.ts` - TypeScript source
- `src/ghidra/scripts/*.py` - Python Ghidra scripts
- `tests/**/*.test.ts` - Test files
- `docs/*` - Documentation
