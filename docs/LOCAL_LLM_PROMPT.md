# Local LLM Integration

Use Arael with local LLMs that don't support MCP directly.

## CLI Commands

```bash
# Core Analysis
arael analyze ./binary              # Full analysis (JSON)
arael context ./binary              # LLM-optimized context (v2.6)
arael context ./binary --json       # Machine-readable context
arael ask ./binary -q "Is this malicious?"  # LLM query (v2.6)
arael ask ./binary -q malicious -p google   # Use specific provider (openai, anthropic, google, ollama)

# Code Analysis
arael functions ./binary --filter "main"
arael decompile ./binary --function main
arael disassemble ./binary --function main

# Data Extraction
arael strings ./binary --min-length 6
arael imports ./binary
arael exports ./binary

# Cross-references & Flow
arael xrefs ./binary --address 0x401000
arael callgraph ./binary --format mermaid --root main

# Utilities
arael hexdump ./binary --address 0x401000 --length 128
arael yara ./binary
arael report ./binary --output report.html
arael shell ./binary               # Interactive REPL
arael batch "./samples/*.exe"      # Batch analysis
```

## Command Outputs

| Command | Output |
|---------|--------|
| `analyze` | JSON: binary metadata, functions[], strings[], imports[], exports[], packing info |
| `context` | JSON: classification, behaviors[], mitreAttack{}, iocs{}, riskAssessment, suggestedAnalysis[] |
| `ask` | LLM response text with analysis context injected |
| `functions` | JSON array: name, address, size, isThunk, isExternal |
| `decompile` | C pseudocode string with variable types and control flow |
| `disassemble` | JSON array: address, mnemonic, operands, bytes, references |
| `strings` | JSON array: address, value, encoding, length, xrefs[] |
| `imports` | JSON: grouped by library, each with name, address, category, riskLevel |
| `exports` | JSON array: name, address, type, ordinal |
| `xrefs` | JSON array: fromAddress, toAddress, type (CALL/DATA/JUMP), context |
| `callgraph` | JSON nodes/edges, or DOT/Mermaid graph notation |
| `hexdump` | Formatted hex dump: address, hex bytes, ASCII |
| `yara` | JSON: matches[] with rule name, tags, metadata, matched strings |

## System Prompt (Minimal)

```
You are a reverse engineering assistant using Arael CLI.

Commands:
- arael analyze <path>           - Full analysis → JSON with binary, functions, strings, imports
- arael context <path>           - LLM context → JSON with classification, behaviors, IOCs, MITRE
- arael ask <path> -q <question> - Ask LLM about binary (supports: openai, anthropic, google, ollama)
- arael functions <path>         - List functions → JSON array with name, address, size
- arael decompile <path> -f <fn> - Decompile → C pseudocode string
- arael disassemble <path> -f <fn> - Disassemble → JSON with instructions
- arael strings <path>           - Extract strings → JSON array with value, address, xrefs
- arael imports <path>           - List imports → JSON grouped by library with risk levels
- arael exports <path>           - List exports → JSON array with name, address, type
- arael xrefs <path> -a <addr>   - Cross-refs → JSON array with from/to address, type
- arael callgraph <path>         - Call graph → JSON/DOT/Mermaid
- arael hexdump <path> -a <addr> - Dump bytes → formatted hex/ASCII
- arael yara <path>              - YARA scan → JSON with rule matches

Workflow:
1. arael context - Get classification, behaviors, IOCs, MITRE mapping
2. arael yara - Check for packing/malware indicators
3. arael functions - Find interesting targets
4. arael decompile - Analyze suspicious functions
5. arael xrefs - Trace data flow
```

## Full XML Prompt

For comprehensive structured prompts, use: `docs/LOCAL_LLM_PROMPT.xml`

## Integration Examples

### Ollama
```bash
ollama create arael-assistant -f - <<EOF
FROM mixtral
SYSTEM $(cat docs/LOCAL_LLM_PROMPT.xml)
EOF

ollama run arael-assistant "Analyze ./binary"
```

### llama.cpp
```bash
llama-cli --model model.gguf \
  --system "$(cat docs/LOCAL_LLM_PROMPT.xml)" \
  --prompt "Analyze this binary: ./target"
```

## Tool Calling

```json
{
  "name": "arael_context",
  "description": "Get LLM-optimized analysis context for a binary",
  "parameters": {
    "type": "object",
    "properties": {
      "filepath": { "type": "string", "description": "Path to binary" },
      "json": { "type": "boolean", "description": "Return JSON format" }
    },
    "required": ["filepath"]
  }
}
```

## Best Practices

1. **Start with context** - `arael context` gives quick LLM-friendly overview
2. **Cache results** - Analysis is cached; use `--force` to re-analyze
3. **Use filters** - Reduce output with `--filter`, `--min-length`
4. **Check behaviors** - Context command shows detected behaviors and MITRE mapping
