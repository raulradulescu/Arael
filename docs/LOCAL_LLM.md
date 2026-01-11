# Local LLM Integration

Arael can be used with local LLMs that don't support MCP directly. This guide explains how to integrate Arael with local models.

## Option 1: CLI Mode

Use Arael's CLI directly with your local LLM:

```bash
# Full analysis (JSON output)
arael analyze ./binary

# List functions
arael functions ./binary --filter "main"

# Decompile and disassemble
arael decompile ./binary --function main
arael disassemble ./binary --function main

# Strings and imports
arael strings ./binary --min-length 6
arael imports ./binary
arael exports ./binary

# Cross-references and call graph
arael xrefs ./binary --address 0x401000
arael callgraph ./binary --format mermaid --root main

# Hexdump
arael hexdump ./binary --address 0x401000 --length 128

# Interactive shell (v2.5)
arael shell ./binary

# Batch analysis (v2.5)
arael batch "./samples/*.exe" --output ./results

# YARA scanning (v2.5)
arael yara ./binary

# HTML report (v2.5)
arael report ./binary --output report.html
```

## Option 2: System Prompt

Use the following system prompt for your local LLM to enable reverse engineering assistance:

### Minimal Prompt

```
You are a reverse engineering assistant. You analyze binaries using the Arael CLI.

Available commands:
- arael analyze <path> - Full binary analysis
- arael functions <path> [--filter <regex>] - List functions
- arael decompile <path> --function <name> - Decompile function
- arael disassemble <path> --function <name> - Disassemble function
- arael strings <path> [--min-length N] - Extract strings
- arael imports <path> - List imports with capabilities
- arael exports <path> - List exported symbols
- arael xrefs <path> --address <addr> - Cross-references
- arael callgraph <path> --format mermaid - Call graph
- arael hexdump <path> --address <addr> - Dump bytes
- arael yara <path> - YARA rule scanning
- arael shell <path> - Interactive REPL mode

Workflow:
1. Run arael analyze to get an overview
2. Check arael yara for packing/malware indicators
3. Review functions and identify interesting targets
4. Decompile suspicious functions
5. Use xrefs to trace data flow
6. Generate callgraph for program structure
```

### Full XML Prompt

For better structured output, use the full XML prompt from:
`docs/LOCAL_LLM_PROMPT.xml` (included with Arael)

## Example Integration

### With llama.cpp

```bash
SYSTEM_PROMPT=$(cat docs/LOCAL_LLM_PROMPT.xml)

llama-cli \
  --model mixtral-8x7b.gguf \
  --system "$SYSTEM_PROMPT" \
  --prompt "Analyze this binary and find vulnerabilities: ./target"
```

### With Ollama

```bash
# Create a custom model with the system prompt
ollama create arael-assistant -f - <<EOF
FROM mixtral
SYSTEM $(cat docs/LOCAL_LLM_PROMPT.xml)
EOF

# Use it
ollama run arael-assistant "Analyze ./crackme and find the flag"
```

### With LM Studio

1. Load your model
2. Set the system prompt to the contents of `LOCAL_LLM_PROMPT.xml`
3. Enable shell command execution
4. Ask: "Analyze ./binary using Arael"

## Tool Calling

If your local LLM supports tool/function calling, you can define Arael tools:

```json
{
  "name": "arael_analyze",
  "description": "Analyze an ELF binary with Ghidra",
  "parameters": {
    "type": "object",
    "properties": {
      "filepath": {
        "type": "string",
        "description": "Path to the binary"
      }
    },
    "required": ["filepath"]
  }
}
```

Then implement the tool call as:
```bash
arael analyze "$filepath"
```

## Output Parsing

Arael outputs JSON by default. Parse it in your LLM integration:

```python
import subprocess
import json

def run_arael(command: list[str]) -> dict:
    result = subprocess.run(
        ["arael"] + command,
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

# Example
analysis = run_arael(["analyze", "./binary"])
print(f"Found {len(analysis['functions'])} functions")
```

## Best Practices

1. **Cache results** - Run `arael analyze` once, then query specific tools
2. **Use filters** - Reduce output size with `--filter`, `--min-length`
3. **Structured workflow** - Analyze → Functions → Decompile interesting ones
4. **Handle errors** - Check for error responses in JSON output

## Limitations

- Local LLMs don't have direct MCP access
- Each tool call requires a shell command
- Large binaries produce large JSON output (consider chunking)
