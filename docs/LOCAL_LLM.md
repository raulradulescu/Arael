# Local LLM Integration

Arael can be used with local LLMs that don't support MCP directly. This guide explains how to integrate Arael with local models.

## Option 1: CLI Mode

Use Arael's CLI directly with your local LLM:

```bash
# Full analysis (JSON output)
arael analyze ./binary

# Human-readable summary
arael analyze ./binary --output summary

# Specific queries
arael functions ./binary
arael decompile ./binary --function main
arael strings ./binary --min-length 6
arael imports ./binary
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
- arael strings <path> [--min-length N] - Extract strings
- arael imports <path> - List imports
- arael hexdump <path> --address <addr> - Dump bytes

Workflow:
1. Run arael analyze to get an overview
2. Review functions and identify interesting targets
3. Decompile suspicious functions
4. Cross-reference strings and imports
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
