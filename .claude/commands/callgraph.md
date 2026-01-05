# Call Graph

Generate call graph for: $ARGUMENTS

Use the `arael_callgraph` MCP tool to visualize function relationships.

Arguments: `[function] [format]`
- function: root function (optional, defaults to all)
- format: `json`, `dot`, or `mermaid` (optional, defaults to mermaid)

Examples:
- `/callgraph main` - Graph from main in mermaid
- `/callgraph main dot` - Graph from main in DOT format
- `/callgraph` - Full program graph
