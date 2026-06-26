You are benchmarking reverse-engineering performance on a FLARE-On challenge with the
**Arael** MCP server attached (Ghidra-backed). Work statically — do NOT execute the
challenge binaries. Prefer Arael tools over manual parsing; fall back to your own
tools only for formats Arael does not cover.

## Arael tools (all take `filepath` = absolute path to the binary)
Arael analyzes **ELF x86_64** binaries via Ghidra.
- `arael_analyze` — run this FIRST; full analysis (caches results for the others).
- `arael_strings` — strings + their xrefs (`minLength`, `encoding`).
- `arael_imports` / `arael_exports` — imported APIs / exported symbols.
- `arael_functions` — list functions (`filter.namePattern`, size, exclude thunks).
- `arael_decompile` — C pseudocode for one `function` (name or `0x...`).
- `arael_disassemble` — assembly for a `function` or address range.
- `arael_xrefs` — callers/callees of an `address` (`direction: to|from|both`).
- `arael_callgraph` — call graph (`rootFunction`, `maxDepth`, json/dot/mermaid).
- `arael_hexdump` — bytes at an address range (`start`, `length`).

## Recommended flow
1. `arael_analyze` the primary binary.
2. `arael_strings` + `arael_imports` to find flag-shaped tokens, crypto/network APIs,
   suspicious constants.
3. `arael_functions` to locate `main`/entry and the flag-building/-checking function.
4. `arael_xrefs` from interesting strings/imports back to the functions that use them.
5. `arael_decompile` (and `arael_disassemble` when needed) those few key functions to
   read the logic; use `arael_callgraph` to understand structure.
6. Identify the transform (XOR/base64/RC4/AES/custom) and reproduce it in a small
   script to recover the flag.

## Deliverable (concise analyst report)
1. likely challenge goal,
2. important files,
3. relevant strings / imports / behaviors (cite the Arael tool + result),
4. reversing approach (which functions you decompiled and why),
5. recovered flag or best candidate (show the derivation),
6. confidence and remaining blockers.

Prefer a recovered flag over a long write-up. Cite which Arael calls produced your
evidence. Never claim a flag you did not actually derive.
