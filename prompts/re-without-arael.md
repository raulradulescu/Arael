You are benchmarking reverse-engineering performance on a FLARE-On challenge using
ONLY your own tooling (no Arael / no Ghidra MCP). Work statically — do NOT execute
the challenge binaries.

## Allowed methods
Reading files and metadata, `file`/`strings`/`xxd`/`objdump`/`readelf`/`nm`, a
disassembler/decompiler you already have, and small throwaway scripts that *parse*
bytes (never run the sample).

## What to look for (in order)
1. **Triage** — file type, format (ELF/PE/Mach-O/.NET/script/packed), architecture,
   bitness, whether it is stripped or packed (high entropy, UPX/odd section names).
2. **Strings** — flag-shaped tokens (`...@flare-on.com`, `flag{...}`), URLs, paths,
   registry keys, error/debug text, format strings, crypto constants, base64 blobs.
3. **Imports / symbols** — APIs that reveal behavior (network, crypto, file, process,
   anti-debug). Map suspicious imports to the functions that call them.
4. **Entry & key functions** — locate `main`/entry, then the function(s) that build,
   check, or print the flag. Decompile those; read the logic, not every function.
5. **Transforms** — identify XOR/add/sub/rotate loops, base64/hex, RC4/AES, custom
   encodings. Reproduce them in a small script to recover the answer.

## Deliverable (concise analyst report)
1. likely challenge goal,
2. important files,
3. relevant strings / imports / behaviors,
4. reversing approach (what you inspected and why),
5. recovered flag or best candidate (show the work that produced it),
6. confidence and remaining blockers.

Prefer a recovered flag over a long write-up. State assumptions explicitly; never
claim a flag you did not actually derive.
