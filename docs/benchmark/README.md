# Agent benchmark

Arael ships a benchmark harness that runs reverse-engineering agents against challenge
directories, grades their output against known flags, and compares them on solve rate,
time, tokens, and cost. It's how the A/B question — *does attaching Arael's MCP tools
actually help an agent solve harder binaries?* — gets answered with numbers instead of
vibes.

Entry point: `runAgentBenchmark()` in `src/benchmark/agent-runner.ts`, exposed on the CLI
as `arael benchmark-agents <target>`.

## What a run does

1. Collects challenge leaf directories under the target (optionally extracting `.7z`/`.zip`
   archives first, e.g. the FLARE-On corpus with password `flare`).
2. For each `engine × model × variant` cell, spawns the agent as an independent process,
   hands it one challenge and a reversing prompt, and captures stdout/stderr.
3. Grades the output. With `--ground-truth`, a trial is **solved** only if the expected
   flag appears verbatim; without it, any flag-shaped token (`…@flare-on.com`, `name{…}`)
   counts.
4. Writes a per-cell `*.record.json` so reruns resume instead of repeating finished work,
   and rolls everything up into a report.

## Engines and variants

Specs are `engine:model[+arael]`, comma-separated via `--agents`.

| Engine   | What it is                                  | `+arael` |
|----------|---------------------------------------------|----------|
| `claude` | Claude Code CLI (`--print`)                 | yes — `--mcp-config` |
| `codex`  | Codex CLI (`exec`)                          | yes — `mcp_servers.arael` |
| `gemini` | Gemini CLI (`--yolo`)                        | yes — `.gemini/settings.json` |
| `ollama` | Local model over the Ollama HTTP API        | n/a (prompt-only baseline) |

The `+arael` variant attaches the Arael MCP server (Ghidra-backed disassembly, decompile,
strings, imports, xrefs, callgraph). The bare variant gives the agent only its own tools,
so the two columns isolate Arael's contribution. Arael analyzes ELF x86_64.

## How a trial is scored

Every trial lands in one canonical outcome (the `canonical_outcome` column in
`results/summary.csv`):

- `solved` — graded correct.
- `completed_unsolved` — agent finished, no correct flag. A legitimate, expected result on
  hard challenges.
- `timeout_unsolved` — hit the per-run timeout (`--timeout`, default 1800s).
- `incomplete_or_infrastructure_failure` — the run never really executed (quota, crash,
  environment). Excluded from solve-rate denominators.
- `dry_run_only` — `--dry-run`, nothing actually ran.

Solve rate is computed over *analytically valid* trials, so infrastructure noise doesn't
inflate or deflate the numbers.

## Running it

```bash
node dist/cli/index.js benchmark-agents ".arael/benchmark-corpus/flare-on" \
  --extract-archives --archive-password flare \
  --agents "claude:claude-opus-4-8+arael,claude:claude-opus-4-8,codex:gpt-5.5,ollama:qwen2.5-coder:7b" \
  --ground-truth flare-flags.json --pricing pricing.json \
  --runs 3 --concurrency 2 --timeout 900 \
  --format html -o ".arael/benchmark-results/run.html"
```

The reversing prompts live in `prompts/` (`re-with-arael.md`, `re-without-arael.md`) and
`bench-prompt-noweb.txt`; pass one with `--prompt`. Note the ground-truth flag file is a
local input and is not committed — the reports below already bake in the grading.

## Sample results

The reports in [`results/`](results/) are saved HTML from real runs on the FLARE-On 2025
corpus. Open them in a browser; each has a summary, a leaderboard by variant, and a
searchable per-run table.

| Report | Covers |
|--------|--------|
| [`claude-vs-codex.html`](results/claude-vs-codex.html) | Claude vs Codex, head to head |
| [`claude-flare-5-8.html`](results/claude-flare-5-8.html) | Claude on the harder challenges 5–8, `+arael` vs bare |
| [`gemini-arael-flare-1-8.html`](results/gemini-arael-flare-1-8.html) | Gemini across the full 1–8 range with Arael attached |
| [`ollama-local-baseline.html`](results/ollama-local-baseline.html) | Local Ollama models as a zero-cost baseline (30 runs) |

`results/summary.csv` is the aggregated per-cell table behind these, one row per
`challenge × agent × variant`.
