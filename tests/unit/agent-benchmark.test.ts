import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildArtifactManifest, detectFlags, extractAgentTokenUsage, parseAgentSpecs, runAgentBenchmark } from '../../src/benchmark/agent-runner';
import type { AgentBenchmarkRecord } from '../../src/benchmark/types';
import { formatAgentBenchmarkResult } from '../../src/benchmark/reporters';

describe('agent benchmark', () => {
  it('parses default agent specs by shape, not pinned model versions', () => {
    const defaults = parseAgentSpecs();

    // Claude and Codex each run as an +arael / bare pair; Antigravity (agy) runs
    // bare-only (its MCP config is global, not per-invocation) — 5 instances total.
    expect(defaults).toHaveLength(5);
    expect(defaults.map(spec => spec.engine)).toEqual([
      'claude', 'claude', 'codex', 'codex', 'antigravity'
    ]);
    expect(defaults.map(spec => spec.araelMcp)).toEqual([
      true, false, true, false, false
    ]);
    // Every default carries a non-empty model string. We intentionally do NOT
    // assert the exact version so bumping model defaults doesn't break tests.
    expect(defaults.every(spec => typeof spec.model === 'string' && spec.model.length > 0)).toBe(true);
    // The two cloud pairs target the same model across their +arael/bare variants.
    expect(defaults[0]?.model).toBe(defaults[1]?.model);
    expect(defaults[2]?.model).toBe(defaults[3]?.model);
  });

  it('parses explicit agent specs', () => {
    expect(parseAgentSpecs('codex:some-model,claude:some-model+arael,antigravity:some-model')).toEqual([
      { engine: 'codex', model: 'some-model', araelMcp: false },
      { engine: 'claude', model: 'some-model', araelMcp: true },
      { engine: 'antigravity', model: 'some-model', araelMcp: false }
    ]);

    // `agy:` is an alias for the antigravity engine, and antigravity is always bare
    // (a trailing +arael is ignored since its MCP config is global, not per-run).
    expect(parseAgentSpecs('agy:Gemini 3.5 Flash (Pro),agy:some-model+arael')).toEqual([
      { engine: 'antigravity', model: 'Gemini 3.5 Flash (Pro)', araelMcp: false },
      { engine: 'antigravity', model: 'some-model', araelMcp: false }
    ]);

    // Local model tags carry a colon (e.g. qwen3.5:4b) and never attach MCP.
    expect(parseAgentSpecs('ollama:qwen3.5:4b,ollama:mythos-nano+arael')).toEqual([
      { engine: 'ollama', model: 'qwen3.5:4b', araelMcp: false },
      { engine: 'ollama', model: 'mythos-nano', araelMcp: false }
    ]);
  });

  it('builds an Ollama HTTP dry-run record without spawning a CLI', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-agent-bench-'));
    fs.writeFileSync(path.join(tempDir, 'challenge.bin'), 'hello');

    const result = await runAgentBenchmark({
      target: tempDir,
      format: 'markdown',
      agents: parseAgentSpecs('ollama:qwen3.5:4b'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 1,
      concurrency: 1,
      force: false,
      codexBin: 'codex',
      claudeBin: 'claude',
      antigravityBin: 'agy',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    expect(result.records).toHaveLength(1);
    expect(result.records[0]?.agent).toBe('ollama');
    expect(result.records[0]?.model).toBe('qwen3.5:4b');
    expect(result.records[0]?.command.join(' ')).toContain('/api/generate');
  });

  it('builds dry-run records for challenge directories', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-agent-bench-'));
    const challengeDir = path.join(tempDir, '1 - sample');
    const assetDir = path.join(challengeDir, 'assets');
    fs.mkdirSync(challengeDir, { recursive: true });
    fs.mkdirSync(assetDir, { recursive: true });
    fs.writeFileSync(path.join(challengeDir, 'sample.bin'), 'hello');
    fs.writeFileSync(path.join(assetDir, 'asset.dat'), 'nested');

    const result = await runAgentBenchmark({
      target: tempDir,
      format: 'markdown',
      agents: parseAgentSpecs('codex:probe-model,claude:probe-model'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 1,
      concurrency: 1,
      force: false,
      codexBin: 'codex',
      claudeBin: 'claude',
      antigravityBin: 'agy',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    expect(result.challenges).toHaveLength(1);
    expect(result.records).toHaveLength(2);
    expect(result.records.every(record => record.dryRun)).toBe(true);
    expect(result.records[0]?.command.join(' ')).toContain('probe-model');
    expect(result.records[1]?.command.join(' ')).toContain('probe-model');
    expect(result.records[1]?.command.join(' ')).toContain('--output-format json');

    // Reproducibility metadata is captured for every run.
    expect(result.metadata?.agents).toEqual(['codex:probe-model', 'claude:probe-model']);
    expect(result.metadata?.promptSource).toBe('default');
    expect(result.metadata?.promptSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(typeof result.metadata?.araelVersion).toBe('string');
  });

  it('passes the Antigravity prompt as the value of --print', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-agent-bench-'));
    fs.writeFileSync(path.join(tempDir, 'challenge.bin'), 'hello');

    const result = await runAgentBenchmark({
      target: tempDir,
      format: 'markdown',
      agents: parseAgentSpecs('agy:Gemini 3.5 Flash (High)'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 1,
      concurrency: 1,
      force: false,
      codexBin: 'codex',
      claudeBin: 'claude',
      antigravityBin: 'agy',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    const command = result.records[0]!.command;
    const printIndex = command.indexOf('--print');
    expect(printIndex).toBe(command.length - 2);
    expect(command[printIndex + 1]).toContain('You are benchmarking reverse-engineering performance');
  });

  it('expands cells by run count and reports variant summaries', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-agent-bench-'));
    fs.writeFileSync(path.join(tempDir, 'challenge.bin'), 'hello');

    const result = await runAgentBenchmark({
      target: tempDir,
      format: 'markdown',
      agents: parseAgentSpecs('codex:test-model,claude:test+arael'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 3,
      concurrency: 4,
      force: false,
      codexBin: 'codex',
      claudeBin: 'claude',
      antigravityBin: 'agy',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    // 2 agents x 3 runs = 6 records, with run indices 0..2.
    expect(result.records).toHaveLength(6);
    expect(result.records.map(record => record.runIndex).sort()).toEqual([0, 0, 1, 1, 2, 2]);
    expect(result.summary.variants).toHaveLength(2);
    expect(result.summary.variants.every(variant => variant.recordCount === 3)).toBe(true);
  });

  it('grades dry-run records against ground truth', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-agent-bench-'));
    const challengeDir = path.join(tempDir, '1 - sample');
    fs.mkdirSync(challengeDir, { recursive: true });
    fs.writeFileSync(path.join(challengeDir, 'sample.bin'), 'hello');
    // Keep the ground-truth file outside the target tree so it isn't mistaken for a challenge file.
    const groundTruthPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'arael-gt-')), 'ground-truth.json');
    fs.writeFileSync(groundTruthPath, JSON.stringify({ '1 - sample': 'win@flare-on.com' }));

    const result = await runAgentBenchmark({
      target: tempDir,
      format: 'markdown',
      agents: parseAgentSpecs('codex:test-model'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 1,
      concurrency: 1,
      force: false,
      groundTruthPath,
      codexBin: 'codex',
      claudeBin: 'claude',
      antigravityBin: 'agy',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    // Dry run never executes, so a graded challenge is recorded as not-yet-solved.
    expect(result.records[0]?.flagCorrect).toBe(false);
    expect(result.summary.gradedCount).toBe(1);
    expect(result.summary.solveCount).toBe(0);
  });

  it('formats agent benchmark reports', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-agent-bench-'));
    fs.writeFileSync(path.join(tempDir, 'challenge.bin'), 'hello');
    const result = await runAgentBenchmark({
      target: tempDir,
      format: 'markdown',
      agents: parseAgentSpecs('codex:test-model'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 1,
      concurrency: 1,
      force: false,
      codexBin: 'codex',
      claudeBin: 'claude',
      antigravityBin: 'agy',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    expect(formatAgentBenchmarkResult(result, 'json')).toContain('"records"');
    expect(formatAgentBenchmarkResult(result, 'jsonl')).toContain('"agent"');
    expect(formatAgentBenchmarkResult(result, 'csv')).toContain('challenge_id');
    expect(formatAgentBenchmarkResult(result, 'csv')).toContain('cost_usd');
    const variantCsv = formatAgentBenchmarkResult(result, 'variant-csv');
    expect(variantCsv).toContain('solve_rate');
    expect(variantCsv).toContain('cost_per_solve');
    expect(variantCsv).toContain('codex:test-model');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('# Arael Agent Benchmark Report');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('Leaderboard (by variant)');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('Solve Rate');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('Cost USD');
    expect(formatAgentBenchmarkResult(result, 'html')).toContain('<!DOCTYPE html>');
    expect(formatAgentBenchmarkResult(result, 'html')).toContain('Leaderboard');
  });

  it('detects flag-shaped tokens', () => {
    expect(detectFlags('the flag is th1s_1s_t3h@flare-on.com nice')).toEqual(['th1s_1s_t3h@flare-on.com']);
    expect(detectFlags('candidate flag{some_value_123}')).toEqual(['flag{some_value_123}']);
    expect(detectFlags('no flags here')).toEqual([]);
  });

  it('builds an artifact manifest with paths relative to the output root', () => {
    const outputRoot = path.join(os.tmpdir(), 'run-abc.artifacts');
    const stdoutPath = path.join(outputRoot, '1_-_sample', 'codex-gpt-arael.stdout.txt');
    const record: AgentBenchmarkRecord = {
      runId: 'run-1',
      timestamp: '2026-01-01T00:00:00.000Z',
      challengeId: '1 - sample',
      challengePath: '/tmp/1 - sample',
      agent: 'codex',
      model: 'gpt',
      araelMcp: true,
      runIndex: 0,
      command: ['codex', 'exec'],
      success: true,
      exitCode: 0,
      timedOut: false,
      durationSeconds: 12,
      inputTokens: 100,
      outputTokens: 50,
      totalTokens: 150,
      costUsd: 0.02,
      flag: 'win@flare-on.com',
      flagFound: true,
      flagCorrect: true,
      stdoutPath,
      stderrPath: stdoutPath.replace('.stdout.txt', '.stderr.txt'),
      outputPreview: 'win@flare-on.com',
      errorMessage: null,
      resumed: false,
      dryRun: false
    };

    const manifest = buildArtifactManifest(outputRoot, 'run-1', '2026-01-01T00:00:00.000Z', [record]);

    expect(manifest.entries).toHaveLength(1);
    const entry = manifest.entries[0]!;
    expect(entry.variant).toBe('codex:gpt+arael');
    expect(entry.solved).toBe(true);
    expect(entry.stdout).toBe('1_-_sample/codex-gpt-arael.stdout.txt');
    expect(entry.stderr).toBe('1_-_sample/codex-gpt-arael.stderr.txt');
    expect(entry.record).toBe('1_-_sample/codex-gpt-arael.record.json');
  });

  it('extracts token usage from agent output', () => {
    expect(extractAgentTokenUsage('tokens used\n48,944')).toEqual({
      inputTokens: null,
      outputTokens: null,
      totalTokens: 48944
    });

    expect(extractAgentTokenUsage('{"usageMetadata":{"promptTokenCount":123,"candidatesTokenCount":45,"totalTokenCount":168}}')).toEqual({
      inputTokens: 123,
      outputTokens: 45,
      totalTokens: 168
    });
  });
});
