import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { detectFlags, extractAgentTokenUsage, parseAgentSpecs, runAgentBenchmark } from '../../src/benchmark/agent-runner';
import { formatAgentBenchmarkResult } from '../../src/benchmark/reporters';

describe('agent benchmark', () => {
  it('parses default and explicit agent specs', () => {
    expect(parseAgentSpecs()).toEqual([
      { engine: 'claude', model: 'claude-opus-4-8', araelMcp: true },
      { engine: 'claude', model: 'claude-opus-4-8', araelMcp: false },
      { engine: 'codex', model: 'gpt-5.5', araelMcp: true },
      { engine: 'codex', model: 'gpt-5.5', araelMcp: false },
      { engine: 'gemini', model: 'gemini-3-pro', araelMcp: true },
      { engine: 'gemini', model: 'gemini-3-pro', araelMcp: false }
    ]);

    expect(parseAgentSpecs('codex:gpt-5.5,claude:opus+arael,gemini:gemini-3-pro')).toEqual([
      { engine: 'codex', model: 'gpt-5.5', araelMcp: false },
      { engine: 'claude', model: 'opus', araelMcp: true },
      { engine: 'gemini', model: 'gemini-3-pro', araelMcp: false }
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
      geminiBin: 'gemini',
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
      agents: parseAgentSpecs('codex:gpt-5.5,claude:claude-opus-4-8'),
      timeoutSeconds: 30,
      extractArchives: false,
      runs: 1,
      concurrency: 1,
      force: false,
      codexBin: 'codex',
      claudeBin: 'claude',
      geminiBin: 'gemini',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    expect(result.challenges).toHaveLength(1);
    expect(result.records).toHaveLength(2);
    expect(result.records.every(record => record.dryRun)).toBe(true);
    expect(result.records[0]?.command.join(' ')).toContain('gpt-5.5');
    expect(result.records[1]?.command.join(' ')).toContain('claude-opus-4-8');
    expect(result.records[1]?.command.join(' ')).toContain('--output-format json');
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
      geminiBin: 'gemini',
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
      geminiBin: 'gemini',
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
      geminiBin: 'gemini',
      ollamaUrl: 'http://localhost:11434',
      dryRun: true
    });

    expect(formatAgentBenchmarkResult(result, 'json')).toContain('"records"');
    expect(formatAgentBenchmarkResult(result, 'jsonl')).toContain('"agent"');
    expect(formatAgentBenchmarkResult(result, 'csv')).toContain('challenge_id');
    expect(formatAgentBenchmarkResult(result, 'csv')).toContain('cost_usd');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('# Arael Agent Benchmark Report');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('Leaderboard (by variant)');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('Solve Rate');
    expect(formatAgentBenchmarkResult(result, 'markdown')).toContain('Cost USD');
  });

  it('detects flag-shaped tokens', () => {
    expect(detectFlags('the flag is th1s_1s_t3h@flare-on.com nice')).toEqual(['th1s_1s_t3h@flare-on.com']);
    expect(detectFlags('candidate flag{some_value_123}')).toEqual(['flag{some_value_123}']);
    expect(detectFlags('no flags here')).toEqual([]);
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
