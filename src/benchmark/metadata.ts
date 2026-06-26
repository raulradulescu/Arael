import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFileSync } from 'child_process';
import type { ReproducibilityMetadata } from './types';

export interface CollectMetadataInput {
  generatedAt: string;
  /** Human label for the prompt origin: 'default' or the file path used. */
  promptSource: string;
  /** The exact prompt text sent to the agents, for hashing. */
  promptText: string;
  pricingFile?: string;
  groundTruthFile?: string;
  /** Agent variant labels, e.g. ['codex:gpt-5.5+arael', 'ollama:qwen3.5:4b']. */
  agents: string[];
  runs: number;
  concurrency: number;
  timeoutSeconds: number;
  ollamaUrl: string;
  araelServerPath?: string;
}

/**
 * Capture an environment + configuration snapshot for a benchmark run so results
 * are reproducible and auditable. Every probe is best-effort: a failure degrades to
 * a null/unknown field rather than throwing, so metadata never breaks a run.
 */
export function collectReproducibilityMetadata(input: CollectMetadataInput): ReproducibilityMetadata {
  return {
    generatedAt: input.generatedAt,
    araelVersion: readAraelVersion(),
    gitCommit: readGitCommit(),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    osType: safe(() => os.type()) ?? 'unknown',
    osRelease: safe(() => os.release()) ?? 'unknown',
    cpuCount: safe(() => os.cpus().length) ?? 0,
    totalMemoryMb: safe(() => Math.round(os.totalmem() / (1024 * 1024))) ?? 0,
    cwd: process.cwd(),
    agents: input.agents,
    runs: input.runs,
    concurrency: input.concurrency,
    timeoutSeconds: input.timeoutSeconds,
    ollamaUrl: input.ollamaUrl,
    promptSource: input.promptSource,
    promptSha256: sha256OfString(input.promptText),
    pricingFile: input.pricingFile ?? null,
    pricingSha256: input.pricingFile ? sha256OfFile(input.pricingFile) : null,
    groundTruthFile: input.groundTruthFile ?? null,
    groundTruthSha256: input.groundTruthFile ? sha256OfFile(input.groundTruthFile) : null,
    ghidraPath: process.env.GHIDRA_PATH ?? null,
    araelPython: process.env.ARAEL_PYTHON ?? null,
    araelServerPath: input.araelServerPath ?? null
  };
}

function readAraelVersion(): string {
  // dist/benchmark/metadata.js -> ../../package.json; same relative depth under src.
  const candidate = path.join(__dirname, '..', '..', 'package.json');
  const version = safe(() => {
    const pkg = JSON.parse(fs.readFileSync(candidate, 'utf-8')) as { version?: string };
    return pkg.version;
  });
  return version ?? 'unknown';
}

function readGitCommit(): string | null {
  return safe(() => execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf-8' }).trim()) ?? null;
}

function sha256OfString(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf-8').digest('hex');
}

function sha256OfFile(filePath: string): string | null {
  return safe(() => crypto.createHash('sha256').update(fs.readFileSync(path.resolve(filePath))).digest('hex')) ?? null;
}

function safe<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}
