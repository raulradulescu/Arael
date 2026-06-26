import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { spawn } from 'child_process';
import { expandArchives, isArchivePath } from './archives';
import { loadPricingTable } from './manifest';
import { calculateCost } from './llm';
import { collectReproducibilityMetadata } from './metadata';
import type {
  AgentBenchmarkOptions,
  AgentBenchmarkRecord,
  AgentBenchmarkRunResult,
  AgentBenchmarkSummary,
  AgentEngine,
  AgentSpec,
  AgentVariantSummary,
  ArtifactManifest,
  ChallengeTarget,
  PricingTable
} from './types';

/** Map an agent engine to the provider key used in the pricing table. */
const ENGINE_PROVIDER: Record<AgentEngine, string> = {
  claude: 'anthropic',
  codex: 'openai',
  gemini: 'google',
  ollama: 'ollama'
};

/** Expected flag(s) per challenge, used for auto-grading. */
type GroundTruth = Map<string, string[]>;

interface AgentTokenUsage {
  inputTokens: number | null;
  outputTokens: number | null;
  totalTokens: number | null;
}

const DEFAULT_PROMPT = `You are benchmarking reverse-engineering performance on a FLARE-On challenge.

Analyze the challenge directory using static reverse-engineering methods. Do not execute challenge binaries.
Allowed methods include reading files, file metadata, strings, hexdumps, disassembly/decompilation tools, and small helper scripts that parse bytes.

Return a concise analyst report with:
1. likely challenge goal,
2. important files,
3. relevant strings/imports/behaviors,
4. reversing approach,
5. recovered flag or candidate flag if found,
6. confidence and remaining blockers.`;

export function parseAgentSpecs(value?: string): AgentSpec[] {
  if (!value || value.trim().length === 0) {
    // Default matrix: each engine on its latest model, run twice — once with the
    // Arael MCP server attached (+arael) and once bare.
    return [
      { engine: 'claude', model: 'claude-opus-4-8', araelMcp: true },
      { engine: 'claude', model: 'claude-opus-4-8', araelMcp: false },
      { engine: 'codex', model: 'gpt-5.5', araelMcp: true },
      { engine: 'codex', model: 'gpt-5.5', araelMcp: false },
      { engine: 'gemini', model: 'gemini-3-pro', araelMcp: true },
      { engine: 'gemini', model: 'gemini-3-pro', araelMcp: false }
    ];
  }

  return value.split(',').map(part => {
    // Local model names contain colons (e.g. ollama:qwen3.5:4b), so split on the first colon only.
    const trimmed = part.trim();
    const sep = trimmed.indexOf(':');
    const engine = sep === -1 ? trimmed : trimmed.slice(0, sep);
    const modelSpec = sep === -1 ? '' : trimmed.slice(sep + 1);
    if (engine !== 'codex' && engine !== 'claude' && engine !== 'gemini' && engine !== 'ollama') {
      throw new Error(`Invalid agent engine in spec "${part}". Use codex:<model>, claude:<model>, gemini:<model>, or ollama:<model> (append +arael to attach the Arael MCP server; ignored for ollama).`);
    }
    if (!modelSpec) {
      throw new Error(`Missing model in agent spec "${part}"`);
    }
    // A trailing "+arael" marks this instance for Arael MCP attachment.
    const araelMcp = /\+arael$/i.test(modelSpec);
    const model = modelSpec.replace(/\+arael$/i, '');
    if (!model) {
      throw new Error(`Missing model in agent spec "${part}"`);
    }
    // The local baseline runs prompt-only, so MCP attachment doesn't apply to ollama.
    return { engine, model, araelMcp: engine === 'ollama' ? false : araelMcp };
  });
}

interface AraelWiring {
  /** Absolute path to the Arael MCP server entrypoint (dist/mcp/server.js). */
  serverPath: string;
  /** Claude-format MCP config file (also reused as the Gemini settings source). */
  mcpConfigPath: string;
}

/**
 * Resolve the Arael MCP server path and emit a Claude-format MCP config file that
 * the +arael instances point their CLIs at. Returns null when no agent requests it.
 */
function prepareAraelWiring(options: AgentBenchmarkOptions, outputRoot: string): AraelWiring | null {
  if (!options.agents.some(agent => agent.araelMcp)) {
    return null;
  }

  // Default to the built server next to this file (dist/benchmark -> dist/mcp/server.js).
  const serverPath = path.resolve(options.araelServerPath ?? path.join(__dirname, '..', 'mcp', 'server.js'));
  const mcpConfigPath = path.join(outputRoot, 'arael-mcp.json');
  const config = {
    mcpServers: {
      arael: {
        command: 'node',
        args: [serverPath]
      }
    }
  };
  fs.writeFileSync(mcpConfigPath, JSON.stringify(config, null, 2));
  return { serverPath, mcpConfigPath };
}

export async function runAgentBenchmark(options: AgentBenchmarkOptions): Promise<AgentBenchmarkRunResult> {
  const runId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const targetRoot = prepareTargetRoot(options);
  const challenges = collectChallengeTargets(targetRoot, options.maxChallenges);
  const outputRoot = path.resolve(options.outputPath
    ? `${options.outputPath}.artifacts`
    : path.join('.arael', 'benchmark-results', 'agents', runId));
  fs.mkdirSync(outputRoot, { recursive: true });

  const prompt = options.promptPath
    ? fs.readFileSync(path.resolve(options.promptPath), 'utf-8')
    : DEFAULT_PROMPT;

  const wiring = prepareAraelWiring(options, outputRoot);
  const pricing = options.pricingFile ? loadPricingTable(options.pricingFile) : undefined;
  const groundTruth = loadGroundTruth(options.groundTruthPath);

  // Build the full grid of work cells: challenge × agent × repeat. Each cell is an
  // independent agent process, so they can run concurrently up to the pool size.
  const runs = Math.max(1, options.runs);
  const cells: Array<{ challenge: ChallengeTarget; agent: AgentSpec; runIndex: number }> = [];
  for (const challenge of challenges) {
    for (const agent of options.agents) {
      for (let runIndex = 0; runIndex < runs; runIndex++) {
        cells.push({ challenge, agent, runIndex });
      }
    }
  }

  const records: AgentBenchmarkRecord[] = new Array(cells.length);
  const concurrency = Math.max(1, options.dryRun ? 1 : options.concurrency);
  let nextCell = 0;
  const worker = async (): Promise<void> => {
    for (let index = nextCell++; index < cells.length; index = nextCell++) {
      const cell = cells[index];
      if (!cell) {
        continue;
      }
      records[index] = await runAgentOnChallenge({
        runId,
        timestamp,
        agent: cell.agent,
        challenge: cell.challenge,
        runIndex: cell.runIndex,
        totalRuns: runs,
        outputRoot,
        prompt,
        wiring,
        pricing,
        groundTruth,
        options
      });
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, cells.length || 1) }, worker));

  const metadata = collectReproducibilityMetadata({
    generatedAt: timestamp,
    promptSource: options.promptPath ?? 'default',
    promptText: prompt,
    pricingFile: options.pricingFile,
    groundTruthFile: options.groundTruthPath,
    agents: options.agents.map(agent => `${agent.engine}:${agent.model}${agent.araelMcp ? '+arael' : ''}`),
    runs,
    concurrency,
    timeoutSeconds: options.timeoutSeconds,
    ollamaUrl: options.ollamaUrl,
    araelServerPath: wiring?.serverPath ?? options.araelServerPath
  });

  // Write a manifest mapping each real run to its artifacts (skip pure dry runs,
  // which produce no files). Makes HTML links and later analysis robust.
  if (records.some(record => !record.dryRun)) {
    writeArtifactManifest(outputRoot, runId, timestamp, records);
  }

  return {
    runId,
    timestamp,
    challenges,
    records,
    summary: summarizeAgentBenchmark(challenges, options.agents, records),
    metadata
  };
}

/** Build the artifact manifest object (pure; paths are relative to outputRoot). */
export function buildArtifactManifest(
  outputRoot: string,
  runId: string,
  timestamp: string,
  records: AgentBenchmarkRecord[]
): ArtifactManifest {
  const relative = (target: string | null): string | null =>
    target === null ? null : path.relative(outputRoot, target).replace(/\\/g, '/');

  return {
    runId,
    timestamp,
    generatedAt: new Date().toISOString(),
    outputRoot,
    entries: records.map(record => ({
      challengeId: record.challengeId,
      agent: record.agent,
      model: record.model,
      araelMcp: record.araelMcp,
      variant: `${record.agent}:${record.model}${record.araelMcp ? '+arael' : ''}`,
      runIndex: record.runIndex,
      success: record.success,
      solved: isSolved(record),
      flag: record.flag,
      stdout: relative(record.stdoutPath),
      stderr: relative(record.stderrPath),
      record: relative(recordPathFromStdout(record.stdoutPath))
    }))
  };
}

function writeArtifactManifest(
  outputRoot: string,
  runId: string,
  timestamp: string,
  records: AgentBenchmarkRecord[]
): void {
  const manifest = buildArtifactManifest(outputRoot, runId, timestamp, records);
  fs.writeFileSync(path.join(outputRoot, 'manifest.json'), JSON.stringify(manifest, null, 2));
}

/** Derive the per-cell record.json path from its stdout path (mirrors the artifact naming). */
function recordPathFromStdout(stdoutPath: string | null): string | null {
  if (stdoutPath === null) {
    return null;
  }
  return stdoutPath.endsWith('.stdout.txt')
    ? `${stdoutPath.slice(0, -'.stdout.txt'.length)}.record.json`
    : `${stdoutPath}.record.json`;
}

/** Load a challengeId -> expected flag(s) map from a JSON ground-truth file. */
function loadGroundTruth(groundTruthPath?: string): GroundTruth {
  const map: GroundTruth = new Map();
  if (!groundTruthPath) {
    return map;
  }

  const parsed = JSON.parse(fs.readFileSync(path.resolve(groundTruthPath), 'utf-8')) as Record<string, unknown>;
  for (const [challengeId, value] of Object.entries(parsed)) {
    const flags = normalizeGroundTruthFlags(value);
    if (flags.length > 0) {
      map.set(challengeId, flags);
    }
  }
  return map;
}

function normalizeGroundTruthFlags(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value.trim()].filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string').map(item => item.trim()).filter(Boolean);
  }
  if (value && typeof value === 'object') {
    const flag = (value as Record<string, unknown>).flag;
    const flags = (value as Record<string, unknown>).flags;
    return [...normalizeGroundTruthFlags(flag), ...normalizeGroundTruthFlags(flags)];
  }
  return [];
}

function prepareTargetRoot(options: AgentBenchmarkOptions): string {
  if (!options.extractArchives) {
    return path.resolve(options.target);
  }

  const extraction = expandArchives({
    target: options.target,
    password: options.archivePassword,
    outputDir: options.extractOutput,
    maxNestedArchives: options.maxChallenges
  });

  return extraction.outputRoot;
}

function collectChallengeTargets(root: string, maxChallenges?: number): ChallengeTarget[] {
  const absoluteRoot = path.resolve(root);
  if (!fs.existsSync(absoluteRoot)) {
    throw new Error(`Agent benchmark target does not exist: ${absoluteRoot}`);
  }

  const stats = fs.statSync(absoluteRoot);
  if (stats.isFile()) {
    if (isArchivePath(absoluteRoot)) {
      throw new Error(`Target is an archive. Re-run with --extract-archives and --archive-password.`);
    }
    return [challengeFromPath(path.dirname(absoluteRoot))];
  }

  const leafDirs = findChallengeLeafDirs(absoluteRoot);
  const targets = (leafDirs.length > 0 ? leafDirs : [absoluteRoot])
    .map(challengeFromPath)
    .filter(challenge => challenge.fileCount > 0)
    .sort((a, b) => a.challengeId.localeCompare(b.challengeId, undefined, { numeric: true }));

  return maxChallenges ? targets.slice(0, maxChallenges) : targets;
}

function findChallengeLeafDirs(root: string): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(root, { withFileTypes: true });
  const childDirs = entries
    .filter(entry => entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'extracted')
    .map(entry => path.join(root, entry.name));

  const hasNonArchiveFile = entries.some(entry =>
    entry.isFile() && !isArchivePath(path.join(root, entry.name)) && entry.name !== 'PASSWORD.txt'
  );

  if (hasNonArchiveFile) {
    results.push(root);
    return results;
  }

  for (const child of childDirs) {
    results.push(...findChallengeLeafDirs(child));
  }

  return results;
}

function challengeFromPath(challengePath: string): ChallengeTarget {
  const files = collectFiles(challengePath);
  return {
    challengeId: path.basename(challengePath),
    path: challengePath,
    fileCount: files.length,
    totalBytes: files.reduce((sum, file) => sum + fs.statSync(file).size, 0)
  };
}

function collectFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath));
    } else if (entry.isFile() && !isArchivePath(fullPath) && entry.name !== 'PASSWORD.txt') {
      results.push(fullPath);
    }
  }
  return results;
}

async function runAgentOnChallenge(input: {
  runId: string;
  timestamp: string;
  agent: AgentSpec;
  challenge: ChallengeTarget;
  runIndex: number;
  totalRuns: number;
  outputRoot: string;
  prompt: string;
  wiring: AraelWiring | null;
  pricing: PricingTable | undefined;
  groundTruth: GroundTruth;
  options: AgentBenchmarkOptions;
}): Promise<AgentBenchmarkRecord> {
  const command = buildAgentCommand(input.agent, input.challenge, input.prompt, input.options, input.wiring);
  const start = process.hrtime.bigint();
  const runSuffix = input.totalRuns > 1 ? `-r${input.runIndex}` : '';
  const artifactPrefix = path.join(
    input.outputRoot,
    sanitizeName(input.challenge.challengeId),
    `${input.agent.engine}-${sanitizeName(input.agent.model)}${input.agent.araelMcp ? '-arael' : ''}${runSuffix}`
  );
  fs.mkdirSync(path.dirname(artifactPrefix), { recursive: true });
  const stdoutPath = `${artifactPrefix}.stdout.txt`;
  const stderrPath = `${artifactPrefix}.stderr.txt`;
  const recordPath = `${artifactPrefix}.record.json`;
  const expectedFlags = input.groundTruth.get(input.challenge.challengeId) ?? [];

  if (input.options.dryRun) {
    return {
      runId: input.runId,
      timestamp: input.timestamp,
      challengeId: input.challenge.challengeId,
      challengePath: input.challenge.path,
      agent: input.agent.engine,
      model: input.agent.model,
      araelMcp: input.agent.araelMcp,
      runIndex: input.runIndex,
      command,
      success: true,
      exitCode: 0,
      timedOut: false,
      durationSeconds: 0,
      inputTokens: null,
      outputTokens: null,
      totalTokens: null,
      costUsd: null,
      flag: null,
      flagFound: false,
      flagCorrect: expectedFlags.length > 0 ? false : null,
      stdoutPath: null,
      stderrPath: null,
      outputPreview: command.join(' '),
      errorMessage: null,
      resumed: false,
      dryRun: true
    };
  }

  // Resume: reuse a cached per-cell record unless --force was given.
  if (!input.options.force && fs.existsSync(recordPath)) {
    const cached = readCachedRecord(recordPath);
    if (cached) {
      return { ...cached, resumed: true };
    }
  }

  // Ollama is a local HTTP model, not a spawned agentic CLI: feed it a static
  // context extracted from the challenge and treat its reply as the report.
  let result: CommandResult;
  let parsedUsage: AgentTokenUsage | null = null;
  if (input.agent.engine === 'ollama') {
    const ollamaPrompt = `${input.prompt}\n\nChallenge directory: ${input.challenge.path}\n\n${buildChallengeContext(input.challenge.path)}`;
    const ollama = await runOllama({
      url: input.options.ollamaUrl,
      model: input.agent.model,
      prompt: ollamaPrompt,
      timeoutSeconds: input.options.timeoutSeconds
    });
    result = ollama.result;
    parsedUsage = ollama.usage;
  } else {
    // Gemini has no inline-MCP CLI flag; it reads .gemini/settings.json from cwd.
    if (input.agent.engine === 'gemini' && input.agent.araelMcp && input.wiring) {
      writeGeminiSettings(input.challenge.path, input.wiring.serverPath);
    }
    result = await runCommand(command, {
      cwd: input.challenge.path,
      timeoutSeconds: input.options.timeoutSeconds
    });
  }

  fs.writeFileSync(stdoutPath, result.stdout);
  fs.writeFileSync(stderrPath, result.stderr);

  // Claude --output-format json wraps the report; pull the result text + usage from it.
  // Ollama returns usage out of band, so use it directly when present.
  const parsed = parsedUsage
    ? { text: result.stdout, usage: parsedUsage }
    : parseAgentOutput(input.agent.engine, result.stdout);
  const tokenUsage = mergeTokenUsage(parsed.usage, extractAgentTokenUsage(result.stderr));
  const costUsd = input.agent.engine === 'ollama'
    ? 0 // Local inference has no per-token API cost.
    : tokenUsage.inputTokens !== null || tokenUsage.outputTokens !== null
      ? calculateCost(
          input.pricing,
          ENGINE_PROVIDER[input.agent.engine],
          input.agent.model,
          tokenUsage.inputTokens ?? 0,
          tokenUsage.outputTokens ?? 0
        )
      : null;

  const grade = gradeFlags(parsed.text, result.stderr, expectedFlags);

  const record: AgentBenchmarkRecord = {
    runId: input.runId,
    timestamp: input.timestamp,
    challengeId: input.challenge.challengeId,
    challengePath: input.challenge.path,
    agent: input.agent.engine,
    model: input.agent.model,
    araelMcp: input.agent.araelMcp,
    runIndex: input.runIndex,
    command,
    success: result.exitCode === 0 && !result.timedOut,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    durationSeconds: Number(process.hrtime.bigint() - start) / 1_000_000_000,
    inputTokens: tokenUsage.inputTokens,
    outputTokens: tokenUsage.outputTokens,
    totalTokens: tokenUsage.totalTokens,
    costUsd,
    flag: grade.flag,
    flagFound: grade.flagFound,
    flagCorrect: grade.flagCorrect,
    stdoutPath,
    stderrPath,
    outputPreview: parsed.text.slice(0, 2000),
    errorMessage: result.timedOut ? `Timed out after ${input.options.timeoutSeconds}s` : result.errorMessage,
    resumed: false,
    dryRun: false
  };

  fs.writeFileSync(recordPath, JSON.stringify(record, null, 2));
  return record;
}

function readCachedRecord(recordPath: string): AgentBenchmarkRecord | null {
  try {
    return JSON.parse(fs.readFileSync(recordPath, 'utf-8')) as AgentBenchmarkRecord;
  } catch {
    return null;
  }
}

/**
 * Pull the human-readable report text and token usage out of an agent's stdout.
 * Claude in JSON mode emits a `{ result, usage }` envelope; other engines emit
 * plain text, so we fall back to the regex/JSON token scraper.
 */
function parseAgentOutput(engine: AgentEngine, stdout: string): { text: string; usage: AgentTokenUsage } {
  if (engine === 'claude') {
    const trimmed = stdout.trim();
    if (trimmed.startsWith('{')) {
      try {
        const envelope = JSON.parse(trimmed) as Record<string, unknown>;
        const text = typeof envelope.result === 'string' ? envelope.result : stdout;
        return { text, usage: extractAgentTokenUsage(trimmed) };
      } catch {
        // Fall through to plain-text handling on malformed JSON.
      }
    }
  }
  return { text: stdout, usage: extractAgentTokenUsage(stdout) };
}

/**
 * Detect flag-shaped tokens in agent output and grade against ground truth.
 * When ground truth exists, a correct grade requires the expected flag to appear
 * verbatim in the output (agents don't always wrap it in `flag{...}`).
 */
function gradeFlags(text: string, stderr: string, expectedFlags: string[]): {
  flag: string | null;
  flagFound: boolean;
  flagCorrect: boolean | null;
} {
  const haystack = `${text}\n${stderr}`;
  const candidates = detectFlags(haystack);
  const flagCorrect = expectedFlags.length === 0
    ? null
    : expectedFlags.some(expected => {
        const needle = expected.toLowerCase();
        return haystack.toLowerCase().includes(needle);
      });

  // Prefer the matching expected flag as the recorded flag when graded correct.
  let flag = candidates[0] ?? null;
  if (flagCorrect && expectedFlags.length > 0) {
    flag = expectedFlags.find(expected => haystack.toLowerCase().includes(expected.toLowerCase())) ?? flag;
  }

  return {
    flag,
    flagFound: candidates.length > 0 || flagCorrect === true,
    flagCorrect
  };
}

/** Heuristic flag detectors covering FLARE-On emails and common CTF `name{...}` formats. */
export function detectFlags(text: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const patterns = [
    /[A-Za-z0-9_.+-]+@flare-on\.com/g,
    /\b[A-Za-z0-9_]{2,}\{[^}\n]{1,256}\}/g
  ];
  for (const pattern of patterns) {
    for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
      const value = match[0];
      if (!seen.has(value)) {
        seen.add(value);
        found.push(value);
      }
    }
  }
  return found;
}

export function extractAgentTokenUsage(text: string): AgentTokenUsage {
  const jsonUsage = extractJsonTokenUsage(text);
  const patternUsage: AgentTokenUsage = {
    inputTokens: lastNumberFor(/(?:input|prompt)\s+tokens?\s*(?:used)?\s*[:=]?\s*([\d][\d,._]*)/gi, text),
    outputTokens: lastNumberFor(/(?:output|completion|response|candidate)\s+tokens?\s*(?:used)?\s*[:=]?\s*([\d][\d,._]*)/gi, text),
    totalTokens: lastNumberFor(/tokens\s+used\s*(?:[:=]|\r?\n|\s)+([\d][\d,._]*)/gi, text)
      ?? lastNumberFor(/total\s+tokens?\s*(?:used)?\s*[:=]?\s*([\d][\d,._]*)/gi, text)
      ?? lastNumberFor(/([\d][\d,._]*)\s+tokens?\s+used/gi, text)
  };

  return mergeTokenUsage(jsonUsage, patternUsage);
}

function extractJsonTokenUsage(text: string): AgentTokenUsage {
  let usage = emptyTokenUsage();
  const candidates = [text, ...text.split(/\r?\n/).map(line => line.trim()).filter(Boolean)];

  for (const candidate of candidates) {
    if (!candidate.startsWith('{') && !candidate.startsWith('[')) {
      continue;
    }
    try {
      usage = mergeTokenUsage(usage, tokenUsageFromValue(JSON.parse(candidate)));
    } catch {
      // Non-JSON agent output is expected for text-mode runs.
    }
  }

  return usage;
}

function tokenUsageFromValue(value: unknown): AgentTokenUsage {
  if (Array.isArray(value)) {
    return value.map(tokenUsageFromValue).reduce(mergeTokenUsage, emptyTokenUsage());
  }

  if (!value || typeof value !== 'object') {
    return emptyTokenUsage();
  }

  const record = value as Record<string, unknown>;
  let usage = tokenUsageFromObject(record);
  for (const key of ['usage', 'usageMetadata', 'tokenUsage', 'metadata', 'message', 'result']) {
    usage = mergeTokenUsage(usage, tokenUsageFromValue(record[key]));
  }
  return usage;
}

function tokenUsageFromObject(record: Record<string, unknown>): AgentTokenUsage {
  const inputTokens = numberFromUnknown(
    record.inputTokens
      ?? record.input_tokens
      ?? record.promptTokens
      ?? record.prompt_tokens
      ?? record.promptTokenCount
      ?? record.cacheCreationInputTokens
      ?? record.cache_creation_input_tokens
      ?? record.cacheReadInputTokens
      ?? record.cache_read_input_tokens
  );
  const outputTokens = numberFromUnknown(
    record.outputTokens
      ?? record.output_tokens
      ?? record.completionTokens
      ?? record.completion_tokens
      ?? record.candidatesTokenCount
      ?? record.responseTokens
      ?? record.response_tokens
  );
  const totalTokens = numberFromUnknown(
    record.totalTokens
      ?? record.total_tokens
      ?? record.totalTokenCount
      ?? record.tokensUsed
      ?? record.tokens_used
  );

  return normalizeTokenUsage({ inputTokens, outputTokens, totalTokens });
}

function mergeTokenUsage(left: AgentTokenUsage, right: AgentTokenUsage): AgentTokenUsage {
  return normalizeTokenUsage({
    inputTokens: right.inputTokens ?? left.inputTokens,
    outputTokens: right.outputTokens ?? left.outputTokens,
    totalTokens: right.totalTokens ?? left.totalTokens
  });
}

function normalizeTokenUsage(usage: AgentTokenUsage): AgentTokenUsage {
  const totalTokens = usage.totalTokens
    ?? (usage.inputTokens !== null || usage.outputTokens !== null
      ? (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0)
      : null);
  return {
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    totalTokens
  };
}

function emptyTokenUsage(): AgentTokenUsage {
  return { inputTokens: null, outputTokens: null, totalTokens: null };
}

function lastNumberFor(pattern: RegExp, text: string): number | null {
  let value: number | null = null;
  for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
    value = parseTokenNumber(match[1]);
  }
  return value;
}

function numberFromUnknown(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    return parseTokenNumber(value);
  }
  return null;
}

function parseTokenNumber(value: string | undefined): number | null {
  if (!value) {
    return null;
  }
  const normalized = value.replace(/[,_\s]/g, '');
  if (!/^\d+$/.test(normalized)) {
    return null;
  }
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function buildAgentCommand(
  agent: AgentSpec,
  challenge: ChallengeTarget,
  prompt: string,
  options: AgentBenchmarkOptions,
  wiring: AraelWiring | null
): string[] {
  const fullPrompt = `${prompt}\n\nChallenge directory: ${challenge.path}`;
  const useArael = agent.araelMcp && wiring !== null;

  if (agent.engine === 'ollama') {
    // Local models run over Ollama's HTTP API rather than a spawned process; this
    // array is a human-readable description used for dry-run previews and records.
    return [`POST ${options.ollamaUrl}/api/generate`, 'model', agent.model];
  }

  if (agent.engine === 'codex') {
    // -yolo equivalent for non-interactive exec: bypass approvals and sandbox.
    const command = [
      options.codexBin,
      'exec',
      '--model',
      agent.model,
      '--cd',
      challenge.path,
      '--dangerously-bypass-approvals-and-sandbox'
    ];
    if (useArael) {
      command.push(
        '-c', 'mcp_servers.arael.command=node',
        '-c', `mcp_servers.arael.args=["${wiring!.serverPath.replace(/\\/g, '\\\\')}"]`
      );
    }
    command.push(fullPrompt);
    return command;
  }

  if (agent.engine === 'gemini') {
    const command = [
      options.geminiBin,
      '--model',
      agent.model,
      '--yolo',
      '--include-directories',
      challenge.path
    ];
    if (useArael) {
      // Settings file (.gemini/settings.json) is written into cwd at run time.
      command.push('--allowed-mcp-server-names', 'arael');
    }
    command.push('--prompt', fullPrompt);
    return command;
  }

  // claude
  // NOTE: --add-dir is variadic, so it must be followed by another flag — never
  // by the positional prompt, or Claude consumes the prompt as a directory and
  // exits with "Input must be provided ... when using --print".
  // --output-format json gives an exact { result, usage } envelope so token/cost
  // accounting doesn't rely on scraping the prose. (Also keeps a flag between the
  // variadic --add-dir and the positional prompt.)
  const command = [
    options.claudeBin,
    '--print',
    '--model',
    agent.model,
    '--dangerously-skip-permissions',
    '--add-dir',
    challenge.path,
    '--output-format',
    'json'
  ];
  if (useArael) {
    command.push('--mcp-config', wiring!.mcpConfigPath, '--strict-mcp-config');
  }
  command.push(fullPrompt);
  return command;
}

/** Write a .gemini/settings.json into the challenge dir so Gemini can load the Arael MCP server. */
function writeGeminiSettings(challengePath: string, serverPath: string): void {
  const settingsDir = path.join(challengePath, '.gemini');
  fs.mkdirSync(settingsDir, { recursive: true });
  const settings = {
    mcpServers: {
      arael: {
        command: 'node',
        args: [serverPath]
      }
    }
  };
  fs.writeFileSync(path.join(settingsDir, 'settings.json'), JSON.stringify(settings, null, 2));
}

/**
 * Run a local model through Ollama's /api/generate endpoint and adapt the reply
 * into the same CommandResult shape the spawned CLIs produce. Token counts come
 * straight from Ollama (prompt_eval_count / eval_count).
 */
async function runOllama(input: {
  url: string;
  model: string;
  prompt: string;
  timeoutSeconds: number;
}): Promise<{ result: CommandResult; usage: AgentTokenUsage }> {
  const endpoint = `${input.url.replace(/\/+$/, '')}/api/generate`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), input.timeoutSeconds * 1000);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: input.model, prompt: input.prompt, stream: false }),
      signal: controller.signal
    });

    const bodyText = await response.text();
    if (!response.ok) {
      return {
        result: { stdout: '', stderr: bodyText, exitCode: null, timedOut: false, errorMessage: `Ollama HTTP ${response.status}` },
        usage: emptyTokenUsage()
      };
    }

    const body = JSON.parse(bodyText) as {
      response?: string;
      prompt_eval_count?: number;
      eval_count?: number;
    };
    const usage = normalizeTokenUsage({
      inputTokens: numberFromUnknown(body.prompt_eval_count),
      outputTokens: numberFromUnknown(body.eval_count),
      totalTokens: null
    });
    return {
      result: { stdout: body.response ?? '', stderr: '', exitCode: 0, timedOut: false, errorMessage: null },
      usage
    };
  } catch (error) {
    const aborted = error instanceof Error && error.name === 'AbortError';
    const message = aborted
      ? null
      : `Ollama request failed: ${error instanceof Error ? error.message : String(error)} (is \`ollama serve\` running at ${input.url}?)`;
    return {
      result: { stdout: '', stderr: message ?? '', exitCode: null, timedOut: aborted, errorMessage: message },
      usage: emptyTokenUsage()
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Build a compact static-analysis context for a challenge so a non-agentic local
 * model has something to reason over: a file listing plus printable strings and a
 * head hexdump of the largest (likely primary) file. Bounded to stay CPU-friendly.
 */
function buildChallengeContext(challengePath: string): string {
  const files = collectFiles(challengePath)
    .map(file => ({ file, size: safeSize(file) }))
    .sort((a, b) => b.size - a.size);

  const listing = files
    .slice(0, 50)
    .map(({ file, size }) => `- ${path.relative(challengePath, file) || path.basename(file)} (${size} bytes)`)
    .join('\n');

  const primary = files[0];
  const sections = [`=== Files (${files.length}) ===\n${listing || '(none)'}`];
  if (primary) {
    const buffer = safeRead(primary.file, 256 * 1024);
    sections.push(`=== Strings: ${path.basename(primary.file)} (first 200) ===\n${extractPrintableStrings(buffer, 4, 200).join('\n')}`);
    sections.push(`=== Hexdump: ${path.basename(primary.file)} (first 512 bytes) ===\n${hexdump(buffer.subarray(0, 512))}`);
  }
  return sections.join('\n\n');
}

function safeSize(file: string): number {
  try {
    return fs.statSync(file).size;
  } catch {
    return 0;
  }
}

function safeRead(file: string, maxBytes: number): Buffer {
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, maxBytes);
      const buffer = Buffer.alloc(size);
      fs.readSync(fd, buffer, 0, size, 0);
      return buffer;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return Buffer.alloc(0);
  }
}

/** Extract runs of printable ASCII (>= minLength) from a buffer, capped at `limit`. */
function extractPrintableStrings(buffer: Buffer, minLength: number, limit: number): string[] {
  const results: string[] = [];
  let current = '';
  for (const byte of buffer) {
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
      continue;
    }
    if (current.length >= minLength) {
      results.push(current);
      if (results.length >= limit) {
        return results;
      }
    }
    current = '';
  }
  if (current.length >= minLength && results.length < limit) {
    results.push(current);
  }
  return results;
}

function hexdump(buffer: Buffer): string {
  const lines: string[] = [];
  for (let offset = 0; offset < buffer.length; offset += 16) {
    const slice = buffer.subarray(offset, offset + 16);
    const hex = Array.from(slice).map(byte => byte.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(slice).map(byte => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.')).join('');
    lines.push(`${offset.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join('\n');
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  errorMessage: string | null;
}

function runCommand(command: string[], options: {
  cwd: string;
  timeoutSeconds: number;
}): Promise<CommandResult> {
  return new Promise(resolve => {
    const [bin, ...args] = command;
    if (!bin) {
      resolve({ stdout: '', stderr: '', exitCode: null, timedOut: false, errorMessage: 'Empty command' });
      return;
    }

    // On Windows the agent CLIs are .cmd shims, which Node cannot spawn directly
    // (EINVAL) without a shell, and shell:true mangles spaced/quoted args. Wrap via
    // cmd.exe with shell:false so Node still quotes each arg. cmd.exe truncates an
    // arg at an embedded newline, so collapse newlines (only affects the prompt arg).
    let spawnBin = bin;
    let spawnArgs = args;
    if (process.platform === 'win32') {
      const comspec = process.env.ComSpec || 'cmd.exe';
      spawnBin = comspec;
      spawnArgs = ['/d', '/s', '/c', ...command.map(part => part.replace(/\r?\n/g, ' '))];
    }

    const child = spawn(spawnBin, spawnArgs, {
      cwd: options.cwd,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let finished = false;
    const timer = setTimeout(() => {
      if (finished) {
        return;
      }
      finished = true;
      child.kill('SIGKILL');
      resolve({ stdout, stderr, exitCode: null, timedOut: true, errorMessage: null });
    }, options.timeoutSeconds * 1000);

    child.stdout.on('data', data => { stdout += data.toString(); });
    child.stderr.on('data', data => { stderr += data.toString(); });
    child.on('error', error => {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: null, timedOut: false, errorMessage: error.message });
    });
    child.on('close', code => {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: code, timedOut: false, errorMessage: code === 0 ? null : `Exited with code ${code}` });
    });
  });
}

/** A record counts as solved when graded correct, or — absent ground truth — when a flag was detected. */
function isSolved(record: AgentBenchmarkRecord): boolean {
  return record.flagCorrect === true || (record.flagCorrect === null && record.flagFound);
}

function sumNullable(values: Array<number | null>): number | null {
  const present = values.filter((value): value is number => value !== null);
  return present.length === 0 ? null : present.reduce((sum, value) => sum + value, 0);
}

function averageNullable(values: number[]): number | null {
  return values.length === 0 ? null : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function summarizeAgentBenchmark(
  challenges: ChallengeTarget[],
  agents: AgentSpec[],
  records: AgentBenchmarkRecord[]
): AgentBenchmarkSummary {
  const completed = records.filter(record => !record.dryRun);
  const durations = completed
    .filter(record => Number.isFinite(record.durationSeconds))
    .map(record => record.durationSeconds);
  const totalTokens = sumNullable(completed.map(record => record.totalTokens));
  const tokenCount = completed.filter(record => record.totalTokens !== null).length;

  return {
    challengeCount: challenges.length,
    agentCount: agents.length,
    recordCount: records.length,
    successCount: records.filter(record => record.success).length,
    failureCount: records.filter(record => !record.success).length,
    timeoutCount: records.filter(record => record.timedOut).length,
    solveCount: records.filter(isSolved).length,
    gradedCount: records.filter(record => record.flagCorrect !== null).length,
    averageDurationSeconds: averageNullable(durations),
    totalTokens,
    averageTokens: totalTokens === null || tokenCount === 0 ? null : totalTokens / tokenCount,
    totalCostUsd: sumNullable(completed.map(record => record.costUsd)),
    variants: summarizeVariants(agents, records)
  };
}

/** Roll records up per (engine, model, araelMcp) so the matrix can be compared directly. */
function summarizeVariants(agents: AgentSpec[], records: AgentBenchmarkRecord[]): AgentVariantSummary[] {
  return agents.map(agent => {
    const variantRecords = records.filter(record =>
      record.agent === agent.engine && record.model === agent.model && record.araelMcp === agent.araelMcp
    );
    const durations = variantRecords
      .filter(record => !record.dryRun && Number.isFinite(record.durationSeconds))
      .map(record => record.durationSeconds);
    const solveCount = variantRecords.filter(isSolved).length;

    return {
      engine: agent.engine,
      model: agent.model,
      araelMcp: agent.araelMcp,
      recordCount: variantRecords.length,
      solveCount,
      solveRate: variantRecords.length === 0 ? null : solveCount / variantRecords.length,
      flagFoundCount: variantRecords.filter(record => record.flagFound).length,
      averageDurationSeconds: averageNullable(durations),
      totalTokens: sumNullable(variantRecords.map(record => record.totalTokens)),
      totalCostUsd: sumNullable(variantRecords.map(record => record.costUsd))
    };
  });
}

function sanitizeName(value: string): string {
  return value.replace(/[^\w.-]+/g, '_').replace(/^_+|_+$/g, '') || 'item';
}
