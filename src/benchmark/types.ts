import type { AnalysisResult } from '../output/schema';
import type { LLMResponse } from '../llm/provider';
import type { YaraScanResult } from '../utils/yara';

export type BenchmarkFormat = 'json' | 'jsonl' | 'csv' | 'markdown' | 'latex' | 'html';
export type AgentBenchmarkFormat = 'json' | 'jsonl' | 'csv' | 'variant-csv' | 'markdown' | 'html';
export type AgentEngine = 'codex' | 'claude' | 'gemini' | 'ollama';

export type BenchmarkMetricName =
  | 'functions'
  | 'functionNames'
  | 'entryPoints'
  | 'strings'
  | 'imports'
  | 'exports'
  | 'xrefs'
  | 'callgraph'
  | 'iocs'
  | 'behaviors'
  | 'mitre'
  | 'yara';

export interface BenchmarkQuestion {
  id: string;
  question: string;
  expectedKeywords?: string[];
  forbiddenClaims?: string[];
  answerScore?: number;
}

export interface BenchmarkGroundTruth {
  complete?: Partial<Record<BenchmarkMetricName, boolean>>;
  expectedFunctions?: string[];
  expectedFunctionNames?: string[];
  expectedEntryPoints?: string[];
  expectedStrings?: string[];
  expectedImports?: string[];
  expectedExports?: string[];
  expectedXrefs?: string[];
  expectedCallgraphEdges?: string[];
  expectedIOCs?: Partial<Record<IOCType, string[]>>;
  expectedBehaviors?: string[];
  expectedMitreTechniques?: string[];
  expectedYaraRules?: string[];
  classification?: string;
  malwareType?: string;
  llmQuestions?: BenchmarkQuestion[];
}

export interface BenchmarkSample {
  sampleId: string;
  path: string;
  sha256?: string;
  fileName?: string;
  fileSizeMb?: number;
  format?: string;
  architecture?: string;
  compiler?: string;
  optimization?: string;
  stripped?: boolean;
  packed?: boolean;
  groundTruth?: BenchmarkGroundTruth;
}

export interface BenchmarkManifest {
  version?: string;
  samples: BenchmarkSample[];
  questions?: BenchmarkQuestion[];
}

export interface PricingEntry {
  inputUsdPerMillionTokens: number;
  outputUsdPerMillionTokens: number;
}

export type PricingTable = Record<string, Record<string, PricingEntry>>;

export type IOCType =
  | 'ips'
  | 'domains'
  | 'urls'
  | 'emails'
  | 'filePaths'
  | 'registryKeys'
  | 'mutexes'
  | 'userAgents';

export interface MetricScore {
  expected: number;
  detected: number;
  truePositive: number;
  falsePositive: number | null;
  falseNegative: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  completeGroundTruth: boolean;
}

export interface BenchmarkScores {
  functions: MetricScore;
  functionNames: MetricScore;
  entryPoints: MetricScore;
  strings: MetricScore;
  imports: MetricScore;
  exports: MetricScore;
  xrefs: MetricScore;
  callgraph: MetricScore;
  iocs: MetricScore;
  iocsByType: Partial<Record<IOCType, MetricScore>>;
  behaviors: MetricScore;
  mitre: MetricScore;
  yara?: MetricScore;
  classificationCorrect: boolean | null;
  malwareTypeCorrect: boolean | null;
  mitreEvidenceQuality: number | null;
  iocDuplicateRate: number | null;
  iocNormalizationQuality: number | null;
  falsePositiveRate: number | null;
  falseNegativeRate: number | null;
}

export interface BenchmarkCounts {
  functionsDetected: number;
  stringsDetected: number;
  importsDetected: number;
  exportsDetected: number;
  xrefsDetected: number;
  yaraMatches: number;
  iocsDetected: number;
  behaviorsDetected: number;
  mitreTechniquesDetected: number;
}

export interface BenchmarkPerformance {
  analysisTimeSeconds: number;
  ghidraReportedAnalysisTimeSeconds: number | null;
  yaraScanTimeSeconds: number | null;
  contextGenerationTimeSeconds: number | null;
  totalWallTimeSeconds: number;
  peakMemoryMb: number | null;
  outputJsonSizeKb: number | null;
  cacheHitOrMiss: 'hit' | 'miss';
  cachedRunTimeSeconds: number | null;
  speedupRatio: number | null;
  secondsPerMb: number | null;
  secondsPerFunction: number | null;
  memoryMbPerMbBinary: number | null;
  jsonKbPerMbBinary: number | null;
}

export interface BenchmarkRecord {
  runId: string;
  timestamp: string;
  araelVersion: string;
  gitCommit: string | null;
  sampleId: string;
  sha256: string | null;
  fileName: string;
  filePath: string;
  fileSizeMb: number | null;
  format: string | null;
  architecture: string | null;
  compiler: string | null;
  optimization: string | null;
  stripped: boolean | null;
  packed: boolean | null;
  command: string;
  runIndex: number;
  analysisSuccess: boolean;
  errorType: string | null;
  errorMessage: string | null;
  timeout: boolean;
  classification: string | null;
  classificationConfidence: number | null;
  groundTruthLabel: string | null;
  counts: BenchmarkCounts;
  performance: BenchmarkPerformance;
  scores: BenchmarkScores;
}

export interface LLMBenchmarkRecord {
  runId: string;
  timestamp: string;
  sampleId: string;
  fileName: string;
  questionId: string;
  question: string;
  llmProvider: string;
  llmModel: string;
  llmLatencySeconds: number;
  inputTokens: number | null;
  outputTokens: number | null;
  costUsd: number | null;
  llmAnswerScore: number | null;
  llmHallucinationCount: number | null;
  evidenceCorrectness: number | null;
  answer: string;
}

export interface BenchmarkRunResult {
  runId: string;
  timestamp: string;
  records: BenchmarkRecord[];
  llmRecords: LLMBenchmarkRecord[];
  summary: BenchmarkSummary;
}

export interface BenchmarkSummary {
  sampleCount: number;
  recordCount: number;
  llmRecordCount: number;
  successCount: number;
  failureCount: number;
  timeoutCount: number;
  averageTotalWallTimeSeconds: number | null;
  averageAnalysisTimeSeconds: number | null;
  averagePeakMemoryMb: number | null;
  averageFunctionRecall: number | null;
  averageBehaviorF1: number | null;
  averageIocF1: number | null;
  averageMitreF1: number | null;
  averageClassificationAccuracy: number | null;
  averageLlmAnswerScore: number | null;
}

export interface BenchmarkOptions {
  target: string;
  manifestPath?: string;
  format: BenchmarkFormat;
  outputPath?: string;
  force: boolean;
  runs: number;
  timeoutSeconds?: number;
  includeYara: boolean;
  withLlm: boolean;
  provider?: 'openai' | 'anthropic' | 'google' | 'ollama';
  model?: string;
  questionsPath?: string;
  pricingFile?: string;
}

export interface AnalysisMeasurement {
  result?: AnalysisResult;
  error?: Error;
  durationSeconds: number;
  peakMemoryMb: number | null;
  timeout: boolean;
}

export interface YaraMeasurement {
  result: YaraScanResult;
  durationSeconds: number;
}

export interface LLMMeasurement {
  response: LLMResponse;
  question: BenchmarkQuestion;
  latencySeconds: number;
  costUsd: number | null;
  answerScore: number | null;
  hallucinationCount: number | null;
  evidenceCorrectness: number | null;
}

export interface AgentSpec {
  engine: AgentEngine;
  model: string;
  /** Attach the Arael MCP server to this agent instance. */
  araelMcp: boolean;
}

export interface AgentBenchmarkOptions {
  target: string;
  outputPath?: string;
  format: AgentBenchmarkFormat;
  agents: AgentSpec[];
  timeoutSeconds: number;
  extractArchives: boolean;
  archivePassword?: string;
  extractOutput?: string;
  maxChallenges?: number;
  codexBin: string;
  claudeBin: string;
  geminiBin: string;
  /** Base URL of the Ollama server for local-model (ollama:*) instances. */
  ollamaUrl: string;
  /** Path to the Arael MCP server entrypoint (dist/mcp/server.js) for +arael instances. */
  araelServerPath?: string;
  promptPath?: string;
  /** Number of times to repeat each (challenge, agent) cell. Defaults to 1. */
  runs: number;
  /** Maximum number of agent processes to run in parallel. Defaults to 1. */
  concurrency: number;
  /** Re-run cells even when a cached per-cell record already exists. */
  force: boolean;
  /** JSON pricing table ({provider:{model:{inputUsdPerMillionTokens,outputUsdPerMillionTokens}}}) for cost estimates. */
  pricingFile?: string;
  /** JSON map of challengeId -> expected flag(s) for auto-grading. */
  groundTruthPath?: string;
  dryRun: boolean;
}

export interface ChallengeTarget {
  challengeId: string;
  path: string;
  fileCount: number;
  totalBytes: number;
}

/** One run's artifact paths (relative to the manifest's outputRoot). */
export interface ArtifactManifestEntry {
  challengeId: string;
  agent: AgentEngine;
  model: string;
  araelMcp: boolean;
  variant: string;
  runIndex: number;
  success: boolean;
  solved: boolean;
  flag: string | null;
  stdout: string | null;
  stderr: string | null;
  record: string | null;
}

/** Maps every benchmark run to its stdout/stderr/record artifacts for reliable linking. */
export interface ArtifactManifest {
  runId: string;
  timestamp: string;
  generatedAt: string;
  outputRoot: string;
  entries: ArtifactManifestEntry[];
}

export interface AgentBenchmarkRecord {
  runId: string;
  timestamp: string;
  challengeId: string;
  challengePath: string;
  agent: AgentEngine;
  model: string;
  /** Whether the Arael MCP server was attached to this run. */
  araelMcp: boolean;
  /** Zero-based repeat index when --runs > 1. */
  runIndex: number;
  command: string[];
  success: boolean;
  exitCode: number | null;
  timedOut: boolean;
  durationSeconds: number;
  inputTokens: number | null;
  outputTokens: number | null;
  totalTokens: number | null;
  /** Estimated USD cost from the pricing table, or null when unpriced. */
  costUsd: number | null;
  /** First flag-shaped token detected in the agent output, if any. */
  flag: string | null;
  /** Whether any flag-shaped token was detected. */
  flagFound: boolean;
  /** True/false when ground truth exists for the challenge; null otherwise. */
  flagCorrect: boolean | null;
  stdoutPath: string | null;
  stderrPath: string | null;
  outputPreview: string;
  errorMessage: string | null;
  /** True when the record was loaded from a cached per-cell artifact rather than freshly run. */
  resumed: boolean;
  dryRun: boolean;
}

export interface AgentVariantSummary {
  engine: AgentEngine;
  model: string;
  araelMcp: boolean;
  recordCount: number;
  /** Records graded correct (flagCorrect===true), or flagFound when no ground truth exists. */
  solveCount: number;
  solveRate: number | null;
  flagFoundCount: number;
  averageDurationSeconds: number | null;
  totalTokens: number | null;
  totalCostUsd: number | null;
}

export interface AgentBenchmarkSummary {
  challengeCount: number;
  agentCount: number;
  recordCount: number;
  successCount: number;
  failureCount: number;
  timeoutCount: number;
  /** Records counted as solved (graded correct, or flag detected when no ground truth). */
  solveCount: number;
  /** Records that had ground-truth grading available. */
  gradedCount: number;
  averageDurationSeconds: number | null;
  totalTokens: number | null;
  averageTokens: number | null;
  totalCostUsd: number | null;
  variants: AgentVariantSummary[];
}

export interface AgentBenchmarkRunResult {
  runId: string;
  timestamp: string;
  challenges: ChallengeTarget[];
  records: AgentBenchmarkRecord[];
  summary: AgentBenchmarkSummary;
  /** Environment/config snapshot for reproducibility (optional for legacy callers). */
  metadata?: ReproducibilityMetadata;
}

/**
 * A snapshot of everything needed to reproduce a benchmark run: tool versions,
 * git commit, OS/hardware, run configuration, and content hashes of external
 * inputs (prompt, pricing table, ground truth).
 */
export interface ReproducibilityMetadata {
  generatedAt: string;
  araelVersion: string;
  gitCommit: string | null;
  node: string;
  platform: string;
  arch: string;
  osType: string;
  osRelease: string;
  cpuCount: number;
  totalMemoryMb: number;
  cwd: string;
  agents: string[];
  runs: number;
  concurrency: number;
  timeoutSeconds: number;
  ollamaUrl: string;
  promptSource: string;
  promptSha256: string;
  pricingFile: string | null;
  pricingSha256: string | null;
  groundTruthFile: string | null;
  groundTruthSha256: string | null;
  ghidraPath: string | null;
  araelPython: string | null;
  araelServerPath: string | null;
}
