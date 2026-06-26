import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFileSync } from 'child_process';
import { analyzeHandler } from '../mcp/handlers/analyze';
import { buildAnalysisContext } from '../llm/context';
import { scan } from '../utils/yara';
import { logger } from '../utils/logger';
import { countIOCs } from '../analysis/ioc-extractor';
import {
  loadBenchmarkManifest,
  loadBenchmarkQuestions,
  loadPricingTable,
  samplesFromTarget
} from './manifest';
import { computeBenchmarkScores } from './metrics';
import { runLlmMeasurement } from './llm';
import { startResourceSampler } from './resource-sampler';
import type {
  AnalysisMeasurement,
  BenchmarkCounts,
  BenchmarkOptions,
  BenchmarkRecord,
  BenchmarkRunResult,
  BenchmarkSample,
  BenchmarkSummary,
  LLMBenchmarkRecord,
  YaraMeasurement
} from './types';

export async function runBenchmark(options: BenchmarkOptions): Promise<BenchmarkRunResult> {
  const runId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const manifest = options.manifestPath ? loadBenchmarkManifest(options.manifestPath) : undefined;
  const samples = manifest?.samples ?? samplesFromTarget(options.target);
  const questions = options.questionsPath ? loadBenchmarkQuestions(options.questionsPath) : manifest?.questions;
  const pricing = options.pricingFile ? loadPricingTable(options.pricingFile) : undefined;
  const records: BenchmarkRecord[] = [];
  const llmRecords: LLMBenchmarkRecord[] = [];
  const araelVersion = readPackageVersion();
  const gitCommit = readGitCommit();

  if (samples.length === 0) {
    throw new Error(`No benchmark samples found for target: ${options.target}`);
  }

  for (const sample of samples) {
    let firstMissSeconds: number | null = null;
    for (let runIndex = 1; runIndex <= options.runs; runIndex++) {
      const force = options.force && runIndex === 1;
      const command = `arael analyze ${shellQuote(sample.path)}${force ? ' --force' : ''}`;
      const sampleStart = process.hrtime.bigint();
      const analysis = await measureAnalysis(sample.path, force);
      let contextSeconds: number | null = null;
      let yaraMeasurement: YaraMeasurement | undefined;
      let record: BenchmarkRecord;

      if (analysis.result) {
        const contextStart = process.hrtime.bigint();
        const context = buildAnalysisContext(analysis.result);
        contextSeconds = secondsSince(contextStart);

        if (options.includeYara) {
          yaraMeasurement = await measureYara(sample.path);
        }

        const cacheState = analysis.result.metadata.cached ? 'hit' : 'miss';
        if (cacheState === 'miss' && firstMissSeconds === null) {
          firstMissSeconds = analysis.durationSeconds;
        }

        const totalWallTimeSeconds = secondsSince(sampleStart);
        const outputJsonSizeKb = Buffer.byteLength(JSON.stringify(analysis.result), 'utf8') / 1024;
        const counts = buildCounts(analysis.result, context.raw.iocs, context.raw.behaviors.length, context.raw.mitre.techniques.length, yaraMeasurement?.result);
        const scores = computeBenchmarkScores({
          result: analysis.result,
          groundTruth: sample.groundTruth,
          iocs: context.raw.iocs,
          behaviors: context.raw.behaviors,
          mitre: context.raw.mitre,
          yara: yaraMeasurement?.result,
          classification: {
            classification: context.classification.type,
            malwareType: context.classification.malwareType
          }
        });

        record = {
          runId,
          timestamp,
          araelVersion,
          gitCommit,
          sampleId: sample.sampleId,
          sha256: sample.sha256 ?? analysis.result.binary.hashes.sha256 ?? sha256OrNull(sample.path),
          fileName: sample.fileName ?? analysis.result.binary.filename,
          filePath: sample.path,
          fileSizeMb: bytesToMb(analysis.result.binary.size),
          format: sample.format ?? analysis.result.binary.format,
          architecture: sample.architecture ?? analysis.result.binary.architecture,
          compiler: sample.compiler ?? null,
          optimization: sample.optimization ?? null,
          stripped: sample.stripped ?? null,
          packed: sample.packed ?? analysis.result.binary.packing?.isPacked ?? null,
          command,
          runIndex,
          analysisSuccess: true,
          errorType: null,
          errorMessage: null,
          timeout: false,
          classification: context.classification.type,
          classificationConfidence: context.classification.confidence,
          groundTruthLabel: sample.groundTruth?.classification ?? null,
          counts,
          performance: {
            analysisTimeSeconds: analysis.durationSeconds,
            ghidraReportedAnalysisTimeSeconds: analysis.result.metadata.analysisDurationMs / 1000,
            yaraScanTimeSeconds: yaraMeasurement?.durationSeconds ?? null,
            contextGenerationTimeSeconds: contextSeconds,
            totalWallTimeSeconds,
            peakMemoryMb: analysis.peakMemoryMb,
            outputJsonSizeKb,
            cacheHitOrMiss: cacheState,
            cachedRunTimeSeconds: cacheState === 'hit' ? analysis.durationSeconds : null,
            speedupRatio: cacheState === 'hit' && firstMissSeconds ? firstMissSeconds / analysis.durationSeconds : null,
            secondsPerMb: ratioOrNull(totalWallTimeSeconds, bytesToMb(analysis.result.binary.size)),
            secondsPerFunction: ratioOrNull(totalWallTimeSeconds, Math.max(1, analysis.result.functions.length)),
            memoryMbPerMbBinary: ratioOrNull(analysis.peakMemoryMb, bytesToMb(analysis.result.binary.size)),
            jsonKbPerMbBinary: ratioOrNull(outputJsonSizeKb, bytesToMb(analysis.result.binary.size))
          },
          scores
        };

        records.push(record);

        if (options.withLlm) {
          const sampleQuestions = sample.groundTruth?.llmQuestions ?? questions ?? [];
          for (const question of sampleQuestions) {
            const llm = await runLlmMeasurement({
              result: analysis.result,
              question,
              provider: options.provider,
              model: options.model,
              pricing
            });
            llmRecords.push(buildLlmRecord(runId, timestamp, sample, llm));
          }
        }
      } else {
        const totalWallTimeSeconds = secondsSince(sampleStart);
        record = buildFailureRecord({
          runId,
          timestamp,
          araelVersion,
          gitCommit,
          sample,
          command,
          runIndex,
          measurement: analysis,
          totalWallTimeSeconds
        });
        records.push(record);
      }
    }
  }

  return {
    runId,
    timestamp,
    records,
    llmRecords,
    summary: summarize(records, llmRecords, samples.length)
  };
}

async function measureAnalysis(filepath: string, force: boolean): Promise<AnalysisMeasurement> {
  const sampler = startResourceSampler();
  const start = process.hrtime.bigint();
  try {
    const result = await analyzeHandler({ filepath, force });
    return {
      result,
      durationSeconds: secondsSince(start),
      peakMemoryMb: sampler.stop(),
      timeout: false
    };
  } catch (error) {
    return {
      error: error instanceof Error ? error : new Error(String(error)),
      durationSeconds: secondsSince(start),
      peakMemoryMb: sampler.stop(),
      timeout: /timed out|timeout/i.test(error instanceof Error ? error.message : String(error))
    };
  }
}

async function measureYara(filepath: string): Promise<YaraMeasurement> {
  const start = process.hrtime.bigint();
  const result = await scan(filepath, { ruleSet: 'all' });
  return {
    result,
    durationSeconds: secondsSince(start)
  };
}

function buildCounts(
  result: NonNullable<AnalysisMeasurement['result']>,
  iocs: ReturnType<typeof buildAnalysisContext>['raw']['iocs'],
  behaviorCount: number,
  mitreCount: number,
  yara?: YaraMeasurement['result']
): BenchmarkCounts {
  return {
    functionsDetected: result.functions.length,
    stringsDetected: result.strings.length,
    importsDetected: result.imports.length,
    exportsDetected: result.exports?.length ?? 0,
    xrefsDetected: result.functions.reduce((sum, func) => sum + func.callers.length + func.callees.length, 0),
    yaraMatches: yara?.matches.length ?? 0,
    iocsDetected: countIOCs(iocs),
    behaviorsDetected: behaviorCount,
    mitreTechniquesDetected: mitreCount
  };
}

function buildFailureRecord(input: {
  runId: string;
  timestamp: string;
  araelVersion: string;
  gitCommit: string | null;
  sample: BenchmarkSample;
  command: string;
  runIndex: number;
  measurement: AnalysisMeasurement;
  totalWallTimeSeconds: number;
}): BenchmarkRecord {
  const fileSizeBytes = fileSizeOrNull(input.sample.path);
  const emptyScores = computeBenchmarkScores({
    groundTruth: input.sample.groundTruth,
    iocs: {
      ips: [],
      domains: [],
      urls: [],
      emails: [],
      filePaths: [],
      registryKeys: [],
      mutexes: [],
      userAgents: []
    },
    behaviors: [],
    mitre: { tactics: [], techniques: [], summary: '' },
    classification: { classification: 'unknown' }
  });

  return {
    runId: input.runId,
    timestamp: input.timestamp,
    araelVersion: input.araelVersion,
    gitCommit: input.gitCommit,
    sampleId: input.sample.sampleId,
    sha256: input.sample.sha256 ?? sha256OrNull(input.sample.path),
    fileName: input.sample.fileName ?? path.basename(input.sample.path),
    filePath: input.sample.path,
    fileSizeMb: fileSizeBytes === null ? null : bytesToMb(fileSizeBytes),
    format: input.sample.format ?? null,
    architecture: input.sample.architecture ?? null,
    compiler: input.sample.compiler ?? null,
    optimization: input.sample.optimization ?? null,
    stripped: input.sample.stripped ?? null,
    packed: input.sample.packed ?? null,
    command: input.command,
    runIndex: input.runIndex,
    analysisSuccess: false,
    errorType: input.measurement.error?.name ?? 'Error',
    errorMessage: input.measurement.error?.message ?? null,
    timeout: input.measurement.timeout,
    classification: null,
    classificationConfidence: null,
    groundTruthLabel: input.sample.groundTruth?.classification ?? null,
    counts: {
      functionsDetected: 0,
      stringsDetected: 0,
      importsDetected: 0,
      exportsDetected: 0,
      xrefsDetected: 0,
      yaraMatches: 0,
      iocsDetected: 0,
      behaviorsDetected: 0,
      mitreTechniquesDetected: 0
    },
    performance: {
      analysisTimeSeconds: input.measurement.durationSeconds,
      ghidraReportedAnalysisTimeSeconds: null,
      yaraScanTimeSeconds: null,
      contextGenerationTimeSeconds: null,
      totalWallTimeSeconds: input.totalWallTimeSeconds,
      peakMemoryMb: input.measurement.peakMemoryMb,
      outputJsonSizeKb: null,
      cacheHitOrMiss: 'miss',
      cachedRunTimeSeconds: null,
      speedupRatio: null,
      secondsPerMb: fileSizeBytes === null ? null : ratioOrNull(input.totalWallTimeSeconds, bytesToMb(fileSizeBytes)),
      secondsPerFunction: null,
      memoryMbPerMbBinary: fileSizeBytes === null ? null : ratioOrNull(input.measurement.peakMemoryMb, bytesToMb(fileSizeBytes)),
      jsonKbPerMbBinary: null
    },
    scores: emptyScores
  };
}

function buildLlmRecord(
  runId: string,
  timestamp: string,
  sample: BenchmarkSample,
  llm: Awaited<ReturnType<typeof runLlmMeasurement>>
): LLMBenchmarkRecord {
  return {
    runId,
    timestamp,
    sampleId: sample.sampleId,
    fileName: sample.fileName ?? path.basename(sample.path),
    questionId: llm.question.id,
    question: llm.question.question,
    llmProvider: llm.response.provider,
    llmModel: llm.response.model,
    llmLatencySeconds: llm.latencySeconds,
    inputTokens: llm.response.usage?.inputTokens ?? null,
    outputTokens: llm.response.usage?.outputTokens ?? null,
    costUsd: llm.costUsd,
    llmAnswerScore: llm.answerScore,
    llmHallucinationCount: llm.hallucinationCount,
    evidenceCorrectness: llm.evidenceCorrectness,
    answer: llm.response.content
  };
}

function summarize(records: BenchmarkRecord[], llmRecords: LLMBenchmarkRecord[], sampleCount: number): BenchmarkSummary {
  const successful = records.filter(record => record.analysisSuccess);
  return {
    sampleCount,
    recordCount: records.length,
    llmRecordCount: llmRecords.length,
    successCount: successful.length,
    failureCount: records.length - successful.length,
    timeoutCount: records.filter(record => record.timeout).length,
    averageTotalWallTimeSeconds: average(successful.map(record => record.performance.totalWallTimeSeconds)),
    averageAnalysisTimeSeconds: average(successful.map(record => record.performance.analysisTimeSeconds)),
    averagePeakMemoryMb: average(successful.map(record => record.performance.peakMemoryMb)),
    averageFunctionRecall: average(successful.map(record => record.scores.functions.recall)),
    averageBehaviorF1: average(successful.map(record => record.scores.behaviors.f1)),
    averageIocF1: average(successful.map(record => record.scores.iocs.f1)),
    averageMitreF1: average(successful.map(record => record.scores.mitre.f1)),
    averageClassificationAccuracy: average(successful.map(record => booleanToNumber(record.scores.classificationCorrect))),
    averageLlmAnswerScore: average(llmRecords.map(record => record.llmAnswerScore))
  };
}

function secondsSince(start: bigint): number {
  return Number(process.hrtime.bigint() - start) / 1_000_000_000;
}

function bytesToMb(bytes: number): number {
  return bytes / 1024 / 1024;
}

function ratioOrNull(numerator: number | null, denominator: number | null): number | null {
  if (numerator === null || denominator === null || denominator === 0) {
    return null;
  }
  return numerator / denominator;
}

function average(values: Array<number | null>): number | null {
  const numeric = values.filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
  if (numeric.length === 0) {
    return null;
  }
  return numeric.reduce((sum, value) => sum + value, 0) / numeric.length;
}

function booleanToNumber(value: boolean | null): number | null {
  if (value === null) {
    return null;
  }
  return value ? 1 : 0;
}

function readPackageVersion(): string {
  try {
    const packagePath = path.join(__dirname, '../../package.json');
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8')) as { version?: string };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

function readGitCommit(): string | null {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf-8' }).trim();
  } catch (error) {
    logger.debug(`Unable to read git commit: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

function sha256OrNull(filepath: string): string | null {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(filepath)).digest('hex');
  } catch {
    return null;
  }
}

function fileSizeOrNull(filepath: string): number | null {
  try {
    return fs.statSync(filepath).size;
  } catch {
    return null;
  }
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:-]+$/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, "'\\''")}'`;
}
