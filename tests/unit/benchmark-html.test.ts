import * as path from 'path';
import { renderAgentBenchmarkHtml, renderBenchmarkHtml } from '../../src/output/html';
import type {
  AgentBenchmarkRunResult,
  BenchmarkRunResult,
  BenchmarkScores,
  MetricScore
} from '../../src/benchmark/types';

describe('benchmark HTML reports', () => {
  it('renders classic benchmark HTML with summary, sample metrics, and LLM rows', () => {
    const html = renderBenchmarkHtml(makeBenchmarkRunResult(), {
      generatedAt: '2026-01-01T00:00:00.000Z'
    });

    expect(html.match(/<!DOCTYPE html>/g)).toHaveLength(1);
    expect(html).toContain('Arael Benchmark Report');
    expect(html).toContain('sample&lt;1&gt;');
    expect(html).toContain('data-search-target="benchmark-records-table"');
    expect(html).toContain('LLM Questions');
    expect(html).toContain('answer &lt;escaped&gt;');
  });

  it('renders agent benchmark HTML with leaderboard, filters, escaped flags, and relative artifacts', () => {
    const reportPath = path.join(process.cwd(), '.arael', 'benchmark-results', 'agents', 'run.html');
    const html = renderAgentBenchmarkHtml(makeAgentBenchmarkRunResult(reportPath), {
      reportPath,
      generatedAt: '2026-01-01T00:00:00.000Z'
    });

    expect(html.match(/<!DOCTYPE html>/g)).toHaveLength(1);
    expect(html).toContain('Arael Agent Benchmark Report');
    expect(html).toContain('Leaderboard');
    expect(html).toContain('data-solved-toggle="agent-runs-table"');
    expect(html).toContain('flag{&lt;script&gt;}');
    expect(html).toContain('data-copy="flag{&lt;script&gt;}"');
    expect(html).toContain('run.html.artifacts/chal-1/codex-test-arael.stdout.txt');
    expect(html).toContain('run.html.artifacts/chal-1/codex-test-arael.record.json');
  });
});

function makeBenchmarkRunResult(): BenchmarkRunResult {
  return {
    runId: 'bench-1',
    timestamp: '2026-01-01T00:00:00.000Z',
    records: [{
      runId: 'bench-1',
      timestamp: '2026-01-01T00:00:00.000Z',
      araelVersion: 'test',
      gitCommit: null,
      sampleId: 'sample<1>',
      sha256: 'abc',
      fileName: 'sample.bin',
      filePath: '/tmp/sample.bin',
      fileSizeMb: 1,
      format: 'ELF',
      architecture: 'x86_64',
      compiler: null,
      optimization: null,
      stripped: null,
      packed: false,
      command: 'arael analyze sample.bin',
      runIndex: 1,
      analysisSuccess: true,
      errorType: null,
      errorMessage: null,
      timeout: false,
      classification: 'benign',
      classificationConfidence: 0.9,
      groundTruthLabel: 'benign',
      counts: {
        functionsDetected: 2,
        stringsDetected: 3,
        importsDetected: 1,
        exportsDetected: 0,
        xrefsDetected: 0,
        yaraMatches: 0,
        iocsDetected: 1,
        behaviorsDetected: 1,
        mitreTechniquesDetected: 0
      },
      performance: {
        analysisTimeSeconds: 1,
        ghidraReportedAnalysisTimeSeconds: 1,
        yaraScanTimeSeconds: null,
        contextGenerationTimeSeconds: 0.1,
        totalWallTimeSeconds: 1.2,
        peakMemoryMb: 100,
        outputJsonSizeKb: 12,
        cacheHitOrMiss: 'miss',
        cachedRunTimeSeconds: null,
        speedupRatio: null,
        secondsPerMb: 1.2,
        secondsPerFunction: 0.6,
        memoryMbPerMbBinary: 100,
        jsonKbPerMbBinary: 12
      },
      scores: makeScores()
    }],
    llmRecords: [{
      runId: 'bench-1',
      timestamp: '2026-01-01T00:00:00.000Z',
      sampleId: 'sample<1>',
      fileName: 'sample.bin',
      questionId: 'q1',
      question: 'What is it?',
      llmProvider: 'openai',
      llmModel: 'test-model',
      llmLatencySeconds: 0.5,
      inputTokens: 10,
      outputTokens: 20,
      costUsd: 0.001,
      llmAnswerScore: 1,
      llmHallucinationCount: 0,
      evidenceCorrectness: 1,
      answer: 'answer <escaped>'
    }],
    summary: {
      sampleCount: 1,
      recordCount: 1,
      llmRecordCount: 1,
      successCount: 1,
      failureCount: 0,
      timeoutCount: 0,
      averageTotalWallTimeSeconds: 1.2,
      averageAnalysisTimeSeconds: 1,
      averagePeakMemoryMb: 100,
      averageFunctionRecall: 1,
      averageBehaviorF1: 1,
      averageIocF1: 1,
      averageMitreF1: null,
      averageClassificationAccuracy: 1,
      averageLlmAnswerScore: 1
    }
  };
}

function makeAgentBenchmarkRunResult(reportPath: string): AgentBenchmarkRunResult {
  const stdoutPath = path.join(path.dirname(reportPath), 'run.html.artifacts', 'chal-1', 'codex-test-arael.stdout.txt');
  return {
    runId: 'agent-1',
    timestamp: '2026-01-01T00:00:00.000Z',
    challenges: [{
      challengeId: 'chal-1',
      path: '/tmp/chal-1',
      fileCount: 1,
      totalBytes: 100
    }],
    records: [{
      runId: 'agent-1',
      timestamp: '2026-01-01T00:00:00.000Z',
      challengeId: 'chal-1',
      challengePath: '/tmp/chal-1',
      agent: 'codex',
      model: 'test',
      araelMcp: true,
      runIndex: 0,
      command: ['codex', 'exec'],
      success: true,
      exitCode: 0,
      timedOut: false,
      durationSeconds: 10,
      inputTokens: 100,
      outputTokens: 50,
      totalTokens: 150,
      costUsd: 0.01,
      flag: 'flag{<script>}',
      flagFound: true,
      flagCorrect: true,
      stdoutPath,
      stderrPath: stdoutPath.replace('.stdout.txt', '.stderr.txt'),
      outputPreview: 'flag{<script>}',
      errorMessage: null,
      resumed: false,
      dryRun: false
    }],
    summary: {
      challengeCount: 1,
      agentCount: 1,
      recordCount: 1,
      successCount: 1,
      failureCount: 0,
      timeoutCount: 0,
      solveCount: 1,
      gradedCount: 1,
      averageDurationSeconds: 10,
      totalTokens: 150,
      averageTokens: 150,
      totalCostUsd: 0.01,
      variants: [{
        engine: 'codex',
        model: 'test',
        araelMcp: true,
        recordCount: 1,
        solveCount: 1,
        solveRate: 1,
        flagFoundCount: 1,
        averageDurationSeconds: 10,
        totalTokens: 150,
        totalCostUsd: 0.01
      }]
    }
  };
}

function makeScores(): BenchmarkScores {
  const metric = makeMetric();
  return {
    functions: metric,
    functionNames: metric,
    entryPoints: metric,
    strings: metric,
    imports: metric,
    exports: metric,
    xrefs: metric,
    callgraph: metric,
    iocs: metric,
    iocsByType: {},
    behaviors: metric,
    mitre: metric,
    classificationCorrect: true,
    malwareTypeCorrect: null,
    mitreEvidenceQuality: null,
    iocDuplicateRate: null,
    iocNormalizationQuality: null,
    falsePositiveRate: null,
    falseNegativeRate: null
  };
}

function makeMetric(): MetricScore {
  return {
    expected: 1,
    detected: 1,
    truePositive: 1,
    falsePositive: 0,
    falseNegative: 0,
    precision: 1,
    recall: 1,
    f1: 1,
    completeGroundTruth: true
  };
}
