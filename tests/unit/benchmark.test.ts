import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scoreSet, computeBenchmarkScores } from '../../src/benchmark/metrics';
import { loadBenchmarkManifest } from '../../src/benchmark/manifest';
import { formatBenchmarkResult } from '../../src/benchmark/reporters';
import { calculateCost } from '../../src/benchmark/llm';
import type { AnalysisResult } from '../../src/output/schema';
import type { BenchmarkRunResult } from '../../src/benchmark/types';

describe('benchmark metrics', () => {
  it('computes precision and recall when ground truth is complete', () => {
    const score = scoreSet(['main', 'helper'], ['main', 'extra'], true);

    expect(score.truePositive).toBe(1);
    expect(score.falsePositive).toBe(1);
    expect(score.falseNegative).toBe(1);
    expect(score.precision).toBe(0.5);
    expect(score.recall).toBe(0.5);
    expect(score.f1).toBe(0.5);
  });

  it('reports recall only when ground truth is incomplete', () => {
    const score = scoreSet(['main'], ['main', 'extra'], false);

    expect(score.precision).toBeNull();
    expect(score.falsePositive).toBeNull();
    expect(score.recall).toBe(1);
    expect(score.f1).toBeNull();
  });

  it('scores analysis outputs against ground truth', () => {
    const result = makeAnalysisResult();
    const scores = computeBenchmarkScores({
      result,
      groundTruth: {
        complete: {
          functions: true,
          strings: true,
          imports: true,
          behaviors: true,
          mitre: true
        },
        expectedFunctions: ['0x1000'],
        expectedStrings: ['http://example.test'],
        expectedImports: ['connect'],
        expectedBehaviors: ['network_client'],
        expectedMitreTechniques: ['T1071'],
        classification: 'suspicious'
      },
      iocs: {
        ips: [],
        domains: [],
        urls: ['http://example.test'],
        emails: [],
        filePaths: [],
        registryKeys: [],
        mutexes: [],
        userAgents: []
      },
      behaviors: [{
        id: 'network_client',
        category: 'network',
        description: 'network',
        evidence: ['import: connect'],
        riskLevel: 'medium',
        confidence: 0.9,
        mitreId: 'T1071'
      }],
      mitre: {
        tactics: ['Command and Control'],
        techniques: [{
          id: 'T1071',
          name: 'Application Layer Protocol',
          tactic: 'Command and Control',
          confidence: 0.9,
          evidence: ['import: connect']
        }],
        summary: 'network'
      },
      classification: { classification: 'suspicious' }
    });

    expect(scores.functions.precision).toBe(1);
    expect(scores.imports.recall).toBe(1);
    expect(scores.behaviors.f1).toBe(1);
    expect(scores.mitre.f1).toBe(1);
    expect(scores.classificationCorrect).toBe(true);
  });
});

describe('benchmark manifest and reporters', () => {
  it('loads manifest samples relative to the manifest file', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael-bench-'));
    const samplePath = path.join(tempDir, 'sample.bin');
    const manifestPath = path.join(tempDir, 'manifest.json');
    fs.writeFileSync(samplePath, 'sample');
    fs.writeFileSync(manifestPath, JSON.stringify({
      samples: [{ sampleId: 's1', path: 'sample.bin' }]
    }));

    const manifest = loadBenchmarkManifest(manifestPath);

    expect(manifest.samples).toHaveLength(1);
    expect(manifest.samples[0]?.path).toBe(samplePath);
  });

  it('formats JSONL, CSV, Markdown, LaTeX, and HTML reports', () => {
    const result = makeBenchmarkRunResult();

    expect(formatBenchmarkResult(result, 'jsonl')).toContain('"type":"sample"');
    expect(formatBenchmarkResult(result, 'csv')).toContain('run_id');
    expect(formatBenchmarkResult(result, 'markdown')).toContain('# Arael Benchmark Report');
    expect(formatBenchmarkResult(result, 'latex')).toContain('\\begin{table}');
    expect(formatBenchmarkResult(result, 'html')).toContain('<!DOCTYPE html>');
  });
});

describe('benchmark LLM cost', () => {
  it('calculates token costs from supplied pricing tables', () => {
    const cost = calculateCost({
      openai: {
        'test-model': {
          inputUsdPerMillionTokens: 1,
          outputUsdPerMillionTokens: 2
        }
      }
    }, 'openai', 'test-model', 1_000_000, 500_000);

    expect(cost).toBe(2);
  });
});

function makeAnalysisResult(): AnalysisResult {
  return {
    version: '1.0.0',
    metadata: {
      analysisId: 'a1',
      timestamp: '2026-01-01T00:00:00.000Z',
      araelVersion: 'test',
      ghidraVersion: 'test',
      analysisDurationMs: 10,
      connectionMode: 'headless',
      cached: false
    },
    binary: {
      filename: 'sample',
      filepath: '/tmp/sample',
      size: 1024,
      hashes: { md5: 'm', sha1: 's', sha256: 'h' },
      format: 'ELF',
      architecture: 'x86_64',
      bits: 64,
      endianness: 'little',
      entryPoint: '0x1000',
      imageBase: '0x0'
    },
    entryPoint: '0x1000',
    imageBase: '0x0',
    functions: [{
      name: 'main',
      address: '0x1000',
      size: 10,
      signature: 'int main()',
      isThunk: false,
      isExternal: false,
      callers: [],
      callees: ['connect'],
      pseudocode: 'connect();'
    }],
    strings: [{
      address: '0x2000',
      value: 'http://example.test',
      length: 19,
      encoding: 'ascii',
      xrefs: []
    }],
    imports: [{
      name: 'connect',
      library: 'libc',
      address: '0x3000',
      type: 'function'
    }],
    exports: []
  };
}

function makeBenchmarkRunResult(): BenchmarkRunResult {
  return {
    runId: 'r1',
    timestamp: '2026-01-01T00:00:00.000Z',
    records: [{
      runId: 'r1',
      timestamp: '2026-01-01T00:00:00.000Z',
      araelVersion: 'test',
      gitCommit: null,
      sampleId: 's1',
      sha256: 'abc',
      fileName: 'sample',
      filePath: '/tmp/sample',
      fileSizeMb: 1,
      format: 'ELF',
      architecture: 'x86_64',
      compiler: null,
      optimization: null,
      stripped: null,
      packed: null,
      command: 'arael analyze sample',
      runIndex: 1,
      analysisSuccess: true,
      errorType: null,
      errorMessage: null,
      timeout: false,
      classification: 'benign',
      classificationConfidence: 0.5,
      groundTruthLabel: 'benign',
      counts: {
        functionsDetected: 1,
        stringsDetected: 1,
        importsDetected: 1,
        exportsDetected: 0,
        xrefsDetected: 0,
        yaraMatches: 0,
        iocsDetected: 0,
        behaviorsDetected: 0,
        mitreTechniquesDetected: 0
      },
      performance: {
        analysisTimeSeconds: 1,
        ghidraReportedAnalysisTimeSeconds: 1,
        yaraScanTimeSeconds: null,
        contextGenerationTimeSeconds: 0.01,
        totalWallTimeSeconds: 1.1,
        peakMemoryMb: 100,
        outputJsonSizeKb: 12,
        cacheHitOrMiss: 'miss',
        cachedRunTimeSeconds: null,
        speedupRatio: null,
        secondsPerMb: 1.1,
        secondsPerFunction: 1.1,
        memoryMbPerMbBinary: 100,
        jsonKbPerMbBinary: 12
      },
      scores: computeBenchmarkScores({
        result: makeAnalysisResult(),
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
        classification: { classification: 'benign' }
      })
    }],
    llmRecords: [],
    summary: {
      sampleCount: 1,
      recordCount: 1,
      llmRecordCount: 0,
      successCount: 1,
      failureCount: 0,
      timeoutCount: 0,
      averageTotalWallTimeSeconds: 1.1,
      averageAnalysisTimeSeconds: 1,
      averagePeakMemoryMb: 100,
      averageFunctionRecall: null,
      averageBehaviorF1: null,
      averageIocF1: null,
      averageMitreF1: null,
      averageClassificationAccuracy: 1,
      averageLlmAnswerScore: null
    }
  };
}
