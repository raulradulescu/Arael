import type { AnalysisResult } from '../output/schema';
import type { ATTACKMapping } from '../analysis/mitre-mapper';
import type { DetectedBehavior } from '../analysis/behavior-detector';
import type { IOCCollection } from '../analysis/ioc-extractor';
import type { YaraScanResult } from '../utils/yara';
import type {
  BenchmarkGroundTruth,
  BenchmarkMetricName,
  BenchmarkScores,
  IOCType,
  MetricScore
} from './types';

const IOC_TYPES: IOCType[] = [
  'ips',
  'domains',
  'urls',
  'emails',
  'filePaths',
  'registryKeys',
  'mutexes',
  'userAgents'
];

export function scoreSet(
  expectedValues: string[] | undefined,
  detectedValues: string[],
  completeGroundTruth = false
): MetricScore {
  const expected = new Set((expectedValues ?? []).map(normalizeToken));
  const detected = new Set(detectedValues.map(normalizeToken));
  let truePositive = 0;

  for (const value of detected) {
    if (expected.has(value)) {
      truePositive += 1;
    }
  }

  const expectedCount = expected.size;
  const detectedCount = detected.size;
  const falsePositive = completeGroundTruth ? Math.max(0, detectedCount - truePositive) : null;
  const falseNegative = Math.max(0, expectedCount - truePositive);
  const precision = completeGroundTruth ? divideOrNull(truePositive, detectedCount) : null;
  const recall = expectedCount > 0 ? divideOrNull(truePositive, expectedCount) : null;
  const f1 = precision === null || recall === null ? null : harmonicMean(precision, recall);

  return {
    expected: expectedCount,
    detected: detectedCount,
    truePositive,
    falsePositive,
    falseNegative,
    precision,
    recall,
    f1,
    completeGroundTruth
  };
}

export function computeBenchmarkScores(input: {
  result?: AnalysisResult;
  groundTruth?: BenchmarkGroundTruth;
  iocs: IOCCollection;
  behaviors: DetectedBehavior[];
  mitre: ATTACKMapping;
  yara?: YaraScanResult;
  classification: { classification: string; malwareType?: string };
}): BenchmarkScores {
  const result = input.result;
  const groundTruth = input.groundTruth;
  const completeness = groundTruth?.complete ?? {};
  const functions = result?.functions ?? [];
  const functionNames = functions.map(func => func.name);
  const functionAddresses = functions.map(func => func.address);
  const entryPoints = [result?.entryPoint, result?.binary.entryPoint].filter(isString);
  const strings = (result?.strings ?? []).map(str => str.value);
  const imports = (result?.imports ?? []).map(imp => imp.name);
  const exports = (result?.exports ?? []).map(exp => exp.name);
  const xrefs = functions.flatMap(func => [
    ...func.callers.map(caller => `${caller}->${func.address}`),
    ...func.callees.map(callee => `${func.address}->${callee}`)
  ]);
  const callgraphEdges = functions.flatMap(func => func.callees.map(callee => `${func.name}->${callee}`));
  const behaviorIds = input.behaviors.map(behavior => behavior.id);
  const mitreIds = input.mitre.techniques.map(technique => technique.id);
  const yaraRules = (input.yara?.matches ?? []).map(match => match.rule);
  const flattenedIocs = flattenIocs(input.iocs);

  const iocsByType: BenchmarkScores['iocsByType'] = {};
  for (const type of IOC_TYPES) {
    iocsByType[type] = scoreSet(
      groundTruth?.expectedIOCs?.[type],
      input.iocs[type],
      Boolean(completeness.iocs)
    );
  }

  const classificationCorrect = groundTruth?.classification
    ? normalizeToken(groundTruth.classification) === normalizeToken(input.classification.classification)
    : null;
  const malwareTypeCorrect = groundTruth?.malwareType
    ? normalizeToken(groundTruth.malwareType) === normalizeToken(input.classification.malwareType ?? '')
    : null;

  return {
    functions: scoreSet(groundTruth?.expectedFunctions, functionAddresses, isComplete(completeness, 'functions')),
    functionNames: scoreSet(groundTruth?.expectedFunctionNames, functionNames, isComplete(completeness, 'functionNames')),
    entryPoints: scoreSet(groundTruth?.expectedEntryPoints, entryPoints, isComplete(completeness, 'entryPoints')),
    strings: scoreSet(groundTruth?.expectedStrings, strings, isComplete(completeness, 'strings')),
    imports: scoreSet(groundTruth?.expectedImports, imports, isComplete(completeness, 'imports')),
    exports: scoreSet(groundTruth?.expectedExports, exports, isComplete(completeness, 'exports')),
    xrefs: scoreSet(groundTruth?.expectedXrefs, xrefs, isComplete(completeness, 'xrefs')),
    callgraph: scoreSet(groundTruth?.expectedCallgraphEdges, callgraphEdges, isComplete(completeness, 'callgraph')),
    iocs: scoreSet(flattenExpectedIocs(groundTruth), flattenedIocs, isComplete(completeness, 'iocs')),
    iocsByType,
    behaviors: scoreSet(groundTruth?.expectedBehaviors, behaviorIds, isComplete(completeness, 'behaviors')),
    mitre: scoreSet(groundTruth?.expectedMitreTechniques, mitreIds, isComplete(completeness, 'mitre')),
    yara: input.yara ? scoreSet(groundTruth?.expectedYaraRules, yaraRules, isComplete(completeness, 'yara')) : undefined,
    classificationCorrect,
    malwareTypeCorrect,
    mitreEvidenceQuality: input.mitre.techniques.length > 0 ? average(input.mitre.techniques.map(t => evidenceQuality(t.evidence))) : null,
    iocDuplicateRate: duplicateRate(flattenedIocs),
    iocNormalizationQuality: normalizationQuality(flattenedIocs),
    falsePositiveRate: classificationFalsePositiveRate(groundTruth?.classification, input.classification.classification),
    falseNegativeRate: classificationFalseNegativeRate(groundTruth?.classification, input.classification.classification)
  };
}

export function flattenIocs(iocs: IOCCollection): string[] {
  return IOC_TYPES.flatMap(type => iocs[type].map(value => `${type}:${value}`));
}

function flattenExpectedIocs(groundTruth?: BenchmarkGroundTruth): string[] | undefined {
  if (!groundTruth?.expectedIOCs) {
    return undefined;
  }
  return IOC_TYPES.flatMap(type => (groundTruth.expectedIOCs?.[type] ?? []).map(value => `${type}:${value}`));
}

function normalizeToken(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function divideOrNull(numerator: number, denominator: number): number | null {
  if (denominator === 0) {
    return null;
  }
  return numerator / denominator;
}

function harmonicMean(a: number, b: number): number | null {
  if (a + b === 0) {
    return null;
  }
  return (2 * a * b) / (a + b);
}

function average(values: number[]): number | null {
  if (values.length === 0) {
    return null;
  }
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function duplicateRate(values: string[]): number | null {
  if (values.length === 0) {
    return null;
  }
  const unique = new Set(values.map(normalizeToken)).size;
  return (values.length - unique) / values.length;
}

function normalizationQuality(values: string[]): number | null {
  if (values.length === 0) {
    return null;
  }
  const normalized = values.filter(value => value === value.trim() && value === value.toLowerCase());
  return normalized.length / values.length;
}

function evidenceQuality(evidence: string[]): number {
  if (evidence.length === 0) {
    return 0;
  }
  if (evidence.some(item => /0x[0-9a-f]+|xref|decompil|function/i.test(item))) {
    return 3;
  }
  if (evidence.length >= 2) {
    return 2;
  }
  return 1;
}

function classificationFalsePositiveRate(expected: string | undefined, detected: string): number | null {
  if (!expected) {
    return null;
  }
  return isBenignLabel(expected) && !isBenignLabel(detected) ? 1 : 0;
}

function classificationFalseNegativeRate(expected: string | undefined, detected: string): number | null {
  if (!expected) {
    return null;
  }
  return !isBenignLabel(expected) && isBenignLabel(detected) ? 1 : 0;
}

function isBenignLabel(value: string): boolean {
  const normalized = normalizeToken(value);
  return normalized === 'benign' || normalized === 'clean' || normalized === 'goodware';
}

function isComplete(
  completeness: Partial<Record<BenchmarkMetricName, boolean>>,
  metric: BenchmarkMetricName
): boolean {
  return Boolean(completeness[metric]);
}

function isString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}
