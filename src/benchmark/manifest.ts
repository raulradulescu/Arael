import * as fs from 'fs';
import * as path from 'path';
import type {
  BenchmarkManifest,
  BenchmarkQuestion,
  BenchmarkSample,
  PricingTable
} from './types';
import { expandPatterns } from '../utils/glob';

interface RawManifest {
  version?: string;
  samples?: unknown;
  questions?: unknown;
}

export function loadBenchmarkManifest(manifestPath: string): BenchmarkManifest {
  const absolutePath = path.resolve(manifestPath);
  const parsed = JSON.parse(fs.readFileSync(absolutePath, 'utf-8')) as RawManifest;

  if (!Array.isArray(parsed.samples)) {
    throw new Error('Benchmark manifest must contain a samples array');
  }

  const baseDir = path.dirname(absolutePath);
  const samples = parsed.samples.map((entry, index) => normalizeSample(entry, index, baseDir));
  const questions = parseQuestions(parsed.questions, 'manifest questions');

  return {
    version: parsed.version,
    samples,
    questions
  };
}

export function loadBenchmarkQuestions(questionsPath: string): BenchmarkQuestion[] {
  const parsed = JSON.parse(fs.readFileSync(path.resolve(questionsPath), 'utf-8')) as unknown;
  return parseQuestions(Array.isArray(parsed) ? parsed : (parsed as { questions?: unknown }).questions, 'questions file') ?? [];
}

export function loadPricingTable(pricingPath: string): PricingTable {
  const parsed = JSON.parse(fs.readFileSync(path.resolve(pricingPath), 'utf-8')) as PricingTable;
  for (const [provider, models] of Object.entries(parsed)) {
    if (!models || typeof models !== 'object') {
      throw new Error(`Pricing provider ${provider} must map model names to prices`);
    }
    for (const [model, price] of Object.entries(models)) {
      if (
        typeof price.inputUsdPerMillionTokens !== 'number' ||
        typeof price.outputUsdPerMillionTokens !== 'number'
      ) {
        throw new Error(`Pricing entry ${provider}/${model} must include inputUsdPerMillionTokens and outputUsdPerMillionTokens`);
      }
    }
  }
  return parsed;
}

export function samplesFromTarget(target: string): BenchmarkSample[] {
  const absoluteTarget = path.resolve(target);

  if (fs.existsSync(absoluteTarget) && fs.statSync(absoluteTarget).isDirectory()) {
    return collectFiles(absoluteTarget).map(filePathToSample);
  }

  const matches = expandPatterns([target]);
  if (matches.length === 0 && fs.existsSync(absoluteTarget) && fs.statSync(absoluteTarget).isFile()) {
    return [filePathToSample(absoluteTarget)];
  }

  return matches.map(filePathToSample);
}

function normalizeSample(entry: unknown, index: number, baseDir: string): BenchmarkSample {
  if (!entry || typeof entry !== 'object') {
    throw new Error(`Manifest sample at index ${index} must be an object`);
  }

  const raw = entry as Partial<BenchmarkSample>;
  if (typeof raw.path !== 'string' || raw.path.length === 0) {
    throw new Error(`Manifest sample at index ${index} must include a path`);
  }

  const absolutePath = path.isAbsolute(raw.path) ? raw.path : path.resolve(baseDir, raw.path);
  return {
    ...raw,
    sampleId: raw.sampleId ?? path.basename(raw.path),
    path: absolutePath,
    fileName: raw.fileName ?? path.basename(raw.path)
  };
}

function parseQuestions(value: unknown, label: string): BenchmarkQuestion[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }

  return value.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`${label} entry ${index} must be an object`);
    }
    const question = entry as Partial<BenchmarkQuestion>;
    if (typeof question.id !== 'string' || typeof question.question !== 'string') {
      throw new Error(`${label} entry ${index} must include id and question`);
    }
    return {
      id: question.id,
      question: question.question,
      expectedKeywords: question.expectedKeywords,
      forbiddenClaims: question.forbiddenClaims,
      answerScore: question.answerScore
    };
  });
}

function collectFiles(dir: string): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }

  return results.sort();
}

function filePathToSample(filepath: string): BenchmarkSample {
  return {
    sampleId: path.basename(filepath),
    path: filepath,
    fileName: path.basename(filepath)
  };
}
