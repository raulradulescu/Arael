import type { AnalysisResult } from '../output/schema';
import { runAskQuestion } from '../llm/ask-runner';
import type {
  BenchmarkQuestion,
  LLMMeasurement,
  PricingTable
} from './types';

export async function runLlmMeasurement(options: {
  result: AnalysisResult;
  question: BenchmarkQuestion;
  provider?: 'openai' | 'anthropic' | 'google' | 'ollama';
  model?: string;
  pricing?: PricingTable;
}): Promise<LLMMeasurement> {
  const askResult = await runAskQuestion({
    result: options.result,
    question: options.question.question,
    provider: options.provider,
    model: options.model
  });

  const usage = askResult.response.usage;
  const costUsd = usage
    ? calculateCost(options.pricing, askResult.response.provider, askResult.response.model, usage.inputTokens, usage.outputTokens)
    : null;

  return {
    response: askResult.response,
    question: options.question,
    latencySeconds: askResult.latencySeconds,
    costUsd,
    answerScore: scoreAnswer(askResult.response.content, options.question),
    hallucinationCount: countForbiddenClaims(askResult.response.content, options.question),
    evidenceCorrectness: null
  };
}

export function calculateCost(
  pricing: PricingTable | undefined,
  provider: string,
  model: string,
  inputTokens: number,
  outputTokens: number
): number | null {
  const entry = pricing?.[provider]?.[model];
  if (!entry) {
    return null;
  }

  return (
    (inputTokens / 1_000_000) * entry.inputUsdPerMillionTokens +
    (outputTokens / 1_000_000) * entry.outputUsdPerMillionTokens
  );
}

function scoreAnswer(answer: string, question: BenchmarkQuestion): number | null {
  if (typeof question.answerScore === 'number') {
    return question.answerScore;
  }
  if (!question.expectedKeywords || question.expectedKeywords.length === 0) {
    return null;
  }

  const normalizedAnswer = answer.toLowerCase();
  const matched = question.expectedKeywords.filter(keyword =>
    normalizedAnswer.includes(keyword.toLowerCase())
  ).length;

  return Math.round((matched / question.expectedKeywords.length) * 5);
}

function countForbiddenClaims(answer: string, question: BenchmarkQuestion): number | null {
  if (!question.forbiddenClaims || question.forbiddenClaims.length === 0) {
    return null;
  }

  const normalizedAnswer = answer.toLowerCase();
  return question.forbiddenClaims.filter(claim =>
    normalizedAnswer.includes(claim.toLowerCase())
  ).length;
}
