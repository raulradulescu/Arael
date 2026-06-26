import type { AnalysisResult } from '../output/schema';
import {
  createProvider,
  type LLMProviderConfig,
  type LLMResponse
} from './provider';
import { SYSTEM_PROMPT, expandQuestion, formatQuestion } from './prompts';

export interface AskRunOptions {
  result: AnalysisResult;
  question: string;
  provider?: 'openai' | 'anthropic' | 'google' | 'ollama';
  model?: string;
}

export interface AskRunResult {
  question: string;
  formattedQuestion: string;
  response: LLMResponse;
  latencySeconds: number;
}

export async function runAskQuestion(options: AskRunOptions): Promise<AskRunResult> {
  const providerConfig: Partial<LLMProviderConfig> = {};
  if (options.provider) {
    providerConfig.provider = options.provider;
  }
  if (options.model) {
    providerConfig.model = options.model;
  }

  const provider = createProvider(providerConfig);
  const isAvailable = await provider.isAvailable();
  if (!isAvailable) {
    throw new Error(`Provider '${provider.name}' is not available`);
  }

  const question = expandQuestion(options.question);
  const formattedQuestion = formatQuestion(question, options.result);
  const start = process.hrtime.bigint();
  const response = await provider.chat([
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: formattedQuestion }
  ]);

  return {
    question,
    formattedQuestion,
    response,
    latencySeconds: Number(process.hrtime.bigint() - start) / 1_000_000_000
  };
}
