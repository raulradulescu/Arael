/**
 * LLM Provider Abstraction (v2.6)
 *
 * Supports: OpenAI, Anthropic, Google (Gemini), Ollama
 */

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LLMResponse {
  content: string;
  model: string;
  provider: string;
  usage?: {
    inputTokens: number;
    outputTokens: number;
  };
}

export interface LLMProviderConfig {
  provider: 'openai' | 'anthropic' | 'google' | 'ollama';
  apiKey?: string;
  baseUrl?: string;
  model?: string;
}

export interface LLMProvider {
  name: string;
  chat(messages: LLMMessage[]): Promise<LLMResponse>;
  isAvailable(): Promise<boolean>;
}

// Default models per provider
const DEFAULT_MODELS: Record<string, string> = {
  openai: 'gpt-4o-mini',
  anthropic: 'claude-sonnet-4-20250514',
  google: 'gemini-2.0-flash',
  ollama: 'llama3.2'
};

/**
 * OpenAI Provider
 */
export class OpenAIProvider implements LLMProvider {
  name = 'openai';
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(config: Partial<LLMProviderConfig> = {}) {
    this.apiKey = config.apiKey ?? process.env['OPENAI_API_KEY'] ?? '';
    this.model = config.model ?? DEFAULT_MODELS.openai!;
    this.baseUrl = config.baseUrl ?? 'https://api.openai.com/v1';
  }

  async isAvailable(): Promise<boolean> {
    return !!this.apiKey;
  }

  async chat(messages: LLMMessage[]): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({
        model: this.model,
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        max_tokens: 4096
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error: ${response.status} - ${error}`);
    }

    const data = await response.json() as {
      choices: { message: { content: string } }[];
      model: string;
      usage?: { prompt_tokens: number; completion_tokens: number };
    };

    return {
      content: data.choices[0]?.message?.content || '',
      model: data.model,
      provider: this.name,
      usage: data.usage ? {
        inputTokens: data.usage.prompt_tokens,
        outputTokens: data.usage.completion_tokens
      } : undefined
    };
  }
}

/**
 * Anthropic Provider
 */
export class AnthropicProvider implements LLMProvider {
  name = 'anthropic';
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(config: Partial<LLMProviderConfig> = {}) {
    this.apiKey = config.apiKey ?? process.env['ANTHROPIC_API_KEY'] ?? '';
    this.model = config.model ?? DEFAULT_MODELS.anthropic!;
    this.baseUrl = config.baseUrl ?? 'https://api.anthropic.com/v1';
  }

  async isAvailable(): Promise<boolean> {
    return !!this.apiKey;
  }

  async chat(messages: LLMMessage[]): Promise<LLMResponse> {
    // Extract system message
    const systemMsg = messages.find(m => m.role === 'system');
    const chatMsgs = messages.filter(m => m.role !== 'system');

    const response = await fetch(`${this.baseUrl}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: 4096,
        system: systemMsg?.content || '',
        messages: chatMsgs.map(m => ({ role: m.role, content: m.content }))
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Anthropic API error: ${response.status} - ${error}`);
    }

    const data = await response.json() as {
      content: { text: string }[];
      model: string;
      usage?: { input_tokens: number; output_tokens: number };
    };

    return {
      content: data.content[0]?.text || '',
      model: data.model,
      provider: this.name,
      usage: data.usage ? {
        inputTokens: data.usage.input_tokens,
        outputTokens: data.usage.output_tokens
      } : undefined
    };
  }
}

/**
 * Google Gemini Provider
 */
export class GoogleProvider implements LLMProvider {
  name = 'google';
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(config: Partial<LLMProviderConfig> = {}) {
    this.apiKey = config.apiKey ?? process.env['GOOGLE_API_KEY'] ?? process.env['GEMINI_API_KEY'] ?? '';
    this.model = config.model ?? DEFAULT_MODELS.google!;
    this.baseUrl = config.baseUrl ?? 'https://generativelanguage.googleapis.com/v1beta';
  }

  async isAvailable(): Promise<boolean> {
    return !!this.apiKey;
  }

  async chat(messages: LLMMessage[]): Promise<LLMResponse> {
    // Convert messages to Gemini format
    // Gemini uses 'user' and 'model' roles, and system instruction is separate
    const systemMsg = messages.find(m => m.role === 'system');
    const chatMsgs = messages.filter(m => m.role !== 'system');

    const contents = chatMsgs.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }]
    }));

    const requestBody: {
      contents: { role: string; parts: { text: string }[] }[];
      systemInstruction?: { parts: { text: string }[] };
      generationConfig: { maxOutputTokens: number };
    } = {
      contents,
      generationConfig: {
        maxOutputTokens: 4096
      }
    };

    // Add system instruction if present
    if (systemMsg) {
      requestBody.systemInstruction = {
        parts: [{ text: systemMsg.content }]
      };
    }

    const response = await fetch(
      `${this.baseUrl}/models/${this.model}:generateContent?key=${this.apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Google API error: ${response.status} - ${error}`);
    }

    const data = await response.json() as {
      candidates: { content: { parts: { text: string }[] } }[];
      usageMetadata?: {
        promptTokenCount: number;
        candidatesTokenCount: number;
      };
    };

    const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

    return {
      content,
      model: this.model,
      provider: this.name,
      usage: data.usageMetadata ? {
        inputTokens: data.usageMetadata.promptTokenCount,
        outputTokens: data.usageMetadata.candidatesTokenCount
      } : undefined
    };
  }
}

/**
 * Ollama Provider (local)
 */
export class OllamaProvider implements LLMProvider {
  name = 'ollama';
  private model: string;
  private baseUrl: string;

  constructor(config: Partial<LLMProviderConfig> = {}) {
    this.model = config.model ?? process.env['OLLAMA_MODEL'] ?? DEFAULT_MODELS.ollama!;
    this.baseUrl = config.baseUrl ?? process.env['OLLAMA_HOST'] ?? 'http://localhost:11434';
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`, { method: 'GET' });
      return response.ok;
    } catch {
      return false;
    }
  }

  async chat(messages: LLMMessage[]): Promise<LLMResponse> {
    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        stream: false
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Ollama API error: ${response.status} - ${error}`);
    }

    const data = await response.json() as {
      message: { content: string };
      model: string;
      eval_count?: number;
      prompt_eval_count?: number;
    };

    return {
      content: data.message?.content || '',
      model: data.model,
      provider: this.name,
      usage: (data.eval_count || data.prompt_eval_count) ? {
        inputTokens: data.prompt_eval_count || 0,
        outputTokens: data.eval_count || 0
      } : undefined
    };
  }
}

/**
 * Create provider from config or auto-detect
 */
export function createProvider(config?: Partial<LLMProviderConfig>): LLMProvider {
  if (config?.provider) {
    switch (config.provider) {
      case 'openai': return new OpenAIProvider(config);
      case 'anthropic': return new AnthropicProvider(config);
      case 'google': return new GoogleProvider(config);
      case 'ollama': return new OllamaProvider(config);
    }
  }

  // Auto-detect based on available API keys
  if (process.env['ANTHROPIC_API_KEY']) {
    return new AnthropicProvider(config);
  }
  if (process.env['OPENAI_API_KEY']) {
    return new OpenAIProvider(config);
  }
  if (process.env['GOOGLE_API_KEY'] || process.env['GEMINI_API_KEY']) {
    return new GoogleProvider(config);
  }

  // Default to Ollama (local)
  return new OllamaProvider(config);
}

/**
 * Get available providers
 */
export async function getAvailableProviders(): Promise<string[]> {
  const providers: LLMProvider[] = [
    new OpenAIProvider(),
    new AnthropicProvider(),
    new GoogleProvider(),
    new OllamaProvider()
  ];

  const available: string[] = [];
  for (const provider of providers) {
    if (await provider.isAvailable()) {
      available.push(provider.name);
    }
  }

  return available;
}
