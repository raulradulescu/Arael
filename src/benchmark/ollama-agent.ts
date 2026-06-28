import * as path from 'path';
import * as fs from 'fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

/**
 * Agentic Ollama runner: unlike the single-shot static-context path, this drives a
 * local model through Ollama's /api/chat tool-calling loop with the Arael MCP
 * reverse-engineering tools attached. The model can request a tool (disassemble,
 * decompile, strings, hexdump, ...), the harness proxies it to the Arael MCP
 * server, and the result is fed back until the model produces a final report.
 *
 * This is what makes "+arael" meaningful for local models: without it the Ollama
 * path is blind (one completion over a fixed context); with it the model gets the
 * same tool surface the cloud agents do.
 */

export interface OllamaAgentResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  errorMessage: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
}

interface OllamaToolCall {
  function: { name: string; arguments: unknown };
}

interface OllamaChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  thinking?: string;
  tool_calls?: OllamaToolCall[];
  tool_name?: string;
}

interface OllamaChatResponse {
  message?: OllamaChatMessage;
  prompt_eval_count?: number;
  eval_count?: number;
  done?: boolean;
}

/** Max agentic iterations before we force the model to summarize. */
const MAX_ITERATIONS = 12;
/** Cap each tool result fed back into context to keep CPU inference tractable. */
const MAX_TOOL_RESULT_CHARS = 4000;
/** Ollama context window for the loop. Bigger = more memory/slower on CPU. */
const NUM_CTX = 4096;

/**
 * Generic local tools available alongside the Arael MCP tools. The cloud agents
 * that run "+arael" still have their own shell/file access, so to mirror them the
 * local agent gets basic file inspection that works on ANY file (Arael's binary
 * tools reject non-PE/ELF inputs like PDFs).
 */
const LOCAL_TOOLS = [
  {
    type: 'function' as const,
    function: {
      name: 'read_file_text',
      description: 'Read a file as UTF-8 text. Use for source code, scripts, text/PDF-ish files. Returns up to maxBytes bytes.',
      parameters: {
        type: 'object',
        properties: {
          filepath: { type: 'string', description: 'Absolute path to the file' },
          maxBytes: { type: 'number', description: 'Max bytes to read (default 8000)' }
        },
        required: ['filepath']
      }
    }
  },
  {
    type: 'function' as const,
    function: {
      name: 'read_file_hex',
      description: 'Hexdump a byte range of any file. Use for binary inspection of arbitrary offsets.',
      parameters: {
        type: 'object',
        properties: {
          filepath: { type: 'string', description: 'Absolute path to the file' },
          offset: { type: 'number', description: 'Start byte offset (default 0)' },
          length: { type: 'number', description: 'Number of bytes (default 512, max 4096)' }
        },
        required: ['filepath']
      }
    }
  },
  {
    type: 'function' as const,
    function: {
      name: 'local_strings',
      description: 'Extract printable ASCII strings from ANY file (works where Arael rejects non-PE/ELF formats).',
      parameters: {
        type: 'object',
        properties: {
          filepath: { type: 'string', description: 'Absolute path to the file' },
          minLength: { type: 'number', description: 'Minimum string length (default 4)' }
        },
        required: ['filepath']
      }
    }
  }
];
const LOCAL_TOOL_NAMES = new Set(LOCAL_TOOLS.map(tool => tool.function.name));

export async function runOllamaAgent(input: {
  url: string;
  model: string;
  prompt: string;
  challengePath: string;
  fileListing: string;
  araelServerPath: string;
  timeoutSeconds: number;
}): Promise<OllamaAgentResult> {
  const transcript: string[] = [];
  let inputTokens = 0;
  let outputTokens = 0;

  // Connect to the Arael MCP server over stdio (same server the cloud agents use).
  const client = new Client({ name: 'arael-ollama-bench', version: '1.0.0' }, { capabilities: {} });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [input.araelServerPath]
  });

  let tools: Array<{ type: 'function'; function: { name: string; description: string; parameters: unknown } }> = [];
  try {
    await client.connect(transport);
    const listed = await client.listTools();
    const araelTools = listed.tools.map(tool => ({
      type: 'function' as const,
      function: {
        name: tool.name,
        description: tool.description ?? '',
        parameters: tool.inputSchema ?? { type: 'object', properties: {} }
      }
    }));
    tools = [...araelTools, ...LOCAL_TOOLS];
  } catch (error) {
    await safeClose(client);
    return {
      stdout: '',
      stderr: `Failed to start Arael MCP server: ${errString(error)}`,
      exitCode: null,
      timedOut: false,
      errorMessage: `Arael MCP server unavailable: ${errString(error)}`,
      inputTokens: null,
      outputTokens: null
    };
  }

  const systemPrompt = `${input.prompt}

You have reverse-engineering tools available. Use them to inspect files rather than guessing.
- The arael_* tools work on PE/ELF executables (disassemble, decompile, functions, imports, strings, xrefs, hexdump).
- For NON-executable files (PDFs, scripts, data) the arael_* tools will reject the format with "Unsupported binary format".
  In that case use the generic tools instead: read_file_text, read_file_hex, local_strings (these work on ANY file).
All tool calls take a "filepath" argument: pass an absolute path to a file in the challenge directory.
Work iteratively: call a tool, read its output, then decide the next step. When you have recovered the
flag (or are confident you cannot), stop calling tools and write your final analyst report as plain text.
The final message MUST contain the recovered flag verbatim if you found one.`;

  const userContext = `Challenge directory: ${input.challengePath}

Files in the challenge (absolute paths):
${input.fileListing}

Begin by inspecting the most relevant file with the appropriate tool.`;

  const messages: OllamaChatMessage[] = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userContext }
  ];

  const endpoint = `${input.url.replace(/\/+$/, '')}/api/chat`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), input.timeoutSeconds * 1000);
  let timedOut = false;
  let finalText = '';
  let errorMessage: string | null = null;
  // Some models (gemma3, some GGUF imports) reject the tools param; once we see that
  // 400 we stop sending tools and rely on text-encoded tool calls for the rest.
  let toolsUnsupported = false;

  try {
    for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
      // On the last allowed iteration, drop tools so the model is forced to answer.
      const wantTools = iteration < MAX_ITERATIONS - 1 && !toolsUnsupported;
      const buildBody = (withTools: boolean): string => JSON.stringify({
        model: input.model,
        messages,
        tools: withTools ? tools : undefined,
        stream: false,
        options: { num_ctx: NUM_CTX }
      });
      // One retry on transient transport failures (Ollama occasionally resets the
      // socket between turns when reloading the model under memory pressure).
      const postWithRetry = async (bodyStr: string): Promise<Response> => {
        try {
          return await postChat(endpoint, bodyStr, controller.signal);
        } catch (firstError) {
          if (controller.signal.aborted) {
            throw firstError;
          }
          transcript.push(`[retry] chat request failed (${errString(firstError)}); retrying once`);
          return postChat(endpoint, bodyStr, controller.signal);
        }
      };

      let response = await postWithRetry(buildBody(wantTools));
      let bodyText = await response.text();

      // Model rejects the tools param outright -> retry once without it and rely on
      // text-encoded tool calls (the tools are described in the system prompt).
      if (!response.ok && wantTools && response.status === 400 && /does not support tools/i.test(bodyText)) {
        toolsUnsupported = true;
        transcript.push('[info] model rejects native tools; falling back to text-encoded tool calls');
        response = await postWithRetry(buildBody(false));
        bodyText = await response.text();
      }

      if (!response.ok) {
        errorMessage = `Ollama HTTP ${response.status}`;
        transcript.push(`[ollama error ${response.status}] ${bodyText.slice(0, 500)}`);
        break;
      }

      const body = JSON.parse(bodyText) as OllamaChatResponse;
      inputTokens += numOr0(body.prompt_eval_count);
      outputTokens += numOr0(body.eval_count);

      const msg = body.message;
      if (!msg) {
        transcript.push('[ollama] empty message in response');
        break;
      }

      messages.push(msg);
      // Smaller local models often emit tool calls as raw JSON in the text content
      // instead of Ollama's structured tool_calls field; recover those too.
      const structuredCalls = msg.tool_calls ?? [];
      const toolCalls = structuredCalls.length > 0
        ? structuredCalls
        : parseTextToolCalls(msg.content ?? '');

      if (msg.content && msg.content.trim().length > 0) {
        transcript.push(`[assistant] ${msg.content.slice(0, 800)}`);
        // Only treat content as the final report when it is NOT a text-encoded tool call.
        if (toolCalls.length === 0) {
          finalText = msg.content;
        }
      } else if (msg.thinking && msg.thinking.trim().length > 0) {
        // Reasoning-only turn (e.g. qwen3.5) with empty content: preserve the thinking
        // so a flag mentioned only in the model's reasoning is still graded.
        transcript.push(`[thinking] ${msg.thinking.slice(0, 800)}`);
        if (toolCalls.length === 0) {
          finalText = msg.thinking;
        }
      }

      if (toolCalls.length === 0) {
        // No tool requested -> this is the model's final answer.
        break;
      }

      for (const call of toolCalls) {
        const name = call.function?.name ?? '(unknown)';
        const args = normalizeArgs(call.function?.arguments);
        transcript.push(`[tool call] ${name}(${JSON.stringify(args).slice(0, 300)})`);
        let toolText: string;
        try {
          if (LOCAL_TOOL_NAMES.has(name)) {
            toolText = runLocalTool(name, args);
          } else {
            const callResult = await client.callTool({ name, arguments: args });
            toolText = extractToolText(callResult);
          }
        } catch (error) {
          toolText = `ERROR: ${errString(error)}`;
        }
        const truncated = toolText.length > MAX_TOOL_RESULT_CHARS
          ? `${toolText.slice(0, MAX_TOOL_RESULT_CHARS)}\n...[truncated ${toolText.length - MAX_TOOL_RESULT_CHARS} chars]`
          : toolText;
        transcript.push(`[tool result] ${truncated.slice(0, 800)}`);
        messages.push({ role: 'tool', content: truncated, tool_name: name });
      }
    }
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      timedOut = true;
    } else {
      errorMessage = `Ollama agent loop failed: ${errString(error)}`;
      transcript.push(errorMessage);
    }
  } finally {
    clearTimeout(timer);
    await safeClose(client);
    // Evict this model from Ollama's memory immediately so the next cell's model
    // loads into freed RAM. Without this, Ollama keeps each model resident for its
    // default keep_alive (~5 min), stacking multiple models and exhausting memory.
    await unloadModel(input.url, input.model);
  }

  // Fall back to the running transcript if the model never emitted plain-text content.
  const stdout = finalText.trim().length > 0 ? finalText : transcript.join('\n');

  return {
    stdout,
    stderr: transcript.join('\n'),
    exitCode: timedOut ? null : errorMessage ? null : 0,
    timedOut,
    errorMessage: timedOut ? null : errorMessage,
    inputTokens: inputTokens || null,
    outputTokens: outputTokens || null
  };
}

/** Tell Ollama to drop a model from memory now (keep_alive: 0). Best-effort. */
async function unloadModel(url: string, model: string): Promise<void> {
  try {
    await fetch(`${url.replace(/\/+$/, '')}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, keep_alive: 0 })
    });
  } catch {
    /* best effort: if this fails the model simply expires on its own keep_alive */
  }
}

async function postChat(endpoint: string, body: string, signal: AbortSignal): Promise<Response> {
  return fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal
  });
}

/** Execute a built-in local file tool (works on any file, unlike Arael's binary tools). */
function runLocalTool(name: string, args: Record<string, unknown>): string {
  const filepath = typeof args.filepath === 'string' ? args.filepath : '';
  if (!filepath) {
    return 'ERROR: missing "filepath" argument';
  }
  if (name === 'read_file_text') {
    const maxBytes = clampNum(args.maxBytes, 8000, 1, 32000);
    const buf = readBounded(filepath, maxBytes);
    return buf.toString('utf8');
  }
  if (name === 'read_file_hex') {
    const offset = clampNum(args.offset, 0, 0, Number.MAX_SAFE_INTEGER);
    const length = clampNum(args.length, 512, 1, 4096);
    const buf = readRange(filepath, offset, length);
    return hexdumpLocal(buf, offset);
  }
  if (name === 'local_strings') {
    const minLength = clampNum(args.minLength, 4, 1, 64);
    const buf = readBounded(filepath, 1024 * 1024);
    return extractStringsLocal(buf, minLength, 500).join('\n') || '(no printable strings found)';
  }
  return `ERROR: unknown local tool ${name}`;
}

function clampNum(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  if (!Number.isFinite(n)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function readBounded(filepath: string, maxBytes: number): Buffer {
  try {
    const fd = fs.openSync(filepath, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, maxBytes);
      const buf = Buffer.alloc(size);
      fs.readSync(fd, buf, 0, size, 0);
      return buf;
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    return Buffer.from(`ERROR reading file: ${errString(error)}`);
  }
}

function readRange(filepath: string, offset: number, length: number): Buffer {
  try {
    const fd = fs.openSync(filepath, 'r');
    try {
      const total = fs.fstatSync(fd).size;
      const start = Math.min(offset, total);
      const size = Math.min(length, Math.max(0, total - start));
      const buf = Buffer.alloc(size);
      fs.readSync(fd, buf, 0, size, start);
      return buf;
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    return Buffer.from(`ERROR reading file: ${errString(error)}`);
  }
}

function hexdumpLocal(buffer: Buffer, baseOffset: number): string {
  const lines: string[] = [];
  for (let i = 0; i < buffer.length; i += 16) {
    const slice = buffer.subarray(i, i + 16);
    const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(slice).map(b => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${(baseOffset + i).toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join('\n') || '(empty)';
}

function extractStringsLocal(buffer: Buffer, minLength: number, limit: number): string[] {
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

/** Recover tool calls a model emitted as raw JSON text instead of structured tool_calls. */
function parseTextToolCalls(content: string): OllamaToolCall[] {
  if (!content || content.indexOf('"name"') === -1) {
    return [];
  }
  const calls: OllamaToolCall[] = [];
  for (const candidate of extractJsonObjects(content)) {
    try {
      const obj = JSON.parse(candidate) as unknown;
      const items = Array.isArray(obj) ? obj : [obj];
      for (const item of items) {
        if (item && typeof item === 'object' && typeof (item as { name?: unknown }).name === 'string') {
          const rec = item as { name: string; arguments?: unknown; parameters?: unknown };
          calls.push({ function: { name: rec.name, arguments: rec.arguments ?? rec.parameters ?? {} } });
        }
      }
    } catch {
      /* ignore non-JSON fragments */
    }
  }
  return calls;
}

/** Scan text for balanced top-level {...} JSON objects, respecting string literals. */
function extractJsonObjects(text: string): string[] {
  const results: string[] = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) {
        esc = false;
      } else if (c === '\\') {
        esc = true;
      } else if (c === '"') {
        inStr = false;
      }
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === '{') {
      if (depth === 0) {
        start = i;
      }
      depth++;
    } else if (c === '}') {
      if (depth > 0) {
        depth--;
        if (depth === 0 && start >= 0) {
          results.push(text.slice(start, i + 1));
          start = -1;
        }
      }
    }
  }
  return results;
}

function normalizeArgs(args: unknown): Record<string, unknown> {
  if (args && typeof args === 'object') {
    return args as Record<string, unknown>;
  }
  if (typeof args === 'string') {
    try {
      return JSON.parse(args) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  return {};
}

function extractToolText(result: unknown): string {
  const content = (result as { content?: Array<{ type?: string; text?: string }> })?.content;
  if (Array.isArray(content)) {
    const text = content
      .filter(part => part?.type === 'text' && typeof part.text === 'string')
      .map(part => part.text)
      .join('\n');
    if (text.length > 0) {
      return text;
    }
  }
  return JSON.stringify(result);
}

function numOr0(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function errString(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function safeClose(client: Client): Promise<void> {
  try {
    await client.close();
  } catch {
    /* ignore */
  }
}

/** Absolute-path file listing (largest first) for the agentic prompt context. */
export function buildAbsoluteFileListing(challengePath: string): string {
  const files: Array<{ file: string; size: number }> = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        let size = 0;
        try {
          size = fs.statSync(full).size;
        } catch {
          /* ignore */
        }
        files.push({ file: full, size });
      }
    }
  };
  try {
    walk(challengePath);
  } catch {
    /* ignore */
  }
  return files
    .sort((a, b) => b.size - a.size)
    .slice(0, 50)
    .map(({ file, size }) => `- ${file} (${size} bytes)`)
    .join('\n') || '(none)';
}
