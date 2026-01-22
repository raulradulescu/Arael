/**
 * LLM Prompt Templates (v2.6)
 *
 * System prompts and templates for binary analysis queries.
 */

import { AnalysisResult } from '../output/schema';

export const SYSTEM_PROMPT = `You are Arael, an expert reverse engineering assistant. You analyze binaries and answer questions based on the provided analysis data.

Your capabilities:
- Analyze binary structure, functions, and strings
- Identify malicious behaviors and IOCs
- Map behaviors to MITRE ATT&CK techniques
- Explain code functionality in plain language
- Suggest analysis approaches

Guidelines:
- Be concise and technical
- Cite specific evidence (function names, addresses, strings)
- Indicate confidence levels when uncertain
- Suggest next analysis steps when relevant`;

export interface ContextData {
  binary: {
    filename: string;
    format: string;
    architecture: string;
    size: number;
    isPacked: boolean;
  };
  functionCount: number;
  stringCount: number;
  importCount: number;
  topFunctions: string[];
  suspiciousStrings: string[];
  importCategories: string[];
  behaviors?: string[];
  mitreAttack?: string[];
  iocs?: {
    ips: string[];
    urls: string[];
    domains: string[];
  };
}

/**
 * Build context from analysis result
 */
export function buildContext(analysis: AnalysisResult, contextData?: Partial<ContextData>): string {
  const binary = analysis.binary;
  const topFuncs = analysis.functions
    .filter(f => !f.name.startsWith('FUN_') && !f.isThunk)
    .slice(0, 20)
    .map(f => f.name);

  const suspiciousStrings = analysis.strings
    .filter(s =>
      /https?:\/\/|HKEY_|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|password|cmd\.exe/i.test(s.value)
    )
    .slice(0, 15)
    .map(s => s.value);

  const importCats = [...new Set(
    analysis.imports
      .filter(i => i.capabilities && i.capabilities.length > 0)
      .flatMap(i => i.capabilities || [])
  )];

  const ctx = {
    binary: {
      filename: binary.filename,
      format: binary.format,
      architecture: binary.architecture,
      size: binary.size,
      isPacked: binary.packing?.isPacked || false
    },
    functionCount: analysis.functions.length,
    stringCount: analysis.strings.length,
    importCount: analysis.imports.length,
    topFunctions: topFuncs,
    suspiciousStrings,
    importCategories: importCats,
    ...contextData
  };

  return `## Binary Analysis Context

**File:** ${ctx.binary.filename}
**Format:** ${ctx.binary.format} ${ctx.binary.architecture}
**Size:** ${(ctx.binary.size / 1024).toFixed(1)} KB
**Packed:** ${ctx.binary.isPacked ? 'Yes' : 'No'}

**Statistics:**
- Functions: ${ctx.functionCount}
- Strings: ${ctx.stringCount}
- Imports: ${ctx.importCount}

**Key Functions:** ${ctx.topFunctions.join(', ') || 'None identified'}

**Import Capabilities:** ${ctx.importCategories.join(', ') || 'None'}

${ctx.suspiciousStrings.length > 0 ? `**Suspicious Strings:**\n${ctx.suspiciousStrings.map(s => `- "${s}"`).join('\n')}` : ''}

${ctx.behaviors ? `**Detected Behaviors:** ${ctx.behaviors.join(', ')}` : ''}

${ctx.mitreAttack ? `**MITRE ATT&CK:** ${ctx.mitreAttack.join(', ')}` : ''}

${ctx.iocs && (ctx.iocs.ips.length || ctx.iocs.urls.length || ctx.iocs.domains.length) ?
  `**IOCs:**
${ctx.iocs.urls.length ? `- URLs: ${ctx.iocs.urls.join(', ')}` : ''}
${ctx.iocs.ips.length ? `- IPs: ${ctx.iocs.ips.join(', ')}` : ''}
${ctx.iocs.domains.length ? `- Domains: ${ctx.iocs.domains.join(', ')}` : ''}` : ''}`;
}

/**
 * Question templates for common queries
 */
export const QUESTION_TEMPLATES: Record<string, string> = {
  malicious: 'Is this binary malicious? Explain your reasoning based on the analysis data.',
  purpose: 'What is the primary purpose of this binary? What does it do?',
  main: 'Analyze the main function and explain what it does step by step.',
  network: 'Does this binary have network capabilities? What network-related activity can it perform?',
  persistence: 'Does this binary establish persistence? How does it ensure it runs after reboot?',
  credentials: 'Does this binary access credentials or sensitive data? What does it target?',
  evasion: 'Does this binary use any anti-analysis or evasion techniques?',
  iocs: 'What are the key Indicators of Compromise (IOCs) from this binary?',
  summary: 'Provide a brief executive summary of this binary\'s capabilities and risk level.'
};

/**
 * Format a question with context
 */
export function formatQuestion(
  question: string,
  analysis: AnalysisResult,
  contextData?: Partial<ContextData>
): string {
  const context = buildContext(analysis, contextData);
  return `${context}\n\n---\n\n**Question:** ${question}`;
}

/**
 * Parse template shorthand
 */
export function expandQuestion(input: string): string {
  const lower = input.toLowerCase().trim();

  // Check for template matches
  for (const [key, template] of Object.entries(QUESTION_TEMPLATES)) {
    if (lower === key || lower === `/${key}` || lower.startsWith(`${key}:`)) {
      return template;
    }
  }

  // Return as-is if no template match
  return input;
}
