#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { glob } from '../utils/glob';
import { getConnection } from '../ghidra/connection';
import { analyzeHandler } from '../mcp/handlers/analyze';
import { decompileHandler } from '../mcp/handlers/decompile';
import { functionsHandler } from '../mcp/handlers/functions';
import { stringsHandler } from '../mcp/handlers/strings';
import { importsHandler } from '../mcp/handlers/imports';
import { hexdumpHandler } from '../mcp/handlers/hexdump';
import { disassembleHandler } from '../mcp/handlers/disassemble';
import { exportsHandler } from '../mcp/handlers/exports';
import { xrefsHandler } from '../mcp/handlers/xrefs';
import { callgraphHandler } from '../mcp/handlers/callgraph';
import { getCache, type AnalysisCacheEntry, type AnalysisCacheEntrySummary } from '../cache/store';
import { logger } from '../utils/logger';
import { loadEnvFromFile } from '../utils/env';
import { startShell } from './shell';
import { scan, isYaraInstalled, getAvailableCategories, getAvailableRuleSets, isRLRulesAvailable, getRLRuleStats } from '../utils/yara';
import { getAvailableProviders } from '../llm/provider';
import { QUESTION_TEMPLATES } from '../llm/prompts';
import { buildAnalysisContext } from '../llm/context';
import { runAskQuestion } from '../llm/ask-runner';
import { runBenchmark } from '../benchmark/runner';
import { runAgentBenchmark, parseAgentSpecs } from '../benchmark/agent-runner';
import { formatBenchmarkResult, formatAgentBenchmarkResult } from '../benchmark/reporters';
import type { AgentBenchmarkFormat, BenchmarkFormat } from '../benchmark/types';
import { renderAnalysisHtml, escapeHtml } from '../output/html';
import type { AnalysisResult } from '../output/schema';

export { escapeHtml };

loadEnvFromFile();

// Get version from package.json
let version = '1.0.0';
try {
  const packagePath = path.join(__dirname, '../../package.json');
  if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8')) as { version?: string };
    version = pkg.version ?? '1.0.0';
  }
} catch {
  // Use default
}

const program = new Command();

program
  .name('arael')
  .description('Reverse engineering assistant that uses Ghidra for static binary analysis')
  .version(version);

program
  .command('analyze <filepath>')
  .description('Run full Ghidra analysis and emit JSON (metadata, functions, strings, imports, packing)')
  .option('-f, --force', 'Bypass cache and re-analyze')
  .option('-o, --output <format>', 'Output format (json|summary)', 'json')
  .action(async (filepath: string, options: { force?: boolean; output?: string }) => {
    try {
      await initConnection();
      logger.userMessage('Analyzing binary (this may take 10-60 seconds)...');
      const result = await analyzeHandler({ filepath, force: options.force });

      outputResult(result, options.output);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('context <filepath>')
  .description('Generate LLM-focused context with behaviors, IOCs, MITRE mapping, and key functions')
  .option('-j, --json', 'Output as JSON')
  .option('--focus <area>', 'Focus area: security, functionality, all', 'all')
  .option('--include-code', 'Include pseudocode for key functions')
  .action(async (filepath: string, options: { json?: boolean; focus?: string; includeCode?: boolean }) => {
    try {
      await initConnection();
      logger.userMessage('Generating LLM context (analyzing binary)...');
      const result = await analyzeHandler({ filepath });

      const context = buildAnalysisContext(result);

      if (options.json) {
        console.log(JSON.stringify(context, null, 2));
      } else {
        // Human-readable output
        console.log('\n' + '='.repeat(70));
        console.log('ARAEL CONTEXT ANALYSIS (v2.6)');
        console.log('='.repeat(70));

        console.log(`\nBinary: ${context.binary.filename}`);
        console.log(`Format: ${context.binary.format} ${context.binary.architecture} (${context.binary.bits}-bit)`);
        console.log(`Size: ${(context.binary.size / 1024).toFixed(1)} KB`);
        if (context.binary.isPacked) console.log(`Packing: PACKED (entropy: ${context.binary.entropy?.toFixed(2)})`);

        console.log('\n--- CLASSIFICATION ---');
        console.log(`Type: ${context.classification.type.toUpperCase()}${context.classification.malwareType ? ` (${context.classification.malwareType})` : ''}`);
        console.log(`Confidence: ${(context.classification.confidence * 100).toFixed(0)}%`);
        console.log(`Reasoning: ${context.classification.reasoning.join('; ')}`);

        console.log('\n--- SUMMARY ---');
        console.log(context.summary);

        console.log('\n--- RISK ASSESSMENT ---');
        console.log(`Overall Risk: ${context.riskAssessment.overall.toUpperCase()}`);
        console.log(`Import Risk: ${context.riskAssessment.importRisk}`);
        if (context.riskAssessment.criticalBehaviors.length > 0) {
          console.log(`Critical: ${context.riskAssessment.criticalBehaviors.join('; ')}`);
        }

        if (context.behaviors.length > 0) {
          console.log('\n--- BEHAVIORS DETECTED ---');
          for (const b of context.behaviors.slice(0, 8)) {
            const icon = b.riskLevel === 'critical' ? '!!' : b.riskLevel === 'high' ? '!' : '-';
            console.log(`[${icon}] ${b.description} (${b.category})`);
          }
        }

        if (context.mitreAttack.techniques.length > 0) {
          console.log('\n--- MITRE ATT&CK ---');
          console.log(`Tactics: ${context.mitreAttack.tactics.join(', ')}`);
          console.log('Techniques:');
          for (const t of context.mitreAttack.techniques.slice(0, 6)) {
            console.log(`  ${t.id}: ${t.name} (${(t.confidence * 100).toFixed(0)}%)`);
          }
        }

        const hasIOCs = context.iocs.ips.length || context.iocs.domains.length || context.iocs.urls.length;
        if (hasIOCs) {
          console.log('\n--- IOCs ---');
          if (context.iocs.urls.length) console.log(`URLs: ${context.iocs.urls.join(', ')}`);
          if (context.iocs.ips.length) console.log(`IPs: ${context.iocs.ips.join(', ')}`);
          if (context.iocs.domains.length) console.log(`Domains: ${context.iocs.domains.join(', ')}`);
          if (context.iocs.registryKeys.length) console.log(`Registry: ${context.iocs.registryKeys.slice(0, 3).join(', ')}`);
        }

        console.log('\n--- SUGGESTED ANALYSIS ---');
        for (const step of context.suggestedAnalysis) {
          console.log(`  * ${step}`);
        }

        console.log('\n--- STATS ---');
        console.log(`Functions: ${context.stats.functions} | Strings: ${context.stats.strings} | Imports: ${context.stats.imports}`);
        console.log(`Behaviors: ${context.stats.behaviorsDetected} | IOCs: ${context.stats.iocsFound} | ATT&CK: ${context.stats.techniquesMatched}`);

        console.log('\n' + '='.repeat(70));
        console.log('Use --json for full machine-readable output');
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('ask [filepath]')
  .description('Ask questions about a binary using an LLM (OpenAI, Anthropic, Google, or Ollama)')
  .option('-q, --question <text>', 'Question to ask (or use template: malicious, purpose, main, network, persistence, credentials, evasion, iocs, summary)')
  .option('-p, --provider <name>', 'LLM provider: openai, anthropic, google, ollama (auto-detects by default)')
  .option('-m, --model <name>', 'Model name (default: provider-specific)')
  .option('--list-templates', 'List available question templates')
  .option('--list-providers', 'List available LLM providers')
  .action(async (filepath: string | undefined, options: { question?: string; provider?: string; model?: string; listTemplates?: boolean; listProviders?: boolean }) => {
    try {
      // List templates
      if (options.listTemplates) {
        console.log('Available question templates:\n');
        for (const [key, template] of Object.entries(QUESTION_TEMPLATES)) {
          console.log(`  ${key.padEnd(14)} - ${template.substring(0, 60)}...`);
        }
        console.log('\nUsage: arael ask ./binary -q malicious');
        console.log('       arael ask ./binary -q "What encryption algorithm is used?"');
        return;
      }

      // List providers
      if (options.listProviders) {
        console.log('Checking available LLM providers...\n');
        const available = await getAvailableProviders();
        console.log('Available providers:');
        for (const p of available) {
          console.log(`  ✓ ${p}`);
        }
        const allProviders = ['openai', 'anthropic', 'google', 'ollama'];
        const unavailable = allProviders.filter(p => !available.includes(p));
        if (unavailable.length > 0) {
          console.log('\nUnavailable (no API key or not running):');
          for (const p of unavailable) {
            console.log(`  ✗ ${p}`);
          }
        }
        console.log('\nSet API keys via: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY (or GEMINI_API_KEY)');
        console.log('For Ollama: ensure ollama is running on localhost:11434');
        return;
      }

      if (!filepath) {
        console.error('Error: filepath is required. Usage: arael ask ./binary -q "your question"');
        process.exit(1);
      }

      if (!options.question) {
        console.error('Error: --question is required. Use --list-templates to see available templates.');
        process.exit(1);
      }

      // Initialize and analyze
      await initConnection();
      logger.userMessage('Analyzing binary...');
      const result = await analyzeHandler({ filepath });

      logger.userMessage('Querying LLM...');
      const askResult = await runAskQuestion({
        result,
        question: options.question,
        provider: options.provider as 'openai' | 'anthropic' | 'google' | 'ollama' | undefined,
        model: options.model
      });
      const { question, response } = askResult;

      // Output
      console.log('\n' + '='.repeat(70));
      console.log(`ARAEL ASK (${response.provider}/${response.model})`);
      console.log('='.repeat(70));
      console.log(`\nQuestion: ${question}\n`);
      console.log(response.content);

      if (response.usage) {
        console.log(`\n[Tokens: ${response.usage.inputTokens} in / ${response.usage.outputTokens} out]`);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('functions <filepath>')
  .description('List discovered functions with addresses and sizes (filtering supported)')
  .option('--filter <regex>', 'Filter functions by name pattern')
  .option('--exclude-thunks', 'Exclude thunk functions')
  .option('--exclude-external', 'Exclude external functions')
  .action(async (filepath: string, options: { filter?: string; excludeThunks?: boolean; excludeExternal?: boolean }) => {
    try {
      await initConnection();
      const result = await functionsHandler({
        filepath,
        filter: {
          namePattern: options.filter,
          excludeThunks: options.excludeThunks,
          excludeExternal: options.excludeExternal
        }
      });

      const summary = result.map((f) => ({
        name: f.name,
        address: f.address,
        size: f.size
      }));

      console.log(JSON.stringify(summary, null, 2));
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('decompile <filepath>')
  .description('Decompile a function by name or address into C-like pseudocode')
  .requiredOption('--function <name>', 'Function name or address')
  .action(async (filepath: string, options: { function: string }) => {
    try {
      await initConnection();
      const result = await decompileHandler({ filepath, function: options.function });

      if (result.pseudocode) {
        console.log(result.pseudocode);
        return;
      }

      console.error(result.error ?? `No decompilation available for ${options.function}`);
      process.exit(1);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('strings <filepath>')
  .description('Extract printable strings with optional xrefs and length filtering')
  .option('--min-length <n>', 'Minimum string length', '4')
  .option('--with-xrefs', 'Include cross-references')
  .action(async (filepath: string, options: { minLength?: string; withXrefs?: boolean }) => {
    try {
      if (process.env['ARAEL_USE_SYSTEM_STRINGS'] !== '1') {
        await initConnection();
      }
      const minLength = parseInt(options.minLength ?? '4', 10);
      const strings = await stringsHandler({ filepath, minLength });
      const formatted = strings.map((s) => {
        if (options.withXrefs) {
          return s;
        }
        return {
          address: s.address,
          value: s.value,
          length: s.length
        };
      });

      console.log(JSON.stringify(formatted, null, 2));
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('imports <filepath>')
  .description('List imported symbols with libraries and capability tags')
  .action(async (filepath: string) => {
    try {
      await initConnection();
      const result = await importsHandler({ filepath });
      console.log(JSON.stringify(result.imports, null, 2));
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('hexdump <filepath>')
  .description('Hex dump raw bytes from a start address and length')
  .requiredOption('--address <addr>', 'Start address (0x...)')
  .option('--length <n>', 'Number of bytes', '256')
  .action(async (filepath: string, options: { address: string; length?: string }) => {
    try {
      const result = await hexdumpHandler({
        filepath,
        start: options.address,
        length: parseInt(options.length ?? '256', 10)
      });

      console.log(result.formatted);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('disassemble <filepath>')
  .description('Disassemble a function by name or address into an assembly listing')
  .requiredOption('--function <name>', 'Function name or address')
  .action(async (filepath: string, options: { function: string }) => {
    try {
      await initConnection();
      const result = await disassembleHandler({ filepath, function: options.function });

      if (result.instructions && result.instructions.length > 0) {
        for (const inst of result.instructions) {
          console.log(`${inst.address}  ${(inst.bytes ?? '').padEnd(24)} ${inst.mnemonic} ${inst.operands}`);
        }
      } else {
        console.error(result.error ?? 'No disassembly available');
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('exports <filepath>')
  .description('List exported symbols and optionally filter by name pattern')
  .option('--filter <regex>', 'Filter exports by name pattern')
  .action(async (filepath: string, options: { filter?: string }) => {
    try {
      await initConnection();
      const result = await exportsHandler({ filepath });

      let exports = result.exports;
      if (options.filter) {
        const regex = new RegExp(options.filter, 'i');
        exports = exports.filter(e => regex.test(e.name));
      }

      console.log(JSON.stringify({ exports, totalCount: exports.length }, null, 2));
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('xrefs <filepath>')
  .description('Show cross-references to/from an address or function name')
  .requiredOption('--address <addr>', 'Address or function name')
  .option('--direction <dir>', 'Direction: to, from, or both', 'both')
  .action(async (filepath: string, options: { address: string; direction?: string }) => {
    try {
      await initConnection();
      const result = await xrefsHandler({
        filepath,
        address: options.address,
        direction: options.direction as 'to' | 'from' | 'both'
      });

      console.log(JSON.stringify(result, null, 2));
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('callgraph <filepath>')
  .description('Generate call graph output in JSON, DOT, or Mermaid with optional root/depth')
  .option('--root <func>', 'Root function (default: all)')
  .option('--format <fmt>', 'Output format: json, dot, mermaid', 'mermaid')
  .option('--depth <n>', 'Maximum depth', '10')
  .action(async (filepath: string, options: { root?: string; format?: string; depth?: string }) => {
    try {
      await initConnection();
      const result = await callgraphHandler({
        filepath,
        rootFunction: options.root,
        format: options.format as 'json' | 'dot' | 'mermaid',
        maxDepth: parseInt(options.depth ?? '10', 10)
      });

      console.log(result.output ?? result.graphData ?? JSON.stringify(result, null, 2));
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('shell <filepath>')
  .description('Start an interactive REPL for common analysis commands on a binary')
  .action(async (filepath: string) => {
    try {
      await startShell(filepath);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('batch <pattern>')
  .description('Analyze multiple binaries from a glob pattern and save JSON results')
  .option('-o, --output <dir>', 'Output directory for JSON results', './arael_output')
  .option('-f, --force', 'Bypass cache and re-analyze')
  .option('--summary', 'Print summary table after completion')
  .action(async (pattern: string, options: { output?: string; force?: boolean; summary?: boolean }) => {
    try {
      await initConnection();

      const files = glob(pattern);
      if (files.length === 0) {
        console.error(`No files found matching: ${pattern}`);
        process.exit(1);
      }

      const outputDir = options.output ?? './arael_output';
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      console.log(`Found ${files.length} files to analyze\n`);

      const results: Array<{ file: string; status: string; functions: number; time: number }> = [];

      for (let i = 0; i < files.length; i++) {
        const file = files[i]!;
        const basename = path.basename(file);
        const start = Date.now();

        process.stdout.write(`[${i + 1}/${files.length}] ${basename}... `);

        try {
          const result = await analyzeHandler({ filepath: file, force: options.force });
          const duration = Date.now() - start;

          // Save result
          const outputPath = path.join(outputDir, `${basename}.json`);
          fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));

          console.log(`OK (${result.functions.length} funcs, ${(duration / 1000).toFixed(1)}s)`);
          results.push({ file: basename, status: 'OK', functions: result.functions.length, time: duration });
        } catch (error) {
          const duration = Date.now() - start;
          console.log(`FAILED: ${error instanceof Error ? error.message : error}`);
          results.push({ file: basename, status: 'FAILED', functions: 0, time: duration });
        }
      }

      if (options.summary) {
        console.log('\n' + '='.repeat(70));
        console.log('SUMMARY');
        console.log('='.repeat(70));
        console.log(`${'File'.padEnd(40)} ${'Status'.padEnd(10)} ${'Functions'.padEnd(10)} Time`);
        console.log('-'.repeat(70));
        for (const r of results) {
          console.log(`${r.file.substring(0, 39).padEnd(40)} ${r.status.padEnd(10)} ${String(r.functions).padEnd(10)} ${(r.time / 1000).toFixed(1)}s`);
        }
        console.log('-'.repeat(70));
        const ok = results.filter(r => r.status === 'OK').length;
        const failed = results.filter(r => r.status === 'FAILED').length;
        const totalTime = results.reduce((a, b) => a + b.time, 0);
        console.log(`Total: ${ok} succeeded, ${failed} failed, ${(totalTime / 1000).toFixed(1)}s`);
      }

      console.log(`\nResults saved to: ${outputDir}/`);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('benchmark <target>')
  .description('Run thesis-grade benchmarks over a binary, glob, directory, or manifest corpus')
  .option('--manifest <file>', 'Ground-truth manifest JSON file')
  .option('-o, --output <file>', 'Write report to file instead of stdout')
  .option('--format <format>', 'Report format: json|jsonl|csv|markdown|latex|html', 'json')
  .option('-f, --force', 'Bypass cache for the first run of each sample')
  .option('--runs <n>', 'Number of runs per sample', '1')
  .option('--timeout <seconds>', 'Headless analysis timeout in seconds')
  .option('--include-yara', 'Run built-in and ReversingLabs YARA rules when available')
  .option('--with-llm', 'Run configured LLM questions for each successful sample')
  .option('-p, --provider <name>', 'LLM provider: openai, anthropic, google, ollama')
  .option('-m, --model <name>', 'LLM model name')
  .option('--questions <file>', 'JSON file containing benchmark LLM questions')
  .option('--pricing-file <file>', 'JSON pricing table for optional LLM cost calculation')
  .action(async (target: string, options: {
    manifest?: string;
    output?: string;
    format?: string;
    force?: boolean;
    runs?: string;
    timeout?: string;
    includeYara?: boolean;
    withLlm?: boolean;
    provider?: string;
    model?: string;
    questions?: string;
    pricingFile?: string;
  }) => {
    try {
      const format = parseBenchmarkFormat(options.format ?? 'json');
      const outputPath = options.output ?? (format === 'html' ? defaultBenchmarkOutputPath('benchmark') : undefined);
      if (format === 'html' && !options.output) {
        console.warn(`HTML output requested without -o; writing to ${outputPath}`);
      }
      const runs = parsePositiveInt(options.runs ?? '1', '--runs');
      const timeoutSeconds = options.timeout ? parsePositiveInt(options.timeout, '--timeout') : undefined;

      await initConnection(timeoutSeconds ? timeoutSeconds * 1000 : undefined);
      const result = await runBenchmark({
        target,
        manifestPath: options.manifest,
        outputPath,
        format,
        force: Boolean(options.force),
        runs,
        timeoutSeconds,
        includeYara: Boolean(options.includeYara),
        withLlm: Boolean(options.withLlm),
        provider: options.provider as 'openai' | 'anthropic' | 'google' | 'ollama' | undefined,
        model: options.model,
        questionsPath: options.questions,
        pricingFile: options.pricingFile
      });

      const rendered = formatBenchmarkResult(result, format, { outputPath });
      if (outputPath) {
        ensureOutputDirectory(outputPath);
        fs.writeFileSync(outputPath, rendered);
        console.log(`Benchmark report written to: ${outputPath}`);
      } else {
        process.stdout.write(rendered);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('benchmark-agents <target>')
  .description('Run external Codex/Claude agents against challenge directories for reversing benchmarks')
  .option('--extract-archives', 'Extract zip/7z archives before collecting challenge directories')
  .option('--archive-password <password>', 'Archive password for protected challenge zips')
  .option('--extract-output <dir>', 'Directory for extracted challenge archives')
  .option('-o, --output <file>', 'Write report to file instead of stdout')
  .option('--format <format>', 'Report format: json|jsonl|csv|variant-csv|markdown|html', 'markdown')
  .option('--agents <spec>', 'Comma-separated specs like codex:gpt-5.5,claude:claude-opus-4-8+arael,ollama:qwen3.5:4b (append +arael to attach the Arael MCP server; ignored for ollama)')
  .option('--timeout <seconds>', 'Timeout per agent/challenge run', '1800')
  .option('--max-challenges <n>', 'Limit number of challenge directories')
  .option('--runs <n>', 'Repeat each agent/challenge cell N times for variance', '1')
  .option('--concurrency <n>', 'Max agent processes to run in parallel', '1')
  .option('--force', 'Re-run cells even if a cached per-cell record exists')
  .option('--pricing <file>', 'JSON pricing table for per-run USD cost estimates')
  .option('--ground-truth <file>', 'JSON map of challengeId -> expected flag(s) for auto-grading')
  .option('--codex-bin <path>', 'Codex executable', 'codex')
  .option('--claude-bin <path>', 'Claude executable', 'claude')
  .option('--antigravity-bin <path>', 'Antigravity (agy) executable for antigravity:* (alias agy:) instances', 'agy')
  .option('--ollama-host <url>', 'Ollama server base URL for ollama:* local-model instances', 'http://localhost:11434')
  .option('--arael-server <path>', 'Arael MCP server entrypoint for +arael instances (default: bundled dist/mcp/server.js)')
  .option('--prompt <file>', 'Custom prompt file for agent runs')
  .option('--dry-run', 'Collect targets and commands without invoking agents')
  .action(async (target: string, options: {
    extractArchives?: boolean;
    archivePassword?: string;
    extractOutput?: string;
    output?: string;
    format?: string;
    agents?: string;
    timeout?: string;
    maxChallenges?: string;
    runs?: string;
    concurrency?: string;
    force?: boolean;
    pricing?: string;
    groundTruth?: string;
    codexBin?: string;
    claudeBin?: string;
    antigravityBin?: string;
    ollamaHost?: string;
    araelServer?: string;
    prompt?: string;
    dryRun?: boolean;
  }) => {
    try {
      const format = parseAgentBenchmarkFormat(options.format ?? 'markdown');
      const outputPath = options.output ?? (format === 'html' ? defaultBenchmarkOutputPath('agent-benchmark') : undefined);
      if (format === 'html' && !options.output) {
        console.warn(`HTML output requested without -o; writing to ${outputPath}`);
      }
      const timeoutSeconds = parsePositiveInt(options.timeout ?? '1800', '--timeout');
      const maxChallenges = options.maxChallenges
        ? parsePositiveInt(options.maxChallenges, '--max-challenges')
        : undefined;
      const runs = parsePositiveInt(options.runs ?? '1', '--runs');
      const concurrency = parsePositiveInt(options.concurrency ?? '1', '--concurrency');

      const result = await runAgentBenchmark({
        target,
        outputPath,
        format,
        agents: parseAgentSpecs(options.agents),
        timeoutSeconds,
        extractArchives: Boolean(options.extractArchives),
        archivePassword: options.archivePassword,
        extractOutput: options.extractOutput,
        maxChallenges,
        runs,
        concurrency,
        force: Boolean(options.force),
        pricingFile: options.pricing,
        groundTruthPath: options.groundTruth,
        codexBin: options.codexBin ?? 'codex',
        claudeBin: options.claudeBin ?? 'claude',
        antigravityBin: options.antigravityBin ?? 'agy',
        ollamaUrl: options.ollamaHost ?? 'http://localhost:11434',
        araelServerPath: options.araelServer,
        promptPath: options.prompt,
        dryRun: Boolean(options.dryRun)
      });

      const rendered = formatAgentBenchmarkResult(result, format, { outputPath });
      if (outputPath) {
        ensureOutputDirectory(outputPath);
        fs.writeFileSync(outputPath, rendered);
        console.log(`Agent benchmark report written to: ${outputPath}`);
      } else {
        process.stdout.write(rendered);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('report [filepath]')
  .description('Generate a standalone HTML report with stats, top functions, and strings')
  .option('-o, --output <file>', 'Output HTML file', 'report.html')
  .option('--title <title>', 'Report title')
  .option('--from-json <file>', 'Render report from an existing AnalysisResult JSON file')
  .option('--from-cache <identifier>', 'Render report from cached SQLite analysis by path, row id, cache key, or SHA-256')
  .option('--cache-only', 'Fail instead of running Ghidra when no cache entry is available')
  .option('--open', 'Open the generated report in the default browser')
  .action(async (filepath: string | undefined, options: {
    output?: string;
    title?: string;
    fromJson?: string;
    fromCache?: string;
    cacheOnly?: boolean;
    open?: boolean;
  }) => {
    try {
      const { result, sourceLabel } = await loadReportAnalysis(filepath, options);

      const html = renderAnalysisHtml(result, {
        title: options.title,
        sourceLabel
      });
      const outputPath = options.output ?? 'report.html';
      ensureOutputDirectory(outputPath);
      fs.writeFileSync(outputPath, html);

      console.log(`Report generated: ${outputPath}`);
      if (options.open) {
        openFile(outputPath);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('yara [filepath]')
  .description('Scan with built-in or custom YARA rules, or list available rule sets')
  .option('-r, --rules <file>', 'Custom YARA rules file')
  .option('-s, --ruleset <set>', 'Rule set: builtin, reversinglabs, all (default: builtin)')
  .option('-c, --category <cat>', 'Filter by category (packer, crypto, network, anti-debug, suspicious, ctf, shellcode, evasion, malware, compiler, ransomware)')
  .option('-l, --list-rules', 'List available rule sets and categories')
  .option('-j, --json', 'Output as JSON')
  .action(async (filepath: string | undefined, options: { rules?: string; ruleset?: string; category?: string; listRules?: boolean; json?: boolean }) => {
    try {
      // List available rules
      if (options.listRules) {
        console.log('Available Rule Sets:\n');
        const ruleSets = getAvailableRuleSets();
        for (const rs of ruleSets) {
          const status = rs.available ? `${rs.ruleCount} rules` : '(not installed)';
          console.log(`  ${rs.name.padEnd(15)} - ${rs.description} [${status}]`);
        }

        if (isRLRulesAvailable()) {
          console.log('\nReversingLabs Categories:');
          const rlStats = getRLRuleStats();
          for (const stat of rlStats) {
            console.log(`  ${stat.category.padEnd(15)} - ${stat.count} rules`);
          }
        }

        console.log('\nBuilt-in Categories:');
        const categories = getAvailableCategories();
        for (const cat of categories) {
          console.log(`  ${cat}`);
        }
        return;
      }

      if (!filepath) {
        console.error('Error: filepath is required unless --list-rules is used.');
        process.exit(1);
      }

      const yaraInstalled = await isYaraInstalled();
      if (!yaraInstalled) {
        console.log('Note: YARA not installed. Using basic pattern matching.');
        console.log('Install YARA for more accurate scanning: https://yara.readthedocs.io/\n');
      }

      // Determine rule set to use
      let result;
      if (options.rules) {
        // Custom rules file takes precedence
        if (!fs.existsSync(options.rules)) {
          console.error(`Rules file not found: ${options.rules}`);
          process.exit(1);
        }
        result = await scan(filepath, { customRulesPath: options.rules });
      } else {
        // Use specified rule set or default to builtin
        const ruleSet = options.ruleset || 'builtin';
        result = await scan(filepath, { ruleSet });
      }

      // Filter by category if specified
      if (options.category) {
        result.matches = result.matches.filter(m =>
          m.tags.includes(options.category!) ||
          m.rule.toLowerCase().includes(options.category!.toLowerCase()) ||
          (m.meta && m.meta.category === options.category)
        );
      }

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.matches.length === 0) {
          console.log('No matches found.');
        } else {
          console.log(`Found ${result.matches.length} matches:\n`);
          console.log(`${'Rule'.padEnd(30)} ${'Tags'.padEnd(20)} ${'Source'.padEnd(15)} Strings`);
          console.log('-'.repeat(80));
          for (const match of result.matches) {
            const tags = match.tags.join(', ') || '-';
            const source = match.meta?.source || 'builtin';
            const stringCount = match.strings.length > 0 ? `${match.strings.length} strings` : '-';
            console.log(`${match.rule.padEnd(30)} ${tags.padEnd(20)} ${source.padEnd(15)} ${stringCount}`);
          }
        }

        // Show rules used
        if (result.rulesUsed.length > 0) {
          console.log(`\nRules used: ${result.rulesUsed.join(', ')}`);
        }

        if (result.errors.length > 0) {
          console.log('\nErrors:');
          for (const err of result.errors) {
            console.log(`  - ${err}`);
          }
        }

        console.log(`\nCategories available: ${getAvailableCategories().join(', ')}`);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('cache')
  .description('Show cache stats or clear cached analyses')
  .option('--stats', 'Show cache statistics')
  .option('--clear', 'Clear all cached analyses')
  .option('--list', 'List cached analyses')
  .option('--limit <n>', 'Maximum entries to list', '20')
  .option('--show <identifier>', 'Show a cached analysis entry by path, row id, cache key, or SHA-256')
  .option('--export <identifier>', 'Export a cached AnalysisResult JSON by path, row id, cache key, or SHA-256')
  .option('-o, --output <file>', 'Output file for --export')
  .option('--json', 'Emit JSON for --list or --show')
  .action((options: {
    stats?: boolean;
    clear?: boolean;
    list?: boolean;
    limit?: string;
    show?: string;
    export?: string;
    output?: string;
    json?: boolean;
  }) => {
    const cache = getCache();

    if (options.clear) {
      const count = cache.invalidateAll();
      console.log(`Cleared ${count} cached analyses`);
      return;
    }

    if (options.list) {
      const entries = cache.listEntries(parsePositiveInt(options.limit ?? '20', '--limit'));
      if (options.json) {
        console.log(JSON.stringify(entries, null, 2));
      } else {
        printCacheEntries(entries);
      }
      return;
    }

    if (options.show) {
      const entry = cache.getEntry(options.show);
      if (!entry) {
        console.error(`No cached analysis found for: ${options.show}`);
        process.exit(1);
      }
      if (options.json) {
        console.log(JSON.stringify(entry, null, 2));
      } else {
        printCacheEntry(entry);
      }
      return;
    }

    if (options.export) {
      const entry = cache.getEntry(options.export);
      if (!entry) {
        console.error(`No cached analysis found for: ${options.export}`);
        process.exit(1);
      }
      const json = `${JSON.stringify(entry.analysis, null, 2)}\n`;
      if (options.output) {
        ensureOutputDirectory(options.output);
        fs.writeFileSync(options.output, json);
        console.log(`Cached analysis exported to: ${options.output}`);
      } else {
        process.stdout.write(json);
      }
      return;
    }

    if (options.stats) {
      const stats = cache.getStats();
      console.log(`Cache entries: ${stats.count}`);
      console.log(`Cache size: ${(stats.sizeBytes / 1024).toFixed(2)} KB`);
      console.log(`Cache database: ${cache.getDbPath()}`);
      return;
    }

    program.help();
  });

// Helper functions
async function initConnection(timeoutMs?: number): Promise<void> {
  const ghidraPath = process.env['GHIDRA_PATH'] ?? '';
  const bridgePortValue = process.env['GHIDRA_BRIDGE_PORT'];
  const bridgePort = bridgePortValue ? parseInt(bridgePortValue, 10) : undefined;
  const connection = getConnection({
    ghidraPath,
    bridgeHost: process.env['GHIDRA_BRIDGE_HOST'],
    bridgePort,
    pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH'],
    timeout: timeoutMs
  });
  await connection.connect();
}

function outputResult(result: unknown, format?: string): void {
  if (format === 'summary') {
    const r = result as import('../output/schema').AnalysisResult;
    console.log(`Binary: ${r.binary.filename}`);
    console.log(`Format: ${r.binary.format} ${r.binary.architecture}`);
    console.log(`Entry Point: ${r.binary.entryPoint}`);
    console.log(`Functions: ${r.functions.length}`);
    console.log(`Strings: ${r.strings.length}`);
    console.log(`Imports: ${r.imports.length}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}

function parseBenchmarkFormat(value: string): BenchmarkFormat {
  if (value === 'json' || value === 'jsonl' || value === 'csv' || value === 'markdown' || value === 'latex' || value === 'html') {
    return value;
  }
  throw new Error(`Invalid benchmark format: ${value}`);
}

function parseAgentBenchmarkFormat(value: string): AgentBenchmarkFormat {
  if (value === 'json' || value === 'jsonl' || value === 'csv' || value === 'variant-csv' || value === 'markdown' || value === 'html') {
    return value;
  }
  throw new Error(`Invalid agent benchmark format: ${value}`);
}

function parsePositiveInt(value: string, optionName: string): number {
  const parsed = parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${optionName} must be a positive integer`);
  }
  return parsed;
}

interface ReportCommandOptions {
  fromJson?: string;
  fromCache?: string;
  cacheOnly?: boolean;
}

async function loadReportAnalysis(
  filepath: string | undefined,
  options: ReportCommandOptions
): Promise<{ result: AnalysisResult; sourceLabel: string }> {
  if (options.fromJson) {
    return {
      result: parseAnalysisJsonFile(options.fromJson),
      sourceLabel: `JSON: ${options.fromJson}`
    };
  }

  if (options.fromCache) {
    const entry = getCache().getEntry(options.fromCache);
    if (!entry) {
      throw new Error(`No cached analysis found for: ${options.fromCache}`);
    }
    return {
      result: entry.analysis,
      sourceLabel: `SQLite cache row ${entry.id}`
    };
  }

  if (!filepath) {
    throw new Error('A binary path, --from-json, or --from-cache is required');
  }

  const jsonResult = maybeParseAnalysisJsonFile(filepath);
  if (jsonResult) {
    return {
      result: jsonResult,
      sourceLabel: `JSON: ${filepath}`
    };
  }

  const cached = getCache().get(filepath);
  if (cached) {
    return {
      result: cached,
      sourceLabel: `SQLite cache: ${filepath}`
    };
  }

  if (options.cacheOnly) {
    throw new Error(`No cached analysis found for: ${filepath}`);
  }

  await initConnection();
  logger.userMessage('Analyzing binary...');
  return {
    result: await analyzeHandler({ filepath }),
    sourceLabel: `Live analysis: ${filepath}`
  };
}

function maybeParseAnalysisJsonFile(filePath: string): AnalysisResult | null {
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    return null;
  }

  if (path.extname(filePath).toLowerCase() === '.json') {
    return parseAnalysisJsonFile(filePath);
  }

  const fd = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.alloc(1024);
    const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
    const firstNonWhitespace = buffer.subarray(0, bytesRead).toString('utf-8').match(/\S/)?.[0];
    if (firstNonWhitespace !== '{') {
      return null;
    }
  } finally {
    fs.closeSync(fd);
  }

  return parseAnalysisJsonFile(filePath);
}

function parseAnalysisJsonFile(filePath: string): AnalysisResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (error) {
    throw new Error(`Failed to parse AnalysisResult JSON from ${filePath}: ${error instanceof Error ? error.message : error}`);
  }
  return validateAnalysisResultJson(parsed, filePath);
}

function validateAnalysisResultJson(value: unknown, source: string): AnalysisResult {
  if (!value || typeof value !== 'object') {
    throw new Error(`Invalid AnalysisResult JSON in ${source}: root value must be an object`);
  }

  const record = value as Record<string, unknown>;
  const invalidFields: string[] = [];
  if (!record.binary || typeof record.binary !== 'object') {
    invalidFields.push('binary');
  }
  if (!Array.isArray(record.functions)) {
    invalidFields.push('functions');
  }
  if (!Array.isArray(record.strings)) {
    invalidFields.push('strings');
  }
  if (!Array.isArray(record.imports)) {
    invalidFields.push('imports');
  }

  if (invalidFields.length > 0) {
    throw new Error(`Invalid AnalysisResult JSON in ${source}: missing or invalid field(s): ${invalidFields.join(', ')}`);
  }

  return value as AnalysisResult;
}

function defaultBenchmarkOutputPath(kind: 'benchmark' | 'agent-benchmark'): string {
  const stamp = new Date().toISOString()
    .replace(/\.\d{3}Z$/, '')
    .replace(/[-:]/g, '')
    .replace('T', '-');
  if (kind === 'agent-benchmark') {
    return path.join('.arael', 'benchmark-results', 'agents', `agent-benchmark-${stamp}.html`);
  }
  return path.join('.arael', 'benchmark-results', `benchmark-${stamp}.html`);
}

function ensureOutputDirectory(outputPath: string): void {
  const dir = path.dirname(path.resolve(outputPath));
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function openFile(filePath: string): void {
  const resolved = path.resolve(filePath);
  const child = process.platform === 'win32'
    ? spawn('cmd', ['/c', 'start', '""', resolved], { detached: true, stdio: 'ignore' })
    : process.platform === 'darwin'
      ? spawn('open', [resolved], { detached: true, stdio: 'ignore' })
      : spawn('xdg-open', [resolved], { detached: true, stdio: 'ignore' });
  child.unref();
}

function printCacheEntries(entries: AnalysisCacheEntrySummary[]): void {
  if (entries.length === 0) {
    console.log('No cached analyses found');
    return;
  }

  console.log(`${'ID'.padEnd(6)} ${'SHA256'.padEnd(14)} ${'Binary'.padEnd(28)} ${'Funcs'.padStart(7)} ${'Strings'.padStart(8)} ${'Accessed'.padEnd(20)} Path`);
  console.log('-'.repeat(120));
  for (const entry of entries) {
    console.log([
      String(entry.id).padEnd(6),
      entry.fileHash.slice(0, 12).padEnd(14),
      truncateForConsole(entry.binaryFilename ?? path.basename(entry.filepath), 27).padEnd(28),
      String(entry.functionCount ?? '').padStart(7),
      String(entry.stringCount ?? '').padStart(8),
      truncateForConsole(entry.accessedAt, 19).padEnd(20),
      entry.filepath
    ].join(' '));
  }
}

function printCacheEntry(entry: AnalysisCacheEntry): void {
  console.log(`Cache row: ${entry.id}`);
  console.log(`Cache key: ${entry.cacheKey}`);
  console.log(`File hash: ${entry.fileHash}`);
  console.log(`File path: ${entry.filepath}`);
  console.log(`Created: ${entry.createdAt}`);
  console.log(`Accessed: ${entry.accessedAt}`);
  console.log(`Ghidra version: ${entry.ghidraVersion}`);
  console.log(`Arael version: ${entry.araelVersion}`);
  console.log(`Analysis ID: ${entry.analysisId ?? ''}`);
  console.log(`Timestamp: ${entry.timestamp ?? ''}`);
  console.log(`Binary: ${entry.binaryFilename ?? entry.analysis.binary.filename}`);
  console.log(`Format: ${entry.format ?? entry.analysis.binary.format}`);
  console.log(`Architecture: ${entry.architecture ?? entry.analysis.binary.architecture}`);
  console.log(`Functions: ${entry.functionCount ?? entry.analysis.functions.length}`);
  console.log(`Strings: ${entry.stringCount ?? entry.analysis.strings.length}`);
  console.log(`Imports: ${entry.importCount ?? entry.analysis.imports.length}`);
}

function truncateForConsole(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, Math.max(0, maxLength - 3))}...` : value;
}

program.parse();
