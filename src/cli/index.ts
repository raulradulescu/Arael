#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
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
import { getCache } from '../cache/store';
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
  .option('--format <format>', 'Report format: json|jsonl|csv|markdown|latex', 'json')
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
      const runs = parsePositiveInt(options.runs ?? '1', '--runs');
      const timeoutSeconds = options.timeout ? parsePositiveInt(options.timeout, '--timeout') : undefined;

      await initConnection(timeoutSeconds ? timeoutSeconds * 1000 : undefined);
      const result = await runBenchmark({
        target,
        manifestPath: options.manifest,
        outputPath: options.output,
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

      const rendered = formatBenchmarkResult(result, format);
      if (options.output) {
        fs.writeFileSync(options.output, rendered);
        console.log(`Benchmark report written to: ${options.output}`);
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
  .option('--format <format>', 'Report format: json|jsonl|csv|markdown', 'markdown')
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
  .option('--gemini-bin <path>', 'Gemini executable', 'gemini')
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
    geminiBin?: string;
    ollamaHost?: string;
    araelServer?: string;
    prompt?: string;
    dryRun?: boolean;
  }) => {
    try {
      const format = parseAgentBenchmarkFormat(options.format ?? 'markdown');
      const timeoutSeconds = parsePositiveInt(options.timeout ?? '1800', '--timeout');
      const maxChallenges = options.maxChallenges
        ? parsePositiveInt(options.maxChallenges, '--max-challenges')
        : undefined;
      const runs = parsePositiveInt(options.runs ?? '1', '--runs');
      const concurrency = parsePositiveInt(options.concurrency ?? '1', '--concurrency');

      const result = await runAgentBenchmark({
        target,
        outputPath: options.output,
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
        geminiBin: options.geminiBin ?? 'gemini',
        ollamaUrl: options.ollamaHost ?? 'http://localhost:11434',
        araelServerPath: options.araelServer,
        promptPath: options.prompt,
        dryRun: Boolean(options.dryRun)
      });

      const rendered = formatAgentBenchmarkResult(result, format);
      if (options.output) {
        fs.writeFileSync(options.output, rendered);
        console.log(`Agent benchmark report written to: ${options.output}`);
      } else {
        process.stdout.write(rendered);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

program
  .command('report <filepath>')
  .description('Generate a standalone HTML report with stats, top functions, and strings')
  .option('-o, --output <file>', 'Output HTML file', 'report.html')
  .option('--title <title>', 'Report title')
  .action(async (filepath: string, options: { output?: string; title?: string }) => {
    try {
      await initConnection();
      logger.userMessage('Analyzing binary...');
      const result = await analyzeHandler({ filepath });

      const html = generateHtmlReport(result, options.title);
      const outputPath = options.output ?? 'report.html';
      fs.writeFileSync(outputPath, html);

      console.log(`Report generated: ${outputPath}`);
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
  .action((options: { stats?: boolean; clear?: boolean }) => {
    const cache = getCache();

    if (options.clear) {
      const count = cache.invalidateAll();
      console.log(`Cleared ${count} cached analyses`);
      return;
    }

    if (options.stats) {
      const stats = cache.getStats();
      console.log(`Cache entries: ${stats.count}`);
      console.log(`Cache size: ${(stats.sizeBytes / 1024).toFixed(2)} KB`);
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
  if (value === 'json' || value === 'jsonl' || value === 'csv' || value === 'markdown' || value === 'latex') {
    return value;
  }
  throw new Error(`Invalid benchmark format: ${value}`);
}

function parseAgentBenchmarkFormat(value: string): AgentBenchmarkFormat {
  if (value === 'json' || value === 'jsonl' || value === 'csv' || value === 'markdown') {
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

function generateHtmlReport(result: import('../output/schema').AnalysisResult, title?: string): string {
  const reportTitle = title ?? `Analysis Report: ${result.binary.filename}`;
  const timestamp = new Date().toISOString();
  const formattedDate = new Date().toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short'
  });

  // Get top functions by size
  const topFunctions = [...result.functions]
    .filter(f => !f.isThunk && !f.isExternal)
    .sort((a, b) => b.size - a.size)
    .slice(0, 20);

  // Get interesting strings categorized
  const interestingStrings = result.strings.filter(s => {
    const v = s.value.toLowerCase();
    return v.includes('flag') || v.includes('password') || v.includes('key') ||
           v.includes('secret') || v.includes('http') || v.includes('error') ||
           v.includes('api') || v.includes('token') || v.includes('credential') ||
           s.value.match(/^[A-Z]{2,}[{_]/) ||
           s.value.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
  }).slice(0, 50);

  // Capability summary from imports
  const capabilities = new Set<string>();
  const capabilityCounts: Record<string, number> = {};
  for (const imp of result.imports) {
    if (imp.capabilities) {
      for (const cap of imp.capabilities) {
        capabilities.add(cap);
        capabilityCounts[cap] = (capabilityCounts[cap] || 0) + 1;
      }
    }
  }

  // Risk level determination
  const highRiskCaps = ['Injection', 'AntiDebug', 'Credential', 'Keylogger'];
  const mediumRiskCaps = ['Network', 'Process', 'Registry', 'Crypto'];
  const hasHighRisk = highRiskCaps.some(c => capabilities.has(c));
  const hasMediumRisk = mediumRiskCaps.some(c => capabilities.has(c));
  const riskLevel = hasHighRisk ? 'high' : hasMediumRisk ? 'medium' : 'low';

  // Section entropy analysis
  const sections = result.sections ?? [];
  const sectionPermissions = (section: import('../output/schema').SectionInfo): string =>
    `${section.permissions.read ? 'r' : '-'}${section.permissions.write ? 'w' : '-'}${section.permissions.execute ? 'x' : '-'}`;
  const suspiciousSections = sections.filter(s =>
    (s.entropy && s.entropy > 7.0) ||
    (s.permissions.write && s.permissions.execute)
  );

  // Exports count
  const exportsCount = result.exports?.length ?? 0;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${reportTitle}</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --accent-hover: #79b8ff;
      --danger: #f85149;
      --warning: #d29922;
      --success: #3fb950;
      --purple: #a371f7;
      --pink: #db61a2;
      --gradient-start: #58a6ff;
      --gradient-end: #a371f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }
    .header {
      background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
      border-bottom: 1px solid var(--border);
      padding: 2rem;
      margin-bottom: 2rem;
    }
    .header-content {
      max-width: 1400px;
      margin: 0 auto;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .header h1 {
      font-size: 1.75rem;
      font-weight: 600;
      background: linear-gradient(90deg, var(--gradient-start), var(--gradient-end));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .header-meta {
      display: flex;
      gap: 1.5rem;
      color: var(--text-muted);
      font-size: 0.875rem;
    }
    .header-meta span { display: flex; align-items: center; gap: 0.5rem; }
    .risk-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.375rem 0.75rem;
      border-radius: 2rem;
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .risk-high { background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid var(--danger); }
    .risk-medium { background: rgba(210, 153, 34, 0.15); color: var(--warning); border: 1px solid var(--warning); }
    .risk-low { background: rgba(63, 185, 80, 0.15); color: var(--success); border: 1px solid var(--success); }
    .container { max-width: 1400px; margin: 0 auto; padding: 0 2rem 2rem; }
    .section { margin-bottom: 2rem; }
    .section-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    .section-header h2 {
      font-size: 1.25rem;
      font-weight: 600;
      color: var(--text);
    }
    .section-icon {
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg-tertiary);
      border-radius: 6px;
      font-size: 0.875rem;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
    .grid-2 { grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); }
    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .card:hover {
      border-color: var(--accent);
      box-shadow: 0 0 0 1px var(--accent);
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }
    .card-title {
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .card-value {
      font-size: 2rem;
      font-weight: 700;
      color: var(--accent);
      line-height: 1;
    }
    .card-label { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem; }
    .info-row {
      display: flex;
      justify-content: space-between;
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border);
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: var(--text-muted); font-size: 0.875rem; }
    .info-value { font-weight: 500; font-family: 'SF Mono', Consolas, monospace; font-size: 0.875rem; }
    .hash-value {
      font-family: 'SF Mono', Consolas, monospace;
      font-size: 0.75rem;
      word-break: break-all;
      background: var(--bg-tertiary);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }
    th {
      text-align: left;
      padding: 0.75rem 1rem;
      background: var(--bg-tertiary);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    tr:hover td { background: var(--bg-tertiary); }
    .table-wrapper {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .table-scroll { max-height: 500px; overflow-y: auto; }
    code {
      font-family: 'SF Mono', Consolas, monospace;
      font-size: 0.8rem;
      background: var(--bg-tertiary);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      color: var(--accent);
    }
    .tag {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      margin: 0.125rem;
      text-transform: uppercase;
      letter-spacing: 0.025em;
    }
    .tag-network { background: rgba(88, 166, 255, 0.15); color: #58a6ff; }
    .tag-crypto { background: rgba(163, 113, 247, 0.15); color: #a371f7; }
    .tag-file, .tag-fileio { background: rgba(63, 185, 80, 0.15); color: #3fb950; }
    .tag-process { background: rgba(248, 81, 73, 0.15); color: #f85149; }
    .tag-registry { background: rgba(210, 153, 34, 0.15); color: #d29922; }
    .tag-antidebug, .tag-debug { background: rgba(219, 97, 162, 0.15); color: #db61a2; }
    .tag-injection { background: rgba(248, 81, 73, 0.2); color: #ff7b72; }
    .tag-memory { background: rgba(121, 184, 255, 0.15); color: #79b8ff; }
    .tag-system { background: rgba(139, 148, 158, 0.15); color: #8b949e; }
    .tag-credential { background: rgba(248, 81, 73, 0.2); color: #ff7b72; }
    .packed-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.625rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .packed-yes { background: rgba(210, 153, 34, 0.15); color: var(--warning); }
    .packed-no { background: rgba(63, 185, 80, 0.15); color: var(--success); }
    .entropy-bar {
      width: 100%;
      height: 6px;
      background: var(--bg-tertiary);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 0.5rem;
    }
    .entropy-fill {
      height: 100%;
      border-radius: 3px;
      transition: width 0.3s ease;
    }
    .entropy-low { background: var(--success); }
    .entropy-medium { background: var(--warning); }
    .entropy-high { background: var(--danger); }
    .capability-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .capability-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--bg-tertiary);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.8rem;
    }
    .capability-count {
      background: var(--bg-primary);
      padding: 0.125rem 0.375rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
    }
    .section-table { margin-top: 1rem; }
    .suspicious { color: var(--warning); }
    footer {
      margin-top: 3rem;
      padding: 2rem;
      text-align: center;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.875rem;
    }
    footer a { color: var(--accent); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
    @media (max-width: 768px) {
      .header-content { flex-direction: column; }
      .header-meta { flex-direction: column; gap: 0.5rem; }
      .grid { grid-template-columns: 1fr; }
      .container { padding: 0 1rem 1rem; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="header-content">
      <div>
        <h1>${reportTitle}</h1>
        <div class="header-meta">
          <span>${formattedDate}</span>
          <span>${result.binary.format} ${result.binary.architecture} (${result.binary.bits}-bit)</span>
          <span>${(result.binary.size / 1024).toFixed(1)} KB</span>
        </div>
      </div>
      <span class="risk-badge risk-${riskLevel}">${riskLevel === 'high' ? '! High Risk' : riskLevel === 'medium' ? '~ Medium Risk' : '+ Low Risk'}</span>
    </div>
  </div>

  <div class="container">
    <div class="section">
      <div class="section-header">
        <span class="section-icon">i</span>
        <h2>Overview</h2>
      </div>
      <div class="grid">
        <div class="card">
          <div class="card-header"><span class="card-title">Functions</span></div>
          <div class="card-value">${result.functions.length.toLocaleString()}</div>
          <div class="card-label">Total analyzed</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Strings</span></div>
          <div class="card-value">${result.strings.length.toLocaleString()}</div>
          <div class="card-label">Extracted</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Imports</span></div>
          <div class="card-value">${result.imports.length.toLocaleString()}</div>
          <div class="card-label">External functions</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Exports</span></div>
          <div class="card-value">${exportsCount.toLocaleString()}</div>
          <div class="card-label">Public symbols</div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <span class="section-icon">#</span>
        <h2>Binary Details</h2>
      </div>
      <div class="grid grid-2">
        <div class="card">
          <div class="card-header"><span class="card-title">File Information</span></div>
          <div class="info-row"><span class="info-label">Filename</span><span class="info-value">${result.binary.filename}</span></div>
          <div class="info-row"><span class="info-label">Format</span><span class="info-value">${result.binary.format}</span></div>
          <div class="info-row"><span class="info-label">Architecture</span><span class="info-value">${result.binary.architecture} (${result.binary.bits}-bit)</span></div>
          <div class="info-row"><span class="info-label">Entry Point</span><code>${result.binary.entryPoint}</code></div>
          <div class="info-row"><span class="info-label">Size</span><span class="info-value">${(result.binary.size / 1024).toFixed(2)} KB</span></div>
        </div>
        <div class="card">
          <div class="card-header">
            <span class="card-title">Packing Analysis</span>
            ${result.binary.packing?.isPacked
              ? `<span class="packed-badge packed-yes">! Packed</span>`
              : `<span class="packed-badge packed-no">+ Clean</span>`}
          </div>
          ${result.binary.packing?.isPacked
            ? `<div class="info-row"><span class="info-label">Packers</span><span class="info-value">${result.binary.packing.packers.map(p => p.name).join(', ')}</span></div>`
            : ''}
          <div class="info-row">
            <span class="info-label">Overall Entropy</span>
            <span class="info-value">${result.binary.packing?.entropy?.overall?.toFixed(2) ?? 'N/A'}</span>
          </div>
          ${result.binary.packing?.entropy?.overall ? `
          <div class="entropy-bar">
            <div class="entropy-fill ${result.binary.packing.entropy.overall > 7.5 ? 'entropy-high' : result.binary.packing.entropy.overall > 6.5 ? 'entropy-medium' : 'entropy-low'}"
                 style="width: ${Math.min(100, (result.binary.packing.entropy.overall / 8) * 100)}%"></div>
          </div>` : ''}
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <span class="section-icon">@</span>
        <h2>Hashes</h2>
      </div>
      <div class="card">
        <div class="info-row"><span class="info-label">MD5</span><span class="hash-value">${result.binary.hashes.md5}</span></div>
        <div class="info-row"><span class="info-label">SHA1</span><span class="hash-value">${result.binary.hashes.sha1}</span></div>
        <div class="info-row"><span class="info-label">SHA256</span><span class="hash-value">${result.binary.hashes.sha256}</span></div>
      </div>
    </div>

    ${capabilities.size > 0 ? `
    <div class="section">
      <div class="section-header">
        <span class="section-icon">!</span>
        <h2>Detected Capabilities</h2>
      </div>
      <div class="card">
        <div class="capability-grid">
          ${Array.from(capabilities).sort().map(c => `
            <div class="capability-item">
              <span class="tag tag-${c.toLowerCase()}">${c}</span>
              <span class="capability-count">${capabilityCounts[c]}</span>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
    ` : ''}

    ${sections.length > 0 ? `
    <div class="section">
      <div class="section-header">
        <span class="section-icon">[</span>
        <h2>Sections ${suspiciousSections.length > 0 ? `<span class="suspicious">(${suspiciousSections.length} suspicious)</span>` : ''}</h2>
      </div>
      <div class="table-wrapper">
        <table>
          <thead><tr><th>Name</th><th>Virtual Address</th><th>Size</th><th>Permissions</th><th>Entropy</th></tr></thead>
          <tbody>
            ${sections.slice(0, 20).map(s => `
              <tr${(s.entropy && s.entropy > 7.0) || (s.permissions.write && s.permissions.execute) ? ' class="suspicious"' : ''}>
                <td><code>${s.name}</code></td>
                <td><code>${s.start ?? '-'}</code></td>
                <td>${s.size?.toLocaleString() ?? '-'}</td>
                <td><code>${sectionPermissions(s)}</code></td>
                <td>${s.entropy?.toFixed(2) ?? '-'}${s.entropy && s.entropy > 7.0 ? ' <span class="suspicious">!</span>' : ''}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
    ` : ''}

    <div class="section">
      <div class="section-header">
        <span class="section-icon">f</span>
        <h2>Top Functions</h2>
      </div>
      <div class="table-wrapper">
        <div class="table-scroll">
          <table>
            <thead><tr><th>Name</th><th>Address</th><th>Size</th></tr></thead>
            <tbody>
              ${topFunctions.map(f => `
                <tr>
                  <td>${f.name}</td>
                  <td><code>${f.address}</code></td>
                  <td>${f.size.toLocaleString()} bytes</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    ${interestingStrings.length > 0 ? `
    <div class="section">
      <div class="section-header">
        <span class="section-icon">"</span>
        <h2>Interesting Strings</h2>
      </div>
      <div class="table-wrapper">
        <div class="table-scroll">
          <table>
            <thead><tr><th>Address</th><th>Value</th></tr></thead>
            <tbody>
              ${interestingStrings.map(s => `
                <tr>
                  <td><code>${s.address}</code></td>
                  <td>${escapeHtml(s.value.substring(0, 120))}${s.value.length > 120 ? '...' : ''}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    ` : ''}

    <div class="section">
      <div class="section-header">
        <span class="section-icon">&lt;</span>
        <h2>Imports</h2>
      </div>
      <div class="table-wrapper">
        <div class="table-scroll">
          <table>
            <thead><tr><th>Function</th><th>Library</th><th>Capabilities</th></tr></thead>
            <tbody>
              ${result.imports.slice(0, 100).map(i => `
                <tr>
                  <td>${i.name}</td>
                  <td><code>${i.library ?? '-'}</code></td>
                  <td>${(i.capabilities ?? []).map(c => `<span class="tag tag-${c.toLowerCase()}">${c}</span>`).join('')}</td>
                </tr>
              `).join('')}
              ${result.imports.length > 100 ? `<tr><td colspan="3" style="text-align:center;color:var(--text-muted);">... and ${result.imports.length - 100} more imports</td></tr>` : ''}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <footer>
    <p>Generated by <a href="https://github.com/raulradulescu/arael">Arael v2.6.1</a> - Reverse Engineering Assistant</p>
    <p style="margin-top:0.5rem;font-size:0.75rem;">Timestamp: ${timestamp}</p>
  </footer>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

program.parse();
