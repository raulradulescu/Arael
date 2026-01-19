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
import { extractIOCs, countIOCs } from '../analysis/ioc-extractor';
import { detectBehaviors, assessBehaviorRisk, classifyBinaryType } from '../analysis/behavior-detector';
import { mapToATTACK } from '../analysis/mitre-mapper';
import { assessImportRisk } from '../analysis/import-database';

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
  .description('Reverse engineering assistant using Ghidra')
  .version(version);

program
  .command('analyze <filepath>')
  .description('Perform full analysis of a binary')
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
  .description('Generate LLM-optimized analysis context (v2.6)')
  .option('-j, --json', 'Output as JSON')
  .option('--focus <area>', 'Focus area: security, functionality, all', 'all')
  .option('--include-code', 'Include pseudocode for key functions')
  .action(async (filepath: string, options: { json?: boolean; focus?: string; includeCode?: boolean }) => {
    try {
      await initConnection();
      logger.userMessage('Generating LLM context (analyzing binary)...');
      const result = await analyzeHandler({ filepath });

      // Extract data for analysis
      const importNames = result.imports.map(i => i.name);
      const stringValues = result.strings.map(s => s.value);

      // Run v2.6 analysis modules
      const behaviors = detectBehaviors(importNames, stringValues);
      const behaviorRisk = assessBehaviorRisk(behaviors);
      const classification = classifyBinaryType(behaviors);
      const iocs = extractIOCs(stringValues);
      const mitreMapping = mapToATTACK(behaviors);
      const importRisk = assessImportRisk(importNames);

      // Build LLM context
      const context = {
        summary: generateContextSummary(result, classification, behaviorRisk),
        classification: {
          type: classification.classification,
          malwareType: classification.malwareType,
          confidence: classification.confidence,
          reasoning: classification.reasoning,
        },
        binary: {
          filename: result.binary.filename,
          format: result.binary.format,
          architecture: result.binary.architecture,
          bits: result.binary.bits,
          size: result.binary.size,
          isPacked: result.binary.packing?.isPacked ?? false,
          entropy: result.binary.packing?.entropy?.overall,
        },
        behaviors: behaviors.map(b => ({
          id: b.id,
          category: b.category,
          description: b.description,
          riskLevel: b.riskLevel,
          evidence: b.evidence.slice(0, 5),
        })),
        riskAssessment: {
          overall: behaviorRisk.overallRisk,
          importRisk: importRisk.overallRisk,
          criticalBehaviors: behaviorRisk.criticalBehaviors,
        },
        iocs: {
          ips: iocs.ips,
          domains: iocs.domains,
          urls: iocs.urls,
          registryKeys: iocs.registryKeys,
          filePaths: iocs.filePaths.slice(0, 10),
        },
        mitreAttack: {
          tactics: mitreMapping.tactics,
          techniques: mitreMapping.techniques.slice(0, 10).map(t => ({
            id: t.id,
            name: t.name,
            confidence: t.confidence,
          })),
          summary: mitreMapping.summary,
        },
        keyFunctions: result.functions
          .filter(f => !f.isThunk && !f.isExternal)
          .sort((a, b) => b.size - a.size)
          .slice(0, 15)
          .map(f => ({
            name: f.name,
            address: f.address,
            size: f.size,
          })),
        suggestedAnalysis: generateSuggestedAnalysis(behaviors, iocs, classification),
        stats: {
          functions: result.functions.length,
          strings: result.strings.length,
          imports: result.imports.length,
          behaviorsDetected: behaviors.length,
          iocsFound: countIOCs(iocs),
          techniquesMatched: mitreMapping.techniques.length,
        },
      };

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
  .command('functions <filepath>')
  .description('List all functions in a binary')
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
  .description('Decompile a specific function')
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
  .description('Extract strings from binary')
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
  .description('List imported functions')
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
  .description('Dump raw bytes at address')
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
  .description('Disassemble a function')
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
  .description('List exported symbols')
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
  .description('Find cross-references')
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
  .description('Generate call graph')
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
  .description('Start interactive analysis shell')
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
  .description('Analyze multiple binaries matching a glob pattern')
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
  .command('report <filepath>')
  .description('Generate HTML analysis report')
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
  .description('Scan binary with YARA rules')
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
  .description('Cache management commands')
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
async function initConnection(): Promise<void> {
  const ghidraPath = process.env['GHIDRA_PATH'] ?? '';
  const bridgePortValue = process.env['GHIDRA_BRIDGE_PORT'];
  const bridgePort = bridgePortValue ? parseInt(bridgePortValue, 10) : undefined;
  const connection = getConnection({
    ghidraPath,
    bridgeHost: process.env['GHIDRA_BRIDGE_HOST'],
    bridgePort,
    pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH']
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

function generateHtmlReport(result: import('../output/schema').AnalysisResult, title?: string): string {
  const reportTitle = title ?? `Analysis Report: ${result.binary.filename}`;
  const timestamp = new Date().toISOString();

  // Get top functions by size
  const topFunctions = [...result.functions]
    .filter(f => !f.isThunk && !f.isExternal)
    .sort((a, b) => b.size - a.size)
    .slice(0, 20);

  // Get interesting strings
  const interestingStrings = result.strings.filter(s => {
    const v = s.value.toLowerCase();
    return v.includes('flag') || v.includes('password') || v.includes('key') ||
           v.includes('secret') || v.includes('http') || v.includes('error') ||
           s.value.match(/^[A-Z]{2,}[{_]/);
  }).slice(0, 50);

  // Capability summary from imports
  const capabilities = new Set<string>();
  for (const imp of result.imports) {
    if (imp.capabilities) {
      for (const cap of imp.capabilities) {
        capabilities.add(cap);
      }
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${reportTitle}</title>
  <style>
    :root {
      --bg: #1a1a2e;
      --bg-secondary: #16213e;
      --text: #eaeaea;
      --text-muted: #a0a0a0;
      --accent: #0f3460;
      --highlight: #e94560;
      --success: #4ecca3;
      --warning: #ffc107;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { color: var(--highlight); margin-bottom: 0.5rem; }
    h2 { color: var(--success); margin: 2rem 0 1rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }
    h3 { color: var(--text); margin: 1.5rem 0 0.5rem; }
    .meta { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
    .card {
      background: var(--bg-secondary);
      border-radius: 8px;
      padding: 1.5rem;
      border: 1px solid var(--accent);
    }
    .card h3 { margin-top: 0; color: var(--highlight); }
    .stat { font-size: 2rem; font-weight: bold; color: var(--success); }
    .stat-label { color: var(--text-muted); font-size: 0.85rem; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--accent); }
    th { background: var(--accent); color: var(--text); }
    tr:hover { background: rgba(255,255,255,0.05); }
    code {
      background: var(--accent);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-family: 'Consolas', monospace;
      font-size: 0.9rem;
    }
    pre {
      background: var(--bg);
      border: 1px solid var(--accent);
      border-radius: 8px;
      padding: 1rem;
      overflow-x: auto;
      font-family: 'Consolas', monospace;
      font-size: 0.85rem;
    }
    .tag {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.8rem;
      margin: 0.2rem;
    }
    .tag-network { background: #3498db; }
    .tag-crypto { background: #9b59b6; }
    .tag-file { background: #27ae60; }
    .tag-process { background: #e74c3c; }
    .tag-registry { background: #f39c12; }
    .tag-debug { background: #c0392b; }
    .packed { color: var(--warning); }
    .clean { color: var(--success); }
  </style>
</head>
<body>
  <div class="container">
    <h1>${reportTitle}</h1>
    <p class="meta">Generated by Arael v2.4.0 on ${timestamp}</p>

    <h2>Overview</h2>
    <div class="grid">
      <div class="card">
        <h3>Binary Info</h3>
        <p><strong>File:</strong> ${result.binary.filename}</p>
        <p><strong>Format:</strong> ${result.binary.format} ${result.binary.architecture} (${result.binary.bits}-bit)</p>
        <p><strong>Size:</strong> ${(result.binary.size / 1024).toFixed(2)} KB</p>
        <p><strong>Entry:</strong> <code>${result.binary.entryPoint}</code></p>
      </div>
      <div class="card">
        <h3>Statistics</h3>
        <p><span class="stat">${result.functions.length}</span> <span class="stat-label">Functions</span></p>
        <p><span class="stat">${result.strings.length}</span> <span class="stat-label">Strings</span></p>
        <p><span class="stat">${result.imports.length}</span> <span class="stat-label">Imports</span></p>
      </div>
      <div class="card">
        <h3>Hashes</h3>
        <p><strong>MD5:</strong> <code>${result.binary.hashes.md5}</code></p>
        <p><strong>SHA1:</strong> <code>${result.binary.hashes.sha1}</code></p>
        <p><strong>SHA256:</strong> <code style="font-size:0.7rem">${result.binary.hashes.sha256}</code></p>
      </div>
      <div class="card">
        <h3>Packing Status</h3>
        ${result.binary.packing?.isPacked
          ? `<p class="packed">⚠️ PACKED</p><p>Packers: ${result.binary.packing.packers.map(p => p.name).join(', ')}</p>`
          : `<p class="clean">✓ Not Packed</p>`}
        <p><strong>Entropy:</strong> ${result.binary.packing?.entropy?.overall?.toFixed(2) ?? 'N/A'}</p>
      </div>
    </div>

    ${capabilities.size > 0 ? `
    <h2>Capabilities Detected</h2>
    <div class="card">
      ${Array.from(capabilities).map(c => `<span class="tag tag-${c.toLowerCase()}">${c}</span>`).join('')}
    </div>
    ` : ''}

    <h2>Top Functions (by size)</h2>
    <table>
      <tr><th>Name</th><th>Address</th><th>Size</th></tr>
      ${topFunctions.map(f => `<tr><td>${f.name}</td><td><code>${f.address}</code></td><td>${f.size}</td></tr>`).join('')}
    </table>

    ${interestingStrings.length > 0 ? `
    <h2>Interesting Strings</h2>
    <table>
      <tr><th>Address</th><th>Value</th></tr>
      ${interestingStrings.map(s => `<tr><td><code>${s.address}</code></td><td>${escapeHtml(s.value.substring(0, 100))}</td></tr>`).join('')}
    </table>
    ` : ''}

    <h2>Imports</h2>
    <table>
      <tr><th>Name</th><th>Library</th><th>Capabilities</th></tr>
      ${result.imports.slice(0, 50).map(i => `<tr>
        <td>${i.name}</td>
        <td>${i.library ?? ''}</td>
        <td>${(i.capabilities ?? []).map(c => `<span class="tag tag-${c.toLowerCase()}">${c}</span>`).join('')}</td>
      </tr>`).join('')}
      ${result.imports.length > 50 ? `<tr><td colspan="3">... and ${result.imports.length - 50} more</td></tr>` : ''}
    </table>

    <footer style="margin-top:3rem; text-align:center; color:var(--text-muted);">
      <p>Generated by <a href="https://github.com/raulradulescu/arael" style="color:var(--highlight);">Arael</a></p>
    </footer>
  </div>
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

function generateContextSummary(
  result: import('../output/schema').AnalysisResult,
  classification: { classification: string; malwareType?: string; confidence: number },
  risk: { overallRisk: string; criticalBehaviors: string[] }
): string {
  const format = `${result.binary.format} ${result.binary.architecture} ${result.binary.bits}-bit`;
  const packed = result.binary.packing?.isPacked ? 'packed ' : '';

  if (classification.classification === 'malware') {
    const type = classification.malwareType ?? 'malicious';
    return `${packed}${format} executable classified as ${type} with ${(classification.confidence * 100).toFixed(0)}% confidence. ${risk.criticalBehaviors.length > 0 ? `Critical behaviors: ${risk.criticalBehaviors.slice(0, 2).join(', ')}.` : ''}`;
  } else if (classification.classification === 'suspicious') {
    return `${packed}${format} executable with suspicious characteristics. Risk level: ${risk.overallRisk}. Requires further analysis to confirm malicious intent.`;
  } else {
    return `${packed}${format} executable with ${result.functions.length} functions and ${result.imports.length} imports. No obvious malicious indicators detected.`;
  }
}

function generateSuggestedAnalysis(
  behaviors: Array<{ id: string; category: string; evidence: string[] }>,
  iocs: { urls: string[]; ips: string[]; registryKeys: string[] },
  classification: { classification: string; malwareType?: string }
): string[] {
  const suggestions: string[] = [];

  if (classification.classification === 'malware' || classification.classification === 'suspicious') {
    suggestions.push('Examine network-related functions for C2 communication patterns');
  }

  if (behaviors.some(b => b.id === 'process_injection')) {
    suggestions.push('Analyze injection target selection and payload in WriteProcessMemory calls');
  }

  if (behaviors.some(b => b.id === 'persistence_registry')) {
    suggestions.push('Check registry key values for persistence payload paths');
  }

  if (iocs.urls.length > 0) {
    suggestions.push(`Investigate URLs: ${iocs.urls.slice(0, 2).join(', ')}`);
  }

  if (behaviors.some(b => b.id === 'credential_theft')) {
    suggestions.push('Examine credential access functions for targeted applications');
  }

  if (behaviors.some(b => b.id === 'file_encryption')) {
    suggestions.push('Analyze encryption routine and look for ransom note generation');
  }

  if (behaviors.some(b => b.category === 'defense_evasion')) {
    suggestions.push('Review anti-analysis checks for sandbox/VM detection logic');
  }

  if (suggestions.length === 0) {
    suggestions.push('Review main entry point and initialization routines');
    suggestions.push('Examine string references for configuration data');
  }

  return suggestions.slice(0, 6);
}

program.parse();
