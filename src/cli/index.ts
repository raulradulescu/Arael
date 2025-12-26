#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { getConnection } from '../ghidra/connection';
import { analyzeHandler } from '../mcp/handlers/analyze';
import { decompileHandler } from '../mcp/handlers/decompile';
import { functionsHandler } from '../mcp/handlers/functions';
import { stringsHandler } from '../mcp/handlers/strings';
import { importsHandler } from '../mcp/handlers/imports';
import { hexdumpHandler } from '../mcp/handlers/hexdump';
import { getCache } from '../cache/store';
import { logger } from '../utils/logger';
import { loadEnvFromFile } from '../utils/env';

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

program.parse();
