import * as readline from 'readline';
import * as path from 'path';
import { getConnection } from '../ghidra/connection';
import { analyzeHandler } from '../mcp/handlers/analyze';
import { decompileHandler } from '../mcp/handlers/decompile';
import { disassembleHandler } from '../mcp/handlers/disassemble';
import { functionsHandler } from '../mcp/handlers/functions';
import { stringsHandler } from '../mcp/handlers/strings';
import { importsHandler } from '../mcp/handlers/imports';
import { exportsHandler } from '../mcp/handlers/exports';
import { xrefsHandler } from '../mcp/handlers/xrefs';
import { callgraphHandler } from '../mcp/handlers/callgraph';
import { hexdumpHandler } from '../mcp/handlers/hexdump';
import { AnalysisResult } from '../output/schema';
// Removed unused logger import

interface ShellState {
  filepath: string;
  analysis: AnalysisResult | null;
  connected: boolean;
}

const HELP_TEXT = `
Arael Interactive Shell - Commands:

  Binary Analysis:
    analyze [--force]      Re-analyze the current binary
    info                   Show binary metadata
    functions [pattern]    List functions (optional regex filter)
    strings [pattern]      Search strings (optional filter)
    imports                List imports with capabilities
    exports                List exports

  Function Analysis:
    decompile <func>       Decompile function (name or address)
    disasm <func>          Disassemble function
    xrefs <addr>           Show cross-references to/from address

  Visualization:
    callgraph [func]       Generate call graph (from func or all)
    hexdump <addr> [len]   Dump bytes at address

  Navigation:
    load <filepath>        Load a different binary
    help                   Show this help
    exit / quit            Exit the shell

  Tips:
    - Function names and addresses both work (e.g., 'main' or '0x401000')
    - Patterns use regex (e.g., 'functions crypto|aes')
`;

export async function startShell(filepath: string): Promise<void> {
  const state: ShellState = {
    filepath: path.resolve(filepath),
    analysis: null,
    connected: false
  };

  // Initialize connection
  console.log('Initializing Ghidra connection...');
  try {
    const ghidraPath = process.env['GHIDRA_PATH'] ?? '';
    const connection = getConnection({
      ghidraPath,
      bridgeHost: process.env['GHIDRA_BRIDGE_HOST'],
      bridgePort: process.env['GHIDRA_BRIDGE_PORT'] ? parseInt(process.env['GHIDRA_BRIDGE_PORT'], 10) : undefined,
      pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH']
    });
    await connection.connect();
    state.connected = true;
    console.log('Connected to Ghidra.');
  } catch (error) {
    console.error(`Failed to connect: ${error instanceof Error ? error.message : error}`);
    return;
  }

  // Initial analysis
  console.log(`\nAnalyzing ${path.basename(state.filepath)}...`);
  try {
    state.analysis = await analyzeHandler({ filepath: state.filepath });
    console.log(`Loaded: ${state.analysis.binary.format} ${state.analysis.binary.architecture}`);
    console.log(`Functions: ${state.analysis.functions.length} | Strings: ${state.analysis.strings.length}`);
  } catch (error) {
    console.error(`Analysis failed: ${error instanceof Error ? error.message : error}`);
    return;
  }

  console.log('\nType "help" for commands.\n');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `arael:${path.basename(state.filepath)}> `
  });

  rl.prompt();

  rl.on('line', async (line) => {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      return;
    }

    const parts = input.split(/\s+/);
    const cmd = parts[0] ?? '';
    const args = parts.slice(1);
    const arg = args.join(' ');

    try {
      await executeCommand(cmd.toLowerCase(), arg, state);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
    }

    if (cmd.toLowerCase() !== 'exit' && cmd.toLowerCase() !== 'quit') {
      rl.prompt();
    }
  });

  rl.on('close', () => {
    console.log('\nGoodbye!');
    process.exit(0);
  });
}

async function executeCommand(cmd: string, arg: string, state: ShellState): Promise<void> {
  switch (cmd) {
    case 'help':
    case '?':
      console.log(HELP_TEXT);
      break;

    case 'exit':
    case 'quit':
    case 'q':
      console.log('Goodbye!');
      process.exit(0);
      break;

    case 'info':
      if (!state.analysis) {
        console.log('No binary loaded.');
        break;
      }
      console.log(`File: ${state.analysis.binary.filename}`);
      console.log(`Path: ${state.analysis.binary.filepath}`);
      console.log(`Format: ${state.analysis.binary.format} ${state.analysis.binary.architecture} (${state.analysis.binary.bits}-bit)`);
      console.log(`Size: ${state.analysis.binary.size} bytes`);
      console.log(`Entry: ${state.analysis.binary.entryPoint}`);
      console.log(`SHA256: ${state.analysis.binary.hashes.sha256}`);
      if (state.analysis.binary.packing?.isPacked) {
        console.log(`Packed: ${state.analysis.binary.packing.packers.map(p => p.name).join(', ')}`);
      }
      break;

    case 'analyze':
      console.log('Re-analyzing...');
      state.analysis = await analyzeHandler({
        filepath: state.filepath,
        force: arg.includes('--force')
      });
      console.log(`Done. Functions: ${state.analysis.functions.length}`);
      break;

    case 'functions':
    case 'funcs':
    case 'fn':
      const funcs = await functionsHandler({
        filepath: state.filepath,
        filter: arg ? { namePattern: arg } : undefined
      });
      if (funcs.length === 0) {
        console.log('No functions found.');
      } else {
        console.log(`\n${'Name'.padEnd(40)} ${'Address'.padEnd(12)} Size`);
        console.log('-'.repeat(60));
        for (const f of funcs.slice(0, 50)) {
          console.log(`${f.name.substring(0, 39).padEnd(40)} ${f.address.padEnd(12)} ${f.size}`);
        }
        if (funcs.length > 50) {
          console.log(`... and ${funcs.length - 50} more`);
        }
      }
      break;

    case 'strings':
    case 'str':
      const strings = await stringsHandler({ filepath: state.filepath, minLength: 4 });
      const filtered = arg
        ? strings.filter(s => new RegExp(arg, 'i').test(s.value))
        : strings;
      if (filtered.length === 0) {
        console.log('No strings found.');
      } else {
        console.log(`\n${'Address'.padEnd(20)} Value`);
        console.log('-'.repeat(60));
        for (const s of filtered.slice(0, 50)) {
          const display = s.value.length > 50 ? s.value.substring(0, 47) + '...' : s.value;
          console.log(`${s.address.padEnd(20)} ${display}`);
        }
        if (filtered.length > 50) {
          console.log(`... and ${filtered.length - 50} more`);
        }
      }
      break;

    case 'imports':
    case 'imp':
      const imports = await importsHandler({ filepath: state.filepath });
      if (imports.imports.length === 0) {
        console.log('No imports found.');
      } else {
        console.log(`\n${'Name'.padEnd(35)} ${'Library'.padEnd(20)} Capabilities`);
        console.log('-'.repeat(70));
        for (const imp of imports.imports.slice(0, 50)) {
          const caps = imp.capabilities?.join(', ') ?? '';
          console.log(`${imp.name.substring(0, 34).padEnd(35)} ${(imp.library ?? '').substring(0, 19).padEnd(20)} ${caps}`);
        }
        if (imports.imports.length > 50) {
          console.log(`... and ${imports.imports.length - 50} more`);
        }
        // Compute capabilities summary
        const capabilityCounts = new Map<string, number>();
        for (const imp of imports.imports) {
          for (const cap of imp.capabilities ?? []) {
            capabilityCounts.set(cap, (capabilityCounts.get(cap) ?? 0) + 1);
          }
        }
        if (capabilityCounts.size > 0) {
          console.log(`\nCapabilities: ${Array.from(capabilityCounts.entries()).map(([k, v]) => `${k}(${v})`).join(', ')}`);
        }
      }
      break;

    case 'exports':
    case 'exp':
      const exportsResult = await exportsHandler({ filepath: state.filepath });
      if (exportsResult.exports.length === 0) {
        console.log('No exports found.');
      } else {
        console.log(`\n${'Name'.padEnd(40)} Address`);
        console.log('-'.repeat(55));
        for (const exp of exportsResult.exports.slice(0, 50)) {
          console.log(`${exp.name.substring(0, 39).padEnd(40)} ${exp.address}`);
        }
        if (exportsResult.exports.length > 50) {
          console.log(`... and ${exportsResult.exports.length - 50} more`);
        }
      }
      break;

    case 'decompile':
    case 'dec':
    case 'd':
      if (!arg) {
        console.log('Usage: decompile <function_name_or_address>');
        break;
      }
      const decompiled = await decompileHandler({ filepath: state.filepath, function: arg });
      if (decompiled.pseudocode) {
        console.log(decompiled.pseudocode);
      } else {
        console.log(decompiled.error ?? 'No decompilation available.');
      }
      break;

    case 'disasm':
    case 'dis':
      if (!arg) {
        console.log('Usage: disasm <function_name_or_address>');
        break;
      }
      const disasm = await disassembleHandler({ filepath: state.filepath, function: arg });
      if (disasm.instructions && disasm.instructions.length > 0) {
        for (const inst of disasm.instructions) {
          console.log(`${inst.address}  ${(inst.bytes ?? '').padEnd(24)} ${inst.mnemonic} ${inst.operands}`);
        }
      } else {
        console.log(disasm.error ?? 'No disassembly available.');
      }
      break;

    case 'xrefs':
    case 'x':
      if (!arg) {
        console.log('Usage: xrefs <address_or_function>');
        break;
      }
      const xrefs = await xrefsHandler({ filepath: state.filepath, address: arg });
      if (xrefs.references.length === 0) {
        console.log('No cross-references found.');
      } else {
        console.log(`\nCross-references for ${arg}:`);
        console.log(`${'From'.padEnd(15)} ${'To'.padEnd(15)} Type`);
        console.log('-'.repeat(45));
        for (const ref of xrefs.references.slice(0, 30)) {
          console.log(`${(ref.from ?? '').padEnd(15)} ${(ref.to ?? '').padEnd(15)} ${ref.type}`);
        }
        if (xrefs.references.length > 30) {
          console.log(`... and ${xrefs.references.length - 30} more`);
        }
      }
      break;

    case 'callgraph':
    case 'cg':
      const cgArgs = arg.split(/\s+/);
      const rootFunc = cgArgs[0] || undefined;
      const cgFormat = cgArgs[1] || 'mermaid';
      const callgraph = await callgraphHandler({
        filepath: state.filepath,
        rootFunction: rootFunc,
        format: cgFormat as 'json' | 'dot' | 'mermaid',
        maxDepth: 5
      });
      console.log(callgraph.output ?? callgraph.graphData ?? 'No graph generated.');
      break;

    case 'hexdump':
    case 'hex':
      const hexArgs = arg.split(/\s+/);
      if (!hexArgs[0]) {
        console.log('Usage: hexdump <address> [length]');
        break;
      }
      const hexResult = await hexdumpHandler({
        filepath: state.filepath,
        start: hexArgs[0],
        length: hexArgs[1] ? parseInt(hexArgs[1], 10) : 256
      });
      console.log(hexResult.formatted);
      break;

    case 'load':
      if (!arg) {
        console.log('Usage: load <filepath>');
        break;
      }
      console.log(`Loading ${arg}...`);
      state.filepath = path.resolve(arg);
      state.analysis = await analyzeHandler({ filepath: state.filepath });
      console.log(`Loaded: ${state.analysis.binary.format} ${state.analysis.binary.architecture}`);
      console.log(`Functions: ${state.analysis.functions.length}`);
      break;

    default:
      console.log(`Unknown command: ${cmd}. Type 'help' for available commands.`);
  }
}
