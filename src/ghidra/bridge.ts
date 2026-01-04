import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import { logger } from '../utils/logger';

export interface GhidraFunction {
  name: string;
  address: string;
  size: number;
  signature?: string;
  isThunk?: boolean;
  isExternal?: boolean;
}

export interface GhidraString {
  address: string;
  value: string;
  length: number;
}

export interface GhidraImport {
  name: string;
  library: string;
  address: string;
}

export interface BridgeError {
  error: string;
}

export interface BridgeConfig {
  host?: string;
  port?: number;
  pythonPath?: string;
}

/**
 * GhidraBridge manages communication with Ghidra via ghidra-bridge.
 *
 * PERFORMANCE NOTE: Each query spawns a Python subprocess. While this adds
 * ~50-100ms overhead per call, it provides:
 * - Process isolation (Python crash doesn't kill MCP server)
 * - Clean state (no memory leaks from long-running Python)
 * - Simplicity (no need to manage Python interpreter lifecycle)
 *
 * FUTURE OPTIMIZATION: For high-frequency queries, implement a persistent
 * Python subprocess with stdin/stdout IPC. This would reduce per-query
 * latency to ~5-10ms but adds complexity. Defer until profiling shows need.
 */
export class GhidraBridge extends EventEmitter {
  private bridgeHost: string;
  private bridgePort: number;
  private pythonPath: string;

  constructor(config: BridgeConfig = {}) {
    super();
    this.bridgeHost = config.host ?? '127.0.0.1';
    this.bridgePort = config.port ?? 4768;
    // Allow PYTHON_PATH env var to override, with fallback to 'python' or 'python3'
    this.pythonPath = config.pythonPath
      ?? process.env['PYTHON_PATH']
      ?? process.env['ARAEL_PYTHON']
      ?? (process.platform === 'win32' ? 'python' : 'python3');
  }

  /**
   * Check if the bridge server is reachable.
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.query<number>('1 + 1');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Execute a Python script via ghidra-bridge.
   */
  async query<T>(script: string, args: Record<string, unknown> = {}): Promise<T> {
    return new Promise((resolve, reject) => {
      const wrappedScript = this.wrapScript(script, args);

      const python = spawn(this.pythonPath, ['-c', wrappedScript], {
        env: {
          ...process.env,
          GHIDRA_BRIDGE_HOST: this.bridgeHost,
          GHIDRA_BRIDGE_PORT: String(this.bridgePort)
        }
      });

      let stdout = '';
      let stderr = '';

      python.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      python.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      python.on('close', (code) => {
        if (code !== 0) {
          logger.error('Ghidra bridge query failed', { code, stderr });
          reject(new Error(`Ghidra query failed (code ${code}): ${stderr}`));
        } else {
          try {
            const result = JSON.parse(stdout) as T | BridgeError;
            if (this.isBridgeError(result)) {
              reject(new Error(result.error));
            } else {
              resolve(result);
            }
          } catch (e) {
            reject(new Error(`Invalid JSON from Ghidra: ${stdout}`));
          }
        }
      });

      python.on('error', (err) => {
        logger.error('Failed to spawn Python process', { error: err.message });
        reject(new Error(`Failed to spawn Python: ${err.message}`));
      });
    });
  }

  private isBridgeError(result: unknown): result is BridgeError {
    return (
      typeof result === 'object' &&
      result !== null &&
      'error' in result &&
      typeof (result as BridgeError).error === 'string'
    );
  }

  private wrapScript(userScript: string, args: Record<string, unknown>): string {
    const host = this.bridgeHost;
    const port = this.bridgePort;

    return `
import json
import sys

try:
    import ghidra_bridge
except ImportError:
    print(json.dumps({"error": "ghidra-bridge not installed. Run: pip install ghidra-bridge"}))
    sys.exit(1)

try:
    b = ghidra_bridge.GhidraBridge(
        namespace=globals(),
        connect_to_host="${host}",
        connect_to_port=${port}
    )
except Exception as e:
    print(json.dumps({"error": f"Failed to connect to Ghidra bridge: {e}"}))
    sys.exit(1)

args = ${JSON.stringify(args)}

try:
    result = (lambda: (
        ${userScript}
    ))()
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
`;
  }

  /**
   * Get all functions from the current program.
   */
  async getFunctions(): Promise<GhidraFunction[]> {
    return this.query<GhidraFunction[]>(`
[
    {
        "name": str(f.getName()),
        "address": str(f.getEntryPoint()),
        "size": f.getBody().getNumAddresses(),
        "signature": str(f.getSignature()),
        "isThunk": f.isThunk(),
        "isExternal": f.isExternal()
    }
    for f in currentProgram.getFunctionManager().getFunctions(True)
]
    `);
  }

  /**
   * Decompile a function by name or address.
   */
  async decompile(functionNameOrAddress: string): Promise<string | null> {
    const isAddress = functionNameOrAddress.startsWith('0x');

    const script = isAddress
      ? `
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)

addr = currentProgram.getAddressFactory().getAddress(args["target"])
func = currentProgram.getFunctionManager().getFunctionAt(addr)

if func is None:
    None
else:
    result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
    result.getDecompiledFunction().getC() if result.decompileCompleted() else None
      `
      : `
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)

funcs = list(currentProgram.getFunctionManager().getFunctions(True))
func = next((f for f in funcs if f.getName() == args["target"]), None)

if func is None:
    None
else:
    result = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
    result.getDecompiledFunction().getC() if result.decompileCompleted() else None
      `;

    return this.query<string | null>(script, { target: functionNameOrAddress });
  }

  /**
   * Get all defined strings from the current program.
   */
  async getStrings(): Promise<GhidraString[]> {
    return this.query<GhidraString[]>(`
[
    {
        "address": str(s.getAddress()),
        "value": s.getValue(),
        "length": s.getLength()
    }
    for s in currentProgram.getListing().getDefinedStrings()
]
    `);
  }

  /**
   * Get all imports from the current program.
   */
  async getImports(): Promise<GhidraImport[]> {
    return this.query<GhidraImport[]>(`
[
    {
        "name": sym.getName(),
        "library": str(sym.getParentNamespace()),
        "address": str(sym.getAddress())
    }
    for sym in currentProgram.getSymbolTable().getExternalSymbols()
]
    `);
  }

  /**
   * Get program metadata.
   */
  async getProgramInfo(): Promise<{
    name: string;
    language: string;
    format: string;
    imageBase: string;
    entryPoint: string;
  }> {
    return this.query(`
{
    "name": currentProgram.getName(),
    "language": str(currentProgram.getLanguage()),
    "format": currentProgram.getExecutableFormat(),
    "imageBase": str(currentProgram.getImageBase()),
    "entryPoint": (lambda symbols: str(symbols[0].getAddress()) if symbols else str(currentProgram.getMinAddress()))([s for s in currentProgram.getSymbolTable().getSymbols("entry")])
}
    `);
  }

  /**
   * Check if a program is currently loaded in Ghidra.
   */
  async hasLoadedProgram(): Promise<boolean> {
    try {
      const result = await this.query<boolean>('currentProgram is not None');
      return result;
    } catch {
      return false;
    }
  }

  /**
   * Get the name of the currently loaded program.
   */
  async getCurrentProgramName(): Promise<string | null> {
    try {
      return await this.query<string | null>(
        'currentProgram.getName() if currentProgram else None'
      );
    } catch {
      return null;
    }
  }

  /**
   * Load a binary file into Ghidra via the bridge.
   * This imports the file into a new project and opens it.
   *
   * Note: This requires Ghidra to be running with the bridge server.
   * The binary will be imported into a temporary project in Ghidra's workspace.
   */
  async loadBinary(binaryPath: string): Promise<{
    success: boolean;
    programName?: string;
    error?: string;
  }> {
    const script = `
import os
from ghidra.base.project import GhidraProject
from ghidra.program.flatapi import FlatProgramAPI

binary_path = args["binaryPath"]

if not os.path.exists(binary_path):
    {"success": False, "error": f"File not found: {binary_path}"}
else:
    try:
        # Get the project location from the current state
        project = state.getProject()
        project_location = project.getProjectLocator()

        # Import the binary
        from ghidra.app.util.importer import AutoImporter, MessageLog
        from java.io import File

        file = File(binary_path)
        msg_log = MessageLog()

        # Try to import
        program = AutoImporter.importByUsingBestGuess(
            file,
            project,
            None,  # folder path (root)
            state,
            msg_log,
            state.getTool().getService(ghidra.app.services.ProgramManager).getDefaultAnalyzerOptions("ELF")
        )

        if program:
            # Open in current tool
            pm = state.getTool().getService(ghidra.app.services.ProgramManager)
            pm.openProgram(program)

            {"success": True, "programName": program.getName()}
        else:
            {"success": False, "error": "Import returned None - unsupported format?"}
    except Exception as e:
        {"success": False, "error": str(e)}
    `;

    try {
      return await this.query<{ success: boolean; programName?: string; error?: string }>(
        script,
        { binaryPath }
      );
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Close the currently loaded program in Ghidra.
   */
  async closeCurrentProgram(): Promise<boolean> {
    try {
      return await this.query<boolean>(`
if currentProgram:
    pm = state.getTool().getService(ghidra.app.services.ProgramManager)
    pm.closeProgram(currentProgram, True)
    True
else:
    True
      `);
    } catch {
      return false;
    }
  }
}
