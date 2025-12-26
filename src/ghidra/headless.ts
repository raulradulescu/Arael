import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { logger } from '../utils/logger';
import { AnalysisResult } from '../output/schema';

export interface HeadlessResult {
  success: boolean;
  outputPath?: string;
  result?: AnalysisResult;
  error?: string;
  duration: number;
}

export interface HeadlessConfig {
  ghidraPath: string;
  pythonPath?: string;
  projectPath?: string;
  scriptPath?: string;
  javaOptions?: string;
  timeout?: number;
}

/**
 * GhidraHeadless manages communication with Ghidra via PyGhidra.
 * This is the fallback mode when ghidra-bridge is not available.
 * Requires Ghidra 12.0+ with PyGhidra support.
 */
export class GhidraHeadless {
  private ghidraPath: string;
  private pythonPath: string;
  private projectPath: string;
  private scriptPath: string;
  private javaOptions: string;
  private timeout: number;

  constructor(config: HeadlessConfig) {
    this.ghidraPath = config.ghidraPath;
    this.pythonPath = config.pythonPath
      ?? process.env['ARAEL_PYTHON']
      ?? process.env['PYTHON_PATH']
      ?? (process.platform === 'win32' ? 'python' : 'python3');
    this.projectPath = config.projectPath ?? path.join(os.tmpdir(), 'arael_projects');
    this.scriptPath = config.scriptPath ?? path.join(__dirname, 'scripts');
    this.javaOptions = config.javaOptions ?? '-Xmx4g';
    this.timeout = config.timeout ?? 300000; // 5 minutes default

    // Ensure directories exist
    if (!fs.existsSync(this.projectPath)) {
      fs.mkdirSync(this.projectPath, { recursive: true });
    }
  }

  /**
   * Check if Ghidra headless is available.
   */
  isAvailable(): boolean {
    return this.getAvailabilityError() === null;
  }

  getAvailabilityError(): string | null {
    if (!this.hasRuntimeArtifacts()) {
      return `Ghidra runtime not found under: ${this.ghidraPath}. Use a pre-built release.`;
    }

    const analysisScript = this.getAnalysisScriptPath();
    if (!fs.existsSync(analysisScript)) {
      return `Analysis script not found at: ${analysisScript}. Run 'npm run build' first.`;
    }

    return null;
  }

  private hasRuntimeArtifacts(): boolean {
    const baseJar = path.join(
      this.ghidraPath,
      'Ghidra',
      'Features',
      'Base',
      'lib',
      'Base.jar'
    );
    const utilityJar = path.join(
      this.ghidraPath,
      'Ghidra',
      'Framework',
      'Utility',
      'lib',
      'Utility.jar'
    );

    return fs.existsSync(baseJar) && fs.existsSync(utilityJar);
  }

  private getAnalysisScriptPath(): string {
    return path.join(this.scriptPath, 'run_analysis.py');
  }

  /**
   * Analyze a binary using PyGhidra.
   */
  async analyze(binaryPath: string): Promise<HeadlessResult> {
    const startTime = Date.now();
    const outputPath = path.join(os.tmpdir(), `arael_output_${Date.now()}.json`);
    const analysisScript = this.getAnalysisScriptPath();

    const availabilityError = this.getAvailabilityError();
    if (availabilityError) {
      return {
        success: false,
        error: availabilityError,
        duration: Date.now() - startTime
      };
    }

    const absoluteBinaryPath = path.resolve(binaryPath);
    if (!fs.existsSync(absoluteBinaryPath)) {
      return {
        success: false,
        error: `Binary file not found: ${absoluteBinaryPath}`,
        duration: Date.now() - startTime
      };
    }

    const args = [analysisScript, absoluteBinaryPath, outputPath];

    logger.info('Starting Ghidra headless analysis', {
      binary: absoluteBinaryPath,
      outputPath
    });

    return new Promise((resolve) => {
      const isWindows = process.platform === 'win32';
      const command = isWindows ? 'cmd.exe' : this.pythonPath;
      const commandArgs = isWindows ? ['/c', this.pythonPath, ...args] : args;

      const proc = spawn(command, commandArgs, {
        env: {
          ...process.env,
          GHIDRA_PATH: this.ghidraPath,
          _JAVA_OPTIONS: this.javaOptions
        }
      });

      let stderr = '';
      let finished = false;
      const finalize = (result: HeadlessResult): void => {
        if (finished) {
          return;
        }
        finished = true;
        clearTimeout(timeoutHandle);
        resolve(result);
      };

      const timeoutHandle = setTimeout(() => {
        if (finished) {
          return;
        }
        logger.error('Ghidra headless analysis timed out', { timeoutMs: this.timeout });
        if (isWindows) {
          proc.kill();
        } else {
          proc.kill('SIGKILL');
        }
        finalize({
          success: false,
          error: `Headless analysis timed out after ${this.timeout} ms`,
          duration: Date.now() - startTime
        });
      }, this.timeout);

      proc.stdout.on('data', (data: Buffer) => {
        logger.debug(`PyGhidra: ${data.toString().trim()}`);
      });

      proc.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        if (finished) {
          return;
        }
        const duration = Date.now() - startTime;

        if (code !== 0 || !fs.existsSync(outputPath)) {
          logger.error('Ghidra headless analysis failed', { code, stderr });
          finalize({
            success: false,
            error: `Headless analysis failed (code ${code}): ${stderr.slice(-500)}`,
            duration
          });
        } else {
          try {
            const content = fs.readFileSync(outputPath, 'utf-8');
            const result = JSON.parse(content) as AnalysisResult;

            // Clean up output file
            fs.unlinkSync(outputPath);

            logger.info('Ghidra headless analysis complete', { duration });
            finalize({
              success: true,
              outputPath,
              result,
              duration
            });
          } catch (e) {
            finalize({
              success: false,
              error: `Failed to parse analysis output: ${e}`,
              duration
            });
          }
        }
      });

      proc.on('error', (err) => {
        logger.error('Failed to spawn Python process', { error: err.message });
        finalize({
          success: false,
          error: `Failed to spawn Python: ${err.message}`,
          duration: Date.now() - startTime
        });
      });
    });
  }

  /**
   * Disassemble a function or address range using PyGhidra.
   */
  async disassemble(
    binaryPath: string,
    addressOrFunction: string,
    length?: number,
    includeBytes = true,
    includeReferences = true
  ): Promise<any[] | null> {
    const disassembleScript = path.join(this.scriptPath, 'disassemble.py');

    if (!fs.existsSync(disassembleScript)) {
      logger.error('Disassemble script not found', { path: disassembleScript });
      throw new Error(`Disassemble script not found: ${disassembleScript}`);
    }

    logger.info('Running disassembly via PyGhidra', {
      binary: binaryPath,
      target: addressOrFunction,
      length
    });

    return new Promise((resolve, reject) => {
      const args = [
        disassembleScript,
        binaryPath,
        addressOrFunction
      ];

      if (length !== undefined) {
        args.push('--length', length.toString());
      }
      if (!includeBytes) {
        args.push('--no-bytes');
      }
      if (!includeReferences) {
        args.push('--no-references');
      }

      const env = {
        ...process.env,
        GHIDRA_PATH: this.ghidraPath,
        JAVA_OPTIONS: this.javaOptions
      };

      const proc = spawn(this.pythonPath, args, {
        env,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      const timeout = setTimeout(() => {
        proc.kill();
        reject(new Error('Disassembly timeout'));
      }, this.timeout);

      proc.on('close', (code) => {
        clearTimeout(timeout);

        if (code !== 0) {
          // Try to extract error from JSON stdout first
          let errorMsg = stderr;
          try {
            const parsed = JSON.parse(stdout);
            if (parsed.error) {
              errorMsg = parsed.error;
            }
          } catch {
            // Not JSON, use stderr or stdout as error
            errorMsg = stderr || stdout;
          }
          logger.error('Disassembly failed', { code, stderr, stdout: stdout.slice(0, 500) });
          reject(new Error(`Disassembly failed with code ${code}: ${errorMsg}`));
          return;
        }

        try {
          const result = JSON.parse(stdout);
          resolve(result.instructions || null);
        } catch (e) {
          logger.error('Failed to parse disassembly output', { error: String(e) });
          reject(new Error(`Failed to parse output: ${e}`));
        }
      });

      proc.on('error', (err) => {
        clearTimeout(timeout);
        logger.error('Failed to spawn Python for disassembly', { error: err.message });
        reject(new Error(`Failed to spawn Python: ${err.message}`));
      });
    });
  }

  /**
   * Get cross-references to/from an address using PyGhidra.
   */
  async getXrefs(
    binaryPath: string,
    address: string,
    direction: 'to' | 'from' | 'both' = 'both',
    maxResults = 100
  ): Promise<any[] | null> {
    const xrefsScript = path.join(this.scriptPath, 'xrefs.py');

    if (!fs.existsSync(xrefsScript)) {
      logger.error('Xrefs script not found', { path: xrefsScript });
      throw new Error(`Xrefs script not found: ${xrefsScript}`);
    }

    logger.info('Running cross-reference analysis via PyGhidra', {
      binary: binaryPath,
      address,
      direction,
      maxResults
    });

    return new Promise((resolve, reject) => {
      const args = [
        xrefsScript,
        binaryPath,
        address,
        '--direction', direction,
        '--max', maxResults.toString()
      ];

      const env = {
        ...process.env,
        GHIDRA_PATH: this.ghidraPath,
        JAVA_OPTIONS: this.javaOptions
      };

      const proc = spawn(this.pythonPath, args, {
        env,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      const timeout = setTimeout(() => {
        proc.kill();
        reject(new Error('Cross-reference analysis timeout'));
      }, this.timeout);

      proc.on('close', (code) => {
        clearTimeout(timeout);

        if (code !== 0) {
          logger.error('Cross-reference analysis failed', { code, stderr });
          reject(new Error(`Cross-reference analysis failed with code ${code}: ${stderr}`));
          return;
        }

        try {
          const result = JSON.parse(stdout);
          resolve(result.references || null);
        } catch (e) {
          logger.error('Failed to parse cross-reference output', { error: String(e) });
          reject(new Error(`Failed to parse output: ${e}`));
        }
      });

      proc.on('error', (err) => {
        clearTimeout(timeout);
        logger.error('Failed to spawn Python for cross-references', { error: err.message });
        reject(new Error(`Failed to spawn Python: ${err.message}`));
      });
    });
  }

  /**
   * Get exported symbols from a binary using PyGhidra.
   */
  async getExports(
    binaryPath: string,
    filter?: {
      namePattern?: string;
      type?: 'function' | 'data' | 'all';
    }
  ): Promise<any[] | null> {
    const exportsScript = path.join(this.scriptPath, 'exports.py');

    if (!fs.existsSync(exportsScript)) {
      logger.error('Exports script not found', { path: exportsScript });
      throw new Error(`Exports script not found: ${exportsScript}`);
    }

    logger.info('Running exports extraction via PyGhidra', {
      binary: binaryPath,
      filter
    });

    return new Promise((resolve, reject) => {
      const args = [exportsScript, binaryPath];

      if (filter?.namePattern) {
        args.push('--pattern', filter.namePattern);
      }
      if (filter?.type && filter.type !== 'all') {
        args.push('--type', filter.type);
      }

      const env = {
        ...process.env,
        GHIDRA_PATH: this.ghidraPath,
        JAVA_OPTIONS: this.javaOptions
      };

      const proc = spawn(this.pythonPath, args, {
        env,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      const timeout = setTimeout(() => {
        proc.kill();
        reject(new Error('Exports extraction timeout'));
      }, this.timeout);

      proc.on('close', (code) => {
        clearTimeout(timeout);

        if (code !== 0) {
          logger.error('Exports extraction failed', { code, stderr });
          reject(new Error(`Exports extraction failed with code ${code}: ${stderr}`));
          return;
        }

        try {
          const result = JSON.parse(stdout);
          resolve(result.exports || null);
        } catch (e) {
          logger.error('Failed to parse exports output', { error: String(e) });
          reject(new Error(`Failed to parse output: ${e}`));
        }
      });

      proc.on('error', (err) => {
        clearTimeout(timeout);
        logger.error('Failed to spawn Python for exports', { error: err.message });
        reject(new Error(`Failed to spawn Python: ${err.message}`));
      });
    });
  }

  /**
   * Generate a call graph using PyGhidra.
   */
  async getCallgraph(
    binaryPath: string,
    options: {
      format: 'json' | 'dot' | 'mermaid';
      rootFunction?: string;
      maxDepth?: number;
      excludeExternal?: boolean;
      includeThunks?: boolean;
    }
  ): Promise<any | null> {
    const callgraphScript = path.join(this.scriptPath, 'callgraph.py');

    if (!fs.existsSync(callgraphScript)) {
      logger.error('Callgraph script not found', { path: callgraphScript });
      throw new Error(`Callgraph script not found: ${callgraphScript}`);
    }

    logger.info('Running call graph generation via PyGhidra', {
      binary: binaryPath,
      options
    });

    return new Promise((resolve, reject) => {
      const args = [
        callgraphScript,
        binaryPath,
        '--format', options.format
      ];

      if (options.rootFunction) {
        args.push('--root', options.rootFunction);
      }
      if (options.maxDepth !== undefined) {
        args.push('--depth', options.maxDepth.toString());
      }
      if (options.excludeExternal) {
        args.push('--no-external');
      }
      if (options.includeThunks) {
        args.push('--include-thunks');
      }

      const env = {
        ...process.env,
        GHIDRA_PATH: this.ghidraPath,
        JAVA_OPTIONS: this.javaOptions
      };

      const proc = spawn(this.pythonPath, args, {
        env,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      const timeout = setTimeout(() => {
        proc.kill();
        reject(new Error('Call graph generation timeout'));
      }, this.timeout);

      proc.on('close', (code) => {
        clearTimeout(timeout);

        if (code !== 0) {
          logger.error('Call graph generation failed', { code, stderr });
          reject(new Error(`Call graph generation failed with code ${code}: ${stderr}`));
          return;
        }

        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (e) {
          logger.error('Failed to parse call graph output', { error: String(e) });
          reject(new Error(`Failed to parse output: ${e}`));
        }
      });

      proc.on('error', (err) => {
        clearTimeout(timeout);
        logger.error('Failed to spawn Python for call graph', { error: err.message });
        reject(new Error(`Failed to spawn Python: ${err.message}`));
      });
    });
  }
}
