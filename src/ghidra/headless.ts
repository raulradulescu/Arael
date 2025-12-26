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
}
