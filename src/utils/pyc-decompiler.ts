import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';

export interface PycInfo {
  isPyc: boolean;
  pythonVersion: string | null;
  magicNumber: number | null;
  timestamp: number | null;
  sourceSize: number | null;
  hasSourceHash: boolean;
}

export interface DecompileResult {
  success: boolean;
  sourceCode: string | null;
  pythonVersion: string;
  decompiler: 'uncompyle6' | 'unknown';
  errors: string[];
  warnings: string[];
}

const MAGIC_NUMBER_MAP: Record<number, string> = {
  0x03f3: '2.7',
  0x0d33: '3.6',
  0x0d42: '3.7',
  0x0d55: '3.8',
  0x0d59: '3.8',
  0x0d61: '3.9',
  0x0d6f: '3.10',
  0x0da7: '3.11',
  0x0dcb: '3.12',
  0x0df3: '3.13'
};

export async function detectPycVersion(filePath: string): Promise<PycInfo> {
  try {
    const buffer = fs.readFileSync(filePath);
    if (buffer.length < 4) {
      return emptyPycInfo();
    }

    const magicNumber = buffer.readUInt16LE(0);
    const pythonVersion = MAGIC_NUMBER_MAP[magicNumber] ?? null;

    if (!pythonVersion) {
      return emptyPycInfo();
    }

    const header = parsePycHeader(buffer, pythonVersion);
    if (!header) {
      return emptyPycInfo();
    }

    return {
      isPyc: true,
      pythonVersion,
      magicNumber,
      timestamp: header.timestamp,
      sourceSize: header.sourceSize,
      hasSourceHash: header.hasSourceHash
    };
  } catch {
    return emptyPycInfo();
  }
}

export async function decompilePyc(filePath: string): Promise<DecompileResult> {
  const info = await detectPycVersion(filePath);

  if (!info.isPyc || !info.pythonVersion) {
    return {
      success: false,
      sourceCode: null,
      pythonVersion: info.pythonVersion ?? 'unknown',
      decompiler: 'unknown',
      errors: ['Not a valid .pyc file or unsupported Python version.'],
      warnings: []
    };
  }

  const headerSize = getPycHeaderSize(info.pythonVersion);
  const scriptPath = resolveScriptPath();

  if (!scriptPath) {
    return {
      success: false,
      sourceCode: null,
      pythonVersion: info.pythonVersion,
      decompiler: 'unknown',
      errors: ['pyc_decompiler.py script not found.'],
      warnings: []
    };
  }

  const args = [scriptPath, filePath, '--header-size', headerSize.toString()];
  const pythonResult = await runPythonScript(args);

  if (!pythonResult) {
    return {
      success: false,
      sourceCode: null,
      pythonVersion: info.pythonVersion,
      decompiler: 'unknown',
      errors: ['Failed to execute Python decompiler helper.'],
      warnings: []
    };
  }

  const { stdout, stderr, error } = pythonResult;
  if (error) {
    return {
      success: false,
      sourceCode: null,
      pythonVersion: info.pythonVersion,
      decompiler: 'unknown',
      errors: [error],
      warnings: stderr ? [stderr] : []
    };
  }

  try {
    const parsed = JSON.parse(stdout) as {
      success: boolean;
      sourceCode: string | null;
      decompiler: 'uncompyle6' | 'unknown';
      errors: string[];
      warnings: string[];
    };

    return {
      success: parsed.success,
      sourceCode: parsed.sourceCode,
      pythonVersion: info.pythonVersion,
      decompiler: parsed.decompiler ?? 'unknown',
      errors: parsed.errors ?? [],
      warnings: parsed.warnings ?? []
    };
  } catch (e) {
    return {
      success: false,
      sourceCode: null,
      pythonVersion: info.pythonVersion,
      decompiler: 'unknown',
      errors: ['Failed to parse decompiler output.'],
      warnings: stderr ? [stderr] : []
    };
  }
}

export async function decompilePycDirectory(
  dirPath: string
): Promise<Map<string, DecompileResult>> {
  const results = new Map<string, DecompileResult>();
  const pycFiles = await collectPycFiles(dirPath);

  for (const filePath of pycFiles) {
    try {
      const result = await decompilePyc(filePath);
      results.set(filePath, result);
    } catch (e) {
      results.set(filePath, {
        success: false,
        sourceCode: null,
        pythonVersion: 'unknown',
        decompiler: 'unknown',
        errors: [String(e)],
        warnings: []
      });
    }
  }

  return results;
}

function emptyPycInfo(): PycInfo {
  return {
    isPyc: false,
    pythonVersion: null,
    magicNumber: null,
    timestamp: null,
    sourceSize: null,
    hasSourceHash: false
  };
}

function parsePycHeader(
  buffer: Buffer,
  pythonVersion: string
): { timestamp: number | null; sourceSize: number | null; hasSourceHash: boolean } | null {
  const version = parseVersion(pythonVersion);
  if (!version) {
    return null;
  }

  const { major, minor } = version;

  if (major > 3 || (major === 3 && minor >= 7)) {
    if (buffer.length < 16) {
      return null;
    }
    const bitfield = buffer.readUInt32LE(4);
    const hasSourceHash = (bitfield & 0x1) !== 0;
    if (hasSourceHash) {
      return {
        timestamp: null,
        sourceSize: null,
        hasSourceHash: true
      };
    }
    return {
      timestamp: buffer.readUInt32LE(8),
      sourceSize: buffer.readUInt32LE(12),
      hasSourceHash: false
    };
  }

  if (major === 3 && minor >= 3) {
    if (buffer.length < 12) {
      return null;
    }
    return {
      timestamp: buffer.readUInt32LE(4),
      sourceSize: buffer.readUInt32LE(8),
      hasSourceHash: false
    };
  }

  if (major === 2) {
    if (buffer.length < 8) {
      return null;
    }
    return {
      timestamp: buffer.readUInt32LE(4),
      sourceSize: null,
      hasSourceHash: false
    };
  }

  return null;
}

function getPycHeaderSize(pythonVersion: string): number {
  const version = parseVersion(pythonVersion);
  if (!version) {
    return 16;
  }

  const { major, minor } = version;
  if (major > 3 || (major === 3 && minor >= 7)) {
    return 16;
  }

  if (major === 3 && minor >= 3) {
    return 12;
  }

  return 8;
}

function parseVersion(version: string): { major: number; minor: number } | null {
  const parts = version.split('.');
  if (parts.length < 2) {
    return null;
  }

  const major = Number(parts[0]);
  const minor = Number(parts[1]);
  if (Number.isNaN(major) || Number.isNaN(minor)) {
    return null;
  }

  return { major, minor };
}

async function collectPycFiles(dirPath: string): Promise<string[]> {
  const results: string[] = [];
  const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      const nested = await collectPycFiles(fullPath);
      results.push(...nested);
    } else if (entry.isFile() && entry.name.endsWith('.pyc')) {
      results.push(fullPath);
    }
  }

  return results;
}

function resolveScriptPath(): string | null {
  const directPath = path.join(__dirname, 'pyc_decompiler.py');
  if (fs.existsSync(directPath)) {
    return directPath;
  }

  const fallbackPath = path.resolve(__dirname, '../../src/utils/pyc_decompiler.py');
  if (fs.existsSync(fallbackPath)) {
    return fallbackPath;
  }

  return null;
}

async function runPythonScript(
  args: string[]
): Promise<{ stdout: string; stderr: string; error?: string } | null> {
  const pythonCandidates = [
    process.env['ARAEL_PYTHON'],
    process.env['PYTHON_PATH'],
    'python3',
    'python'
  ].filter(Boolean) as string[];

  for (const python of pythonCandidates) {
    try {
      const result = await spawnWithOutput(python, args);
      return result;
    } catch (e) {
      continue;
    }
  }

  return null;
}

function spawnWithOutput(
  command: string,
  args: string[],
  timeoutMs = 60000
): Promise<{ stdout: string; stderr: string; error?: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    let stderr = '';
    let finished = false;

    const timeout = setTimeout(() => {
      if (!finished) {
        finished = true;
        proc.kill();
        resolve({
          stdout,
          stderr,
          error: 'Python decompiler timed out.'
        });
      }
    }, timeoutMs);

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    proc.on('close', () => {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timeout);
      resolve({ stdout, stderr });
    });
  });
}
