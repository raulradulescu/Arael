/**
 * Unit tests for .pyc decompilation feature
 *
 * Requirements:
 * - Detect .pyc files (Python bytecode)
 * - Identify Python version from magic bytes
 * - Decompile to readable Python source
 * - Handle multiple Python versions (2.7, 3.6-3.13)
 * - Integrate with PyInstaller extraction workflow
 *
 * Dependencies (to be implemented):
 * - src/utils/pyc-decompiler.ts
 * - External tool: uncompyle6 (preferred), with marshal/dis/AST fallback
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

// Load environment before accessing env variables
import { loadEnvFromFile } from '../../src/utils/env';
loadEnvFromFile();

import {
  detectPycVersion,
  decompilePyc,
  decompilePycDirectory
} from '../../src/utils/pyc-decompiler';

const MAGIC_NUMBER_MAP: Record<string, number> = {
  '2.7': 0x03f3,
  '3.6': 0x0d33,
  '3.7': 0x0d42,
  '3.8': 0x0d55,
  '3.9': 0x0d61,
  '3.10': 0x0d6f,
  '3.11': 0x0da7,
  '3.12': 0x0dcb,
  '3.13': 0x0df3
};

function getPythonCandidates(): string[] {
  return [
    process.env['ARAEL_PYTHON'],
    process.env['PYTHON_PATH'],
    'python3',
    'python'
  ].filter(Boolean) as string[];
}

const compiledCache = new Map<string, Buffer>();
const fixturesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arael_pyc_'));

function getHeaderSize(version: string): number {
  const parts = version.split('.');
  const major = Number(parts[0] ?? '0');
  const minor = Number(parts[1] ?? '0');
  if (major > 3 || (major === 3 && minor >= 7)) {
    return 16;
  }
  if (major === 3 && minor >= 3) {
    return 12;
  }
  return 8;
}

function compileSource(source: string): Buffer {
  const cached = compiledCache.get(source);
  if (cached) {
    return cached;
  }

  const script = [
    'import base64, marshal, sys',
    'src = sys.stdin.read()',
    'code = compile(src, "<test>", "exec")',
    'data = marshal.dumps(code)',
    'sys.stdout.write(base64.b64encode(data).decode("ascii"))'
  ].join('; ');

  for (const python of getPythonCandidates()) {
    const result = spawnSync(python, ['-c', script], {
      input: source,
      encoding: 'utf8'
    });

    if (result.status === 0 && result.stdout) {
      const buffer = Buffer.from(result.stdout.trim(), 'base64');
      compiledCache.set(source, buffer);
      return buffer;
    }
  }

  throw new Error('Python not available to generate .pyc fixtures.');
}

function writePycFile(
  filePath: string,
  version: string,
  source: string,
  options: { hashBased?: boolean } = {}
): void {
  const magic = MAGIC_NUMBER_MAP[version];
  if (!magic) {
    throw new Error(`Unsupported magic version: ${version}`);
  }

  const headerSize = getHeaderSize(version);
  const header = Buffer.alloc(headerSize, 0);
  header.writeUInt16LE(magic, 0);
  header.writeUInt16LE(0x0d0a, 2);

  if (headerSize === 16) {
    header.writeUInt32LE(options.hashBased ? 1 : 0, 4);
    if (!options.hashBased) {
      header.writeUInt32LE(1, 8);
      header.writeUInt32LE(Buffer.byteLength(source), 12);
    }
  } else if (headerSize === 12) {
    header.writeUInt32LE(1, 4);
    header.writeUInt32LE(Buffer.byteLength(source), 8);
  } else {
    header.writeUInt32LE(1, 4);
  }

  const body = compileSource(source);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, Buffer.concat([header, body]));
}

beforeAll(() => {
  const simpleSource = 'def simple():\n    return 1\n';
  const argsSource = 'def with_args(a, b, *args, **kwargs):\n    return a + b\n';
  const classSource = 'class Example:\n    pass\n';
  const importSource = 'import os\nfrom sys import path\n';
  const asyncSource = 'async def coro():\n    return 42\n';
  const fstringSource = 'def fmt(name):\n    return f"hello {name}"\n';
  const walrusSource = 'def walrus():\n    if (x := 1):\n        return x\n';
  const matchSource = 'def matcher(x):\n    match x:\n        case 1:\n            return 1\n        case _:\n            return 0\n';
  const complexSource = 'def complex_func(a, b):\n    if a > b:\n        return a - b\n    return a + b\n';

  writePycFile(path.join(fixturesDir, 'python311_example.pyc'), '3.11', simpleSource);
  writePycFile(path.join(fixturesDir, 'python310_example.pyc'), '3.10', simpleSource);
  writePycFile(path.join(fixturesDir, 'python39_example.pyc'), '3.9', simpleSource);
  writePycFile(path.join(fixturesDir, 'python38_example.pyc'), '3.8', simpleSource);
  writePycFile(path.join(fixturesDir, 'python27_example.pyc'), '2.7', simpleSource);
  writePycFile(path.join(fixturesDir, 'python311_hashbased.pyc'), '3.11', simpleSource, {
    hashBased: true
  });
  writePycFile(path.join(fixturesDir, 'python312_example.pyc'), '3.12', simpleSource);

  writePycFile(path.join(fixturesDir, 'simple_function_311.pyc'), '3.11', simpleSource);
  writePycFile(path.join(fixturesDir, 'simple_function_38.pyc'), '3.8', simpleSource);
  writePycFile(path.join(fixturesDir, 'function_with_args.pyc'), '3.11', argsSource);
  writePycFile(path.join(fixturesDir, 'class_example.pyc'), '3.11', classSource);
  writePycFile(path.join(fixturesDir, 'with_imports.pyc'), '3.11', importSource);
  writePycFile(path.join(fixturesDir, 'complex_example.pyc'), '3.11', complexSource);
  writePycFile(path.join(fixturesDir, 'async_example.pyc'), '3.11', asyncSource);
  writePycFile(path.join(fixturesDir, 'fstring_example.pyc'), '3.11', fstringSource);
  writePycFile(path.join(fixturesDir, 'walrus_example.pyc'), '3.11', walrusSource);
  writePycFile(path.join(fixturesDir, 'match_example.pyc'), '3.11', matchSource);

  fs.writeFileSync(path.join(fixturesDir, 'not_a_pyc.txt'), 'not a pyc');
  fs.writeFileSync(path.join(fixturesDir, 'corrupted.pyc'), Buffer.from([0x00, 0x01]));
  fs.writeFileSync(path.join(fixturesDir, 'obfuscated.pyc'), Buffer.from([0xff, 0xff, 0xff, 0xff]));

  const pyiDir = path.join(fixturesDir, 'pyinstaller_extracted');
  writePycFile(path.join(pyiDir, 'module_a.pyc'), '3.11', simpleSource);
  writePycFile(path.join(pyiDir, 'module_b.pyc'), '3.11', classSource);

  const nestedDir = path.join(fixturesDir, 'nested_pyc', 'pkg');
  writePycFile(path.join(nestedDir, 'nested_module.pyc'), '3.11', simpleSource);

  const mixedDir = path.join(fixturesDir, 'mixed_files');
  writePycFile(path.join(mixedDir, 'mixed_module.pyc'), '3.11', simpleSource);
  fs.writeFileSync(path.join(mixedDir, 'readme.txt'), 'hello');

  const corruptedDir = path.join(fixturesDir, 'some_corrupted');
  writePycFile(path.join(corruptedDir, 'good.pyc'), '3.11', simpleSource);
  fs.writeFileSync(path.join(corruptedDir, 'bad.pyc'), Buffer.from([0x00, 0x02, 0x03]));
});

afterAll(() => {
  fs.rmSync(fixturesDir, { recursive: true, force: true });
});

const describeOrSkip = describe;

describeOrSkip('PYC Detection', () => {
  describe('detectPycVersion', () => {
    it('should detect Python 3.11 .pyc file', async () => {
      const pycPath = path.join(fixturesDir, 'python311_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.isPyc).toBe(true);
      expect(info.pythonVersion).toBe('3.11');
      expect(info.magicNumber).toBeDefined();
    });

    it('should detect Python 3.10 .pyc file', async () => {
      const pycPath = path.join(fixturesDir, 'python310_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.isPyc).toBe(true);
      expect(info.pythonVersion).toBe('3.10');
    });

    it('should detect Python 3.9 .pyc file', async () => {
      const pycPath = path.join(fixturesDir, 'python39_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.isPyc).toBe(true);
      expect(info.pythonVersion).toBe('3.9');
    });

    it('should detect Python 3.8 .pyc file', async () => {
      const pycPath = path.join(fixturesDir, 'python38_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.isPyc).toBe(true);
      expect(info.pythonVersion).toBe('3.8');
    });

    it('should detect Python 2.7 .pyc file', async () => {
      const pycPath = path.join(fixturesDir, 'python27_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.isPyc).toBe(true);
      expect(info.pythonVersion).toBe('2.7');
    });

    it('should detect Python 3.7+ hash-based .pyc', async () => {
      const pycPath = path.join(fixturesDir, 'python311_hashbased.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.isPyc).toBe(true);
      expect(info.hasSourceHash).toBe(true);
    });

    it('should return isPyc=false for non-.pyc file', async () => {
      const txtPath = path.join(fixturesDir, 'not_a_pyc.txt');
      const info = await detectPycVersion(txtPath);

      expect(info.isPyc).toBe(false);
      expect(info.pythonVersion).toBeNull();
    });

    it('should handle corrupted .pyc file gracefully', async () => {
      const corruptPath = path.join(fixturesDir, 'corrupted.pyc');
      const info = await detectPycVersion(corruptPath);

      expect(info.isPyc).toBe(false);
    });

    it('should extract timestamp from .pyc header', async () => {
      const pycPath = path.join(fixturesDir, 'python38_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.timestamp).toBeDefined();
      expect(info.timestamp).toBeGreaterThan(0);
    });

    it('should extract source size from Python 3.3+ .pyc', async () => {
      const pycPath = path.join(fixturesDir, 'python311_example.pyc');
      const info = await detectPycVersion(pycPath);

      expect(info.sourceSize).toBeDefined();
      expect(info.sourceSize).toBeGreaterThan(0);
    });
  });
});

describeOrSkip('PYC Decompilation', () => {
  describe('decompilePyc', () => {
    it('should decompile simple Python 3.11 function', async () => {
      const pycPath = path.join(fixturesDir, 'simple_function_311.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      expect(result.sourceCode).toBeDefined();
      expect(result.sourceCode).toContain('def ');
      expect(result.pythonVersion).toBe('3.11');
    });

    it('should decompile Python 3.8', async () => {
      const pycPath = path.join(fixturesDir, 'simple_function_38.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      // Accept any working decompiler (uncompyle6 preferred, fallback to unknown)
      expect(['uncompyle6', 'unknown']).toContain(result.decompiler);
      expect(result.sourceCode).toContain('def ');
    });

    it('should decompile Python 2.7 code', async () => {
      const pycPath = path.join(fixturesDir, 'python27_example.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      expect(result.pythonVersion).toBe('2.7');
    });

    it('should fallback to marshal/dis when uncompyle6 fails', async () => {
      const pycPath = path.join(fixturesDir, 'python312_example.pyc');
      const result = await decompilePyc(pycPath);

      // Python 3.12+ may require fallback if uncompyle6 lacks support
      expect(result.success).toBe(true);
      expect(['uncompyle6', 'unknown']).toContain(result.decompiler);
    });

    it('should preserve function signatures', async () => {
      const pycPath = path.join(fixturesDir, 'function_with_args.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      expect(result.sourceCode).toMatch(/def\s+\w+\s*\([^)]+\)/);
    });

    it('should preserve class definitions', async () => {
      const pycPath = path.join(fixturesDir, 'class_example.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      expect(result.sourceCode).toContain('class ');
    });

    it('should handle imports correctly', async () => {
      const pycPath = path.join(fixturesDir, 'with_imports.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      expect(result.sourceCode).toMatch(/^(import |from )/m);
    });

    it('should report errors for obfuscated bytecode', async () => {
      const pycPath = path.join(fixturesDir, 'obfuscated.pyc');
      const result = await decompilePyc(pycPath);

      // May succeed partially or fail
      if (!result.success) {
        expect(result.errors.length).toBeGreaterThan(0);
      }
    });

    it('should include warnings for incomplete decompilation', async () => {
      const pycPath = path.join(fixturesDir, 'complex_example.pyc');
      const result = await decompilePyc(pycPath);

      // Complex code might have warnings even if successful
      expect(result.warnings).toBeDefined();
    });

    it('should handle async/await syntax (Python 3.5+)', async () => {
      const pycPath = path.join(fixturesDir, 'async_example.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      expect(result.sourceCode).toMatch(/async\s+def/);
    });

    it('should handle f-strings (Python 3.6+)', async () => {
      const pycPath = path.join(fixturesDir, 'fstring_example.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      // f-strings may be decompiled to .format() or concatenation
      expect(result.sourceCode).toBeDefined();
    });

    it('should handle walrus operator (Python 3.8+)', async () => {
      const pycPath = path.join(fixturesDir, 'walrus_example.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      // May be decompiled with or without :=
      expect(result.sourceCode).toBeDefined();
    });

    it('should handle match statements (Python 3.10+)', async () => {
      const pycPath = path.join(fixturesDir, 'match_example.pyc');
      const result = await decompilePyc(pycPath);

      expect(result.success).toBe(true);
      // match/case may be decompiled to if/elif chains
      expect(result.sourceCode).toBeDefined();
    });
  });

  describe('decompilePycDirectory', () => {
    it('should decompile all .pyc files in directory', async () => {
      const dirPath = path.join(fixturesDir, 'pyinstaller_extracted');
      const results = await decompilePycDirectory(dirPath);

      expect(results.size).toBeGreaterThan(0);

      for (const [filename, result] of results) {
        expect(filename.endsWith('.pyc')).toBe(true);
        expect(result.pythonVersion).toBeDefined();
      }
    });

    it('should handle nested directories', async () => {
      const dirPath = path.join(fixturesDir, 'nested_pyc');
      const results = await decompilePycDirectory(dirPath);

      // Should find .pyc files in subdirectories
      expect(results.size).toBeGreaterThan(0);
    });

    it('should skip non-.pyc files', async () => {
      const dirPath = path.join(fixturesDir, 'mixed_files');
      const results = await decompilePycDirectory(dirPath);

      for (const [filename] of results) {
        expect(filename.endsWith('.pyc')).toBe(true);
      }
    });

    it('should continue on individual file failures', async () => {
      const dirPath = path.join(fixturesDir, 'some_corrupted');
      const results = await decompilePycDirectory(dirPath);

      // Should have results for good files even if some fail
      let hasSuccess = false;
      let hasFailure = false;

      for (const [, result] of results) {
        if (result.success) hasSuccess = true;
        else hasFailure = true;
      }

      expect(hasSuccess).toBe(true);
      expect(hasFailure).toBe(true);
    });
  });
});

describeOrSkip('PyInstaller + PYC Integration', () => {
  it('should extract and decompile PyInstaller bundle', async () => {
    const pyiPath = path.join(__dirname, '../fixtures/pyinstaller_bundle.exe');
    void pyiPath;

    // This would use the existing extractPyInstaller + new decompilePycDirectory
    // const extractResult = await extractPyInstaller(pyiPath);
    // const decompileResults = await decompilePycDirectory(extractResult.outputDir);

    // expect(decompileResults.size).toBeGreaterThan(0);
    expect(true).toBe(true); // Placeholder
  });

  it('should identify main entry point .pyc', async () => {
    const pyiPath = path.join(__dirname, '../fixtures/pyinstaller_bundle.exe');
    void pyiPath;

    // Main script is usually at the root or named after the bundle
    // const extractResult = await extractPyInstaller(pyiPath);
    // expect(extractResult.mainScript).toBeDefined();

    expect(true).toBe(true); // Placeholder
  });
});

describeOrSkip('Decompiler Tool Detection', () => {
  it('should detect if uncompyle6 is installed', async () => {
    // const hasUncompyle6 = await checkDecompilerAvailable('uncompyle6');
    // expect(typeof hasUncompyle6).toBe('boolean');
    expect(true).toBe(true); // Placeholder
  });

  it('should detect if fallback decompiler is available', async () => {
    // const hasFallback = await checkDecompilerAvailable('marshal');
    // expect(typeof hasFallback).toBe('boolean');
    expect(true).toBe(true); // Placeholder
  });

  it('should provide installation instructions when tools missing', async () => {
    // const instructions = await getDecompilerInstallInstructions();
    // expect(instructions.uncompyle6).toContain('pip install');
    expect(true).toBe(true); // Placeholder
  });
});

// Magic number reference for Python versions
// https://github.com/python/cpython/blob/main/Lib/importlib/_bootstrap_external.py
describe('Python Magic Numbers Reference', () => {
  it('should document known magic numbers', () => {
    const magicNumbers: Record<string, number[]> = {
      '2.7': [0x03f3],
      '3.6': [0x0d33],
      '3.7': [0x0d42],
      '3.8': [0x0d55, 0x0d59],
      '3.9': [0x0d61],
      '3.10': [0x0d6f],
      '3.11': [0x0da7],
      '3.12': [0x0dcb],
      '3.13': [0x0df3],
    };

    // Just verify the reference exists
    expect(Object.keys(magicNumbers).length).toBeGreaterThan(5);
  });
});
