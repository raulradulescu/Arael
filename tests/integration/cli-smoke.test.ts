import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * CLI smoke tests for the paths that must work WITHOUT a live Ghidra connection.
 * The CLI is run through ts-node (no build step needed). These exercise real
 * argument wiring end-to-end, not just the underlying functions.
 *
 * Note: `cache --list` loads the native better-sqlite3 binding. On a host where
 * that binding was built for a different platform (e.g. the Windows/WSL mismatch
 * this project hits), the test soft-skips instead of failing. Run under WSL for a
 * real assertion.
 */
const repoRoot = path.resolve(__dirname, '..', '..');
const cliEntry = path.join(repoRoot, 'src', 'cli', 'index.ts');
const tsNodeRegister = require.resolve('ts-node/register/transpile-only');

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): CliResult {
  const result = spawnSync(process.execPath, ['-r', tsNodeRegister, cliEntry, ...args], {
    cwd: repoRoot,
    encoding: 'utf-8',
    env: { ...process.env, TS_NODE_TRANSPILE_ONLY: '1' },
    timeout: 50_000
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? ''
  };
}

function makeTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeAnalysisFixture(filePath: string): void {
  const fixture = {
    binary: {
      filename: 'sample.bin',
      filepath: '/tmp/sample.bin',
      format: 'ELF',
      architecture: 'x86_64',
      bits: 64,
      endianness: 'little',
      entryPoint: '0x1000',
      imageBase: '0x0',
      size: 1024,
      hashes: { md5: '0'.repeat(32), sha1: '0'.repeat(40), sha256: '0'.repeat(64) }
      // `packing` intentionally omitted: --from-json must tolerate partial JSON.
    },
    functions: [],
    strings: [],
    imports: [],
    exports: [],
    sections: []
  };
  fs.writeFileSync(filePath, JSON.stringify(fixture));
}

describe('CLI smoke tests (no Ghidra)', () => {
  it('report --from-json renders standalone HTML', () => {
    const dir = makeTempDir('arael-smoke-report-');
    const jsonPath = path.join(dir, 'analysis.json');
    const outPath = path.join(dir, 'report.html');
    writeAnalysisFixture(jsonPath);

    const result = runCli(['report', '--from-json', jsonPath, '-o', outPath]);

    expect(result.status).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);
    expect(fs.readFileSync(outPath, 'utf-8')).toContain('<!DOCTYPE html>');
  });

  it('cache --list --json prints a JSON array', () => {
    const result = runCli(['cache', '--list', '--json']);

    // Soft-skip when the native SQLite binding cannot load on this platform.
    if (result.status !== 0 && /better_sqlite3|NODE_MODULE_VERSION|not a valid Win32/i.test(result.stderr)) {
      console.warn('Skipping cache smoke test: better-sqlite3 native binding unavailable on this platform.');
      return;
    }

    expect(result.status).toBe(0);
    expect(Array.isArray(JSON.parse(result.stdout))).toBe(true);
  });

  it('benchmark-agents --dry-run --format html renders standalone HTML', () => {
    const challengeRoot = makeTempDir('arael-smoke-bench-');
    const challengeDir = path.join(challengeRoot, '1 - sample');
    fs.mkdirSync(challengeDir, { recursive: true });
    fs.writeFileSync(path.join(challengeDir, 'sample.bin'), 'hello');
    const outPath = path.join(challengeRoot, 'agents.html');

    const result = runCli([
      'benchmark-agents', challengeRoot,
      '--agents', 'codex:test-model',
      '--dry-run',
      '--format', 'html',
      '-o', outPath
    ]);

    expect(result.status).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);
    expect(fs.readFileSync(outPath, 'utf-8')).toContain('<!DOCTYPE html>');
  });
});
