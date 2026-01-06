/**
 * Integration tests for arael_analyze tool
 * Requires: GHIDRA_PATH environment variable or running ghidra-bridge
 */

import * as fs from 'fs';
import * as path from 'path';
import { GhidraConnection, getConnection } from '../../src/ghidra/connection';
import { analyzeHandler } from '../../src/mcp/handlers/analyze';
import { getCache } from '../../src/cache/store';
import {
  describeOrSkip,
  fixturesDir,
  hasTestBinary,
  integrationAvailable,
  integrationSkipReason,
  testBinary
} from './helpers';

const GHIDRA_PATH = process.env['GHIDRA_PATH'];

describeOrSkip('arael_analyze (integration)', () => {
  let connection: GhidraConnection;

  beforeAll(async () => {
    // Verify test binary exists
    if (!fs.existsSync(testBinary)) {
      console.warn(`Test binary not found: ${testBinary}`);
      console.warn('Run "cd tests/fixtures && make" to build test fixtures');
    }

    // Initialize connection
    const bridgePortValue = process.env['GHIDRA_BRIDGE_PORT'];
    const bridgePort = bridgePortValue ? parseInt(bridgePortValue, 10) : undefined;

    connection = getConnection({
      ghidraPath: GHIDRA_PATH ?? '',
      bridgeHost: process.env['GHIDRA_BRIDGE_HOST'],
      bridgePort,
      pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH']
    });

    try {
      await connection.connect();
    } catch (error) {
      console.warn('Could not connect to Ghidra:', error);
    }
  });

  afterAll(() => {
    // Clean up cache entries created during tests
    try {
      const cache = getCache();
      cache.invalidateAll();
    } catch {
      // Ignore cleanup errors
    }
  });

  it('should return valid analysis JSON for ELF binary', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await analyzeHandler({ filepath: testBinary });

    expect(result.metadata).toBeDefined();
    expect(result.metadata.araelVersion).toBe('2.4.0');
    expect(result.metadata.connectionMode).toMatch(/bridge|headless/);

    expect(result.binary).toBeDefined();
    expect(result.binary.format).toBe('ELF');
    expect(result.binary.architecture).toBe('x86_64');

    expect(result.functions).toBeInstanceOf(Array);
    expect(result.functions.length).toBeGreaterThan(0);

    // Should have a main function
    const main = result.functions.find(f => f.name === 'main');
    expect(main).toBeDefined();
  }, 120000); // 2 minute timeout for first analysis

  it('should reject non-existent file', async () => {
    await expect(
      analyzeHandler({ filepath: '/nonexistent/binary' })
    ).rejects.toThrow(/does not exist/i);
  });

  it('should reject non-ELF file', async () => {
    const textFile = path.join(fixturesDir, 'not_a_binary.txt');

    await expect(
      analyzeHandler({ filepath: textFile })
    ).rejects.toThrow(/not an ELF|unsupported/i);
  });

  it('should cache results by file hash', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    // First call - may take time
    const result1 = await analyzeHandler({ filepath: testBinary });

    // Second call - should be cached (fast)
    const startTime = Date.now();
    const result2 = await analyzeHandler({ filepath: testBinary });
    const duration = Date.now() - startTime;

    // Cached result should be fast (< 1 second)
    expect(duration).toBeLessThan(1000);

    // Should be marked as cached
    expect(result2.metadata.cached).toBe(true);

    // Analysis IDs should match (same cached result)
    expect(result1.metadata.analysisId).toBe(result2.metadata.analysisId);
  }, 120000);

  it('should bypass cache when force=true', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    // Ensure we have a cached result
    const result1 = await analyzeHandler({ filepath: testBinary });

    // Force re-analysis
    const result2 = await analyzeHandler({ filepath: testBinary, force: true });

    // Should have different analysis IDs (new analysis)
    expect(result1.metadata.analysisId).not.toBe(result2.metadata.analysisId);

    // Should not be marked as cached
    expect(result2.metadata.cached).toBe(false);
  }, 120000);
});

// Log skip reason
if (!integrationAvailable) {
  describe('arael_analyze (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
