/**
 * Integration tests for arael_functions tool
 * Requires: GHIDRA_PATH environment variable or running ghidra-bridge
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { functionsHandler } from '../../src/mcp/handlers/functions';
import { analyzeHandler } from '../../src/mcp/handlers/analyze';
import { getCache } from '../../src/cache/store';
import {
  describeOrSkip,
  hasTestBinary,
  integrationAvailable,
  integrationSkipReason,
  testBinary
} from './helpers';

const GHIDRA_PATH = process.env['GHIDRA_PATH'];

describeOrSkip('arael_functions (integration)', () => {
  beforeAll(async () => {
    if (!fs.existsSync(testBinary)) {
      console.warn(`Test binary not found: ${testBinary}`);
      return;
    }

    const bridgePortValue = process.env['GHIDRA_BRIDGE_PORT'];
    const bridgePort = bridgePortValue ? parseInt(bridgePortValue, 10) : undefined;
    const connection = getConnection({
      ghidraPath: GHIDRA_PATH ?? '',
      bridgeHost: process.env['GHIDRA_BRIDGE_HOST'],
      bridgePort,
      pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH']
    });

    await connection.connect();

    // Pre-analyze to populate cache
    await analyzeHandler({ filepath: testBinary });
  }, 120000);

  afterAll(() => {
    try {
      const cache = getCache();
      cache.invalidateAll();
    } catch {
      // Ignore
    }
  });

  it('should return array of function objects', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await functionsHandler({ filepath: testBinary });

    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);

    // Each function should have required fields
    const func = result[0];
    expect(func).toHaveProperty('name');
    expect(func).toHaveProperty('address');
    expect(func).toHaveProperty('size');
    expect(func).toHaveProperty('signature');
  });

  it('should filter by name pattern', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await functionsHandler({
      filepath: testBinary,
      filter: { namePattern: '^main$' }
    });

    expect(result.length).toBe(1);
    expect(result[0]?.name).toBe('main');
  });

  it('should filter by name pattern (regex)', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await functionsHandler({
      filepath: testBinary,
      filter: { namePattern: '_start|main' }
    });

    expect(result.length).toBeGreaterThanOrEqual(1);
    const names = result.map(f => f.name);
    expect(names.some(n => n === 'main' || n === '_start')).toBe(true);
  });

  it('should exclude thunk functions', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const allFunctions = await functionsHandler({ filepath: testBinary });
    const withoutThunks = await functionsHandler({
      filepath: testBinary,
      filter: { excludeThunks: true }
    });

    // Should have fewer or equal functions when excluding thunks
    expect(withoutThunks.length).toBeLessThanOrEqual(allFunctions.length);

    // No thunks in result
    const hasThunks = withoutThunks.some(f => f.isThunk);
    expect(hasThunks).toBe(false);
  });

  it('should exclude external functions', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const withoutExternal = await functionsHandler({
      filepath: testBinary,
      filter: { excludeExternal: true }
    });

    // No external functions in result
    const hasExternal = withoutExternal.some(f => f.isExternal);
    expect(hasExternal).toBe(false);
  });

  it('should filter by size', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await functionsHandler({
      filepath: testBinary,
      filter: { minSize: 10, maxSize: 1000 }
    });

    // All functions should be within size range
    for (const func of result) {
      expect(func.size).toBeGreaterThanOrEqual(10);
      expect(func.size).toBeLessThanOrEqual(1000);
    }
  });
});

if (!integrationAvailable) {
  describe('arael_functions (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
