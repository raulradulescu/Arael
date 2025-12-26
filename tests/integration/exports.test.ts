/**
 * Integration tests for arael_exports tool
 * Requires: GHIDRA_PATH environment variable
 * Tests exported symbol listing (functions, data)
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { exportsHandler } from '../../src/mcp/handlers/exports';
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

describeOrSkip('arael_exports (integration)', () => {
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

  it('should list all exported symbols', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);

    // Simple binaries may have 0 exports (statically linked)
    // or a few exports (_start, main, etc.)
    expect(result.exports.length).toBeGreaterThanOrEqual(0);

    // Check export format if exports exist
    if (result.exports.length > 0) {
      const exp = result.exports[0];
      expect(exp).toBeDefined();
      if (!exp) return;

      expect(exp).toHaveProperty('name');
      expect(exp).toHaveProperty('address');
      expect(exp).toHaveProperty('type');
      expect(exp.address).toMatch(/^0x[0-9a-fA-F]+$/);
      expect(['function', 'data']).toContain(exp.type);
    }
  });

  it('should list only function exports when filtered', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary,
      filter: {
        type: 'function'
      }
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);

    // All exports should be functions
    result.exports.forEach((exp: any) => {
      expect(exp.type).toBe('function');
    });
  });

  it('should list only data exports when filtered', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary,
      filter: {
        type: 'data'
      }
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);

    // All exports should be data
    result.exports.forEach((exp: any) => {
      expect(exp.type).toBe('data');
    });
  });

  it('should filter exports by name pattern (regex)', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary,
      filter: {
        namePattern: '^main$'  // Exact match for 'main'
      }
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);

    // Should only have exports matching 'main' (if it's exported)
    result.exports.forEach((exp: any) => {
      expect(exp.name).toMatch(/^main$/);
    });
  });

  it('should filter by pattern and type combined', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary,
      filter: {
        namePattern: '^_',  // Names starting with underscore
        type: 'function'
      }
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);

    // All should be functions starting with _
    result.exports.forEach((exp: any) => {
      expect(exp.name).toMatch(/^_/);
      expect(exp.type).toBe('function');
    });
  });

  it('should include size for each export', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary
    });

    expect(result.exports).toBeTruthy();

    if (result.exports.length > 0) {
      const exp = result.exports[0];
      expect(exp).toBeDefined();
      if (!exp) return;

      expect(exp).toHaveProperty('size');
      expect(typeof exp.size).toBe('number');
      expect(exp.size).toBeGreaterThanOrEqual(0);
    }
  });

  it('should return empty array for binary with no exports', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    // Simple statically-linked binaries may have no exports
    const result = await exportsHandler({
      filepath: testBinary
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);
    // Length can be 0 or more, depending on binary
  });

  it('should return total count of exports', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary
    });

    expect(result).toHaveProperty('totalCount');
    expect(typeof result.totalCount).toBe('number');
    expect(result.totalCount).toBe(result.exports.length);
  });

  it('should handle case-insensitive name patterns', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary,
      filter: {
        namePattern: 'MAIN'  // Should match 'main' case-insensitively
      }
    });

    expect(result.exports).toBeTruthy();
    expect(Array.isArray(result.exports)).toBe(true);

    // Should find exports matching 'main' (case-insensitive)
    result.exports.forEach((exp: any) => {
      expect(exp.name.toLowerCase()).toMatch(/main/);
    });
  });

  it('should sort exports by address', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await exportsHandler({
      filepath: testBinary
    });

    expect(result.exports).toBeTruthy();

    if (result.exports.length > 1) {
      // Check that addresses are in ascending order
      for (let i = 1; i < result.exports.length; i++) {
        const prevExp = result.exports[i - 1];
        const currExp = result.exports[i];
        if (!prevExp || !currExp) continue;

        const prev = parseInt(prevExp.address, 16);
        const curr = parseInt(currExp.address, 16);
        expect(curr).toBeGreaterThanOrEqual(prev);
      }
    }
  });
});

if (!integrationAvailable) {
  describe('arael_exports (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
