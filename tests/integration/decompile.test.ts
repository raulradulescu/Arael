/**
 * Integration tests for arael_decompile tool
 * Requires: GHIDRA_PATH environment variable or running ghidra-bridge
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { decompileHandler } from '../../src/mcp/handlers/decompile';
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

describeOrSkip('arael_decompile (integration)', () => {
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

  it('should decompile function by name', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await decompileHandler({
      filepath: testBinary,
      function: 'main'
    });

    expect(result.function).toBe('main');
    expect(result.pseudocode).toBeTruthy();
    expect(result.pseudocode).toContain('main');
    // Should have function body with braces
    expect(result.pseudocode).toMatch(/\{[\s\S]*\}/);
  });

  it('should decompile function by address', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    // Get main's address from cache
    const cache = getCache();
    const cached = cache.get(testBinary);

    if (!cached) {
      console.warn('Skipping: no cached analysis');
      return;
    }

    const main = cached.functions.find(f => f.name === 'main');
    if (!main) {
      console.warn('Skipping: main function not found');
      return;
    }

    const result = await decompileHandler({
      filepath: testBinary,
      function: main.address
    });

    expect(result.pseudocode).toBeTruthy();
  });

  it('should return error for non-existent function', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await decompileHandler({
      filepath: testBinary,
      function: 'this_function_does_not_exist_12345'
    });

    expect(result.pseudocode).toBeNull();
    expect(result.error).toMatch(/not found|does not exist/i);
  });
});

if (!integrationAvailable) {
  describe('arael_decompile (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
