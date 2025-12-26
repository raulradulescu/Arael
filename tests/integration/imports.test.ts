/**
 * Integration tests for arael_imports tool
 * Requires: running Ghidra (bridge or headless)
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { importsHandler } from '../../src/mcp/handlers/imports';
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

describeOrSkip('arael_imports (integration)', () => {
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

  it('should return imports and grouped libraries', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await importsHandler({ filepath: testBinary });

    expect(Array.isArray(result.imports)).toBe(true);
    expect(Array.isArray(result.grouped)).toBe(true);
  });
});

if (!integrationAvailable) {
  describe('arael_imports (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
