/**
 * Integration tests for arael_strings tool
 * Requires: running Ghidra (bridge or headless)
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { stringsHandler } from '../../src/mcp/handlers/strings';
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

describeOrSkip('arael_strings (integration)', () => {
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

  it('should return strings array', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await stringsHandler({ filepath: testBinary });
    expect(Array.isArray(result)).toBe(true);
  });

  it('should respect minimum length', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await stringsHandler({ filepath: testBinary, minLength: 8 });
    expect(result.every((s) => s.length >= 8)).toBe(true);
  });

  it('should filter by encoding', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await stringsHandler({ filepath: testBinary, encoding: 'ascii' });
    expect(result.every((s) => s.encoding === 'ascii')).toBe(true);
  });
});

if (!integrationAvailable) {
  describe('arael_strings (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
