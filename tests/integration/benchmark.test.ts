/**
 * Integration tests for arael benchmark.
 * Requires: GHIDRA_PATH environment variable or running ghidra-bridge.
 */

import { GhidraConnection, getConnection } from '../../src/ghidra/connection';
import { runBenchmark } from '../../src/benchmark/runner';
import { formatBenchmarkResult } from '../../src/benchmark/reporters';
import { getCache } from '../../src/cache/store';
import {
  describeOrSkip,
  hasTestBinary,
  testBinary
} from './helpers';

const GHIDRA_PATH = process.env['GHIDRA_PATH'];

describeOrSkip('arael benchmark (integration)', () => {
  let connection: GhidraConnection;

  beforeAll(async () => {
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
    } catch {
      // describeOrSkip already gates normal runs; keep the test file resilient.
    }
  });

  afterAll(() => {
    try {
      getCache().invalidateAll();
    } catch {
      // Ignore cleanup errors.
    }
  });

  it('produces benchmark records for the hello_world fixture', async () => {
    if (!hasTestBinary()) {
      return;
    }

    const result = await runBenchmark({
      target: testBinary,
      format: 'json',
      force: true,
      runs: 1,
      includeYara: false,
      withLlm: false
    });

    expect(result.records).toHaveLength(1);
    expect(result.records[0]?.analysisSuccess).toBe(true);
    expect(result.records[0]?.counts.functionsDetected).toBeGreaterThan(0);
    expect(formatBenchmarkResult(result, 'json')).toContain('"records"');
  }, 120000);
});
