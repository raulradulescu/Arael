/**
 * Integration tests for arael_disassemble tool
 * Requires: GHIDRA_PATH environment variable
 * Tests disassembly extraction for functions and address ranges
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { disassembleHandler } from '../../src/mcp/handlers/disassemble';
import { analyzeHandler } from '../../src/mcp/handlers/analyze';
import { getCache } from '../../src/cache/store';
import {
  describeOrSkip,
  hasTestBinary,
  integrationAvailable,
  integrationSkipReason,
  testBinary
} from './helpers';

describeOrSkip('arael_disassemble (integration)', () => {
  beforeAll(async () => {
    if (!fs.existsSync(testBinary)) {
      console.warn(`Test binary not found: ${testBinary}`);
      return;
    }

    // Read env vars INSIDE beforeAll to ensure .env is loaded
    const ghidraPath = process.env['GHIDRA_PATH'] ?? '';
    const bridgePortValue = process.env['GHIDRA_BRIDGE_PORT'];
    const bridgePort = bridgePortValue ? parseInt(bridgePortValue, 10) : undefined;
    const connection = getConnection({
      ghidraPath,
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

  it('should disassemble function by name', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await disassembleHandler({
      filepath: testBinary,
      function: 'main'
    });

    expect(result.function).toBe('main');
    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    expect(Array.isArray(result.instructions)).toBe(true);
    expect(result.instructions.length).toBeGreaterThan(0);

    // Check instruction format
    const firstInst = result.instructions[0];
    expect(firstInst).toBeDefined();
    if (!firstInst) return;

    expect(firstInst).toHaveProperty('address');
    expect(firstInst).toHaveProperty('mnemonic');
    expect(firstInst).toHaveProperty('operands');

    // Should have valid address format
    expect(firstInst.address).toMatch(/^0x[0-9a-fA-F]+$/);
  }, 120000);

  it('should disassemble function by address', async () => {
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

    const result = await disassembleHandler({
      filepath: testBinary,
      function: main.address
    });

    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    expect(Array.isArray(result.instructions)).toBe(true);
    expect(result.instructions.length).toBeGreaterThan(0);
  });

  it('should include raw bytes when requested', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await disassembleHandler({
      filepath: testBinary,
      function: 'main',
      includeBytes: true
    });

    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    const firstInst = result.instructions[0];
    expect(firstInst).toBeDefined();
    if (!firstInst) return;

    expect(firstInst).toHaveProperty('bytes');
    expect(firstInst.bytes).toBeTruthy();
    // Bytes should be hex string (e.g., "55 48 89 e5")
    expect(firstInst.bytes).toMatch(/^[0-9a-fA-F\s]+$/);
  });

  it('should exclude bytes when not requested', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await disassembleHandler({
      filepath: testBinary,
      function: 'main',
      includeBytes: false
    });

    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    const firstInst = result.instructions[0];
    if (!firstInst) return;

    expect(firstInst.bytes).toBeUndefined();
  });

  it('should include cross-references when requested', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await disassembleHandler({
      filepath: testBinary,
      function: 'main',
      includeReferences: true
    });

    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    // Find CALL instructions which should have xrefs
    const callInsts = result.instructions.filter(
      (inst: any) => inst.mnemonic.toLowerCase().includes('call')
    );

    if (callInsts.length > 0) {
      const callInst = callInsts[0];
      if (!callInst) return;

      // Should have references array (may be empty)
      expect(callInst).toHaveProperty('references');
      expect(Array.isArray(callInst.references)).toBe(true);
    }
  });

  it('should disassemble address range', async () => {
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

    const result = await disassembleHandler({
      filepath: testBinary,
      startAddress: main.address,
      length: 64  // Disassemble first 64 bytes
    });

    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    expect(Array.isArray(result.instructions)).toBe(true);
    expect(result.instructions.length).toBeGreaterThan(0);
    expect(result.instructions.length).toBeLessThanOrEqual(64); // ~64 bytes of instructions
  });

  it('should return error for non-existent function', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await disassembleHandler({
      filepath: testBinary,
      function: 'this_function_does_not_exist_12345'
    });

    expect(result.instructions).toBeNull();
    expect(result.error).toMatch(/not found|does not exist/i);
  });

  it('should match standard disassembly format', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await disassembleHandler({
      filepath: testBinary,
      function: 'main',
      includeBytes: true
    });

    expect(result.instructions).toBeTruthy();
    if (!result.instructions) return;

    // Check each instruction has required fields
    result.instructions.forEach((inst: any) => {
      expect(inst).toHaveProperty('address');
      expect(inst).toHaveProperty('mnemonic');
      expect(inst).toHaveProperty('operands');

      // Mnemonic should be valid x86 instruction (all caps or lowercase)
      expect(inst.mnemonic).toMatch(/^[A-Z0-9]+$/i);
    });
  });
});

if (!integrationAvailable) {
  describe('arael_disassemble (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
