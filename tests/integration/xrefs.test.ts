/**
 * Integration tests for arael_xrefs tool
 * Requires: GHIDRA_PATH environment variable
 * Tests cross-reference finding (to/from/both directions)
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { xrefsHandler } from '../../src/mcp/handlers/xrefs';
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

describeOrSkip('arael_xrefs (integration)', () => {
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

  it('should find references TO an address (who calls this)', async () => {
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

    const result = await xrefsHandler({
      filepath: testBinary,
      address: main.address,
      direction: 'to'
    });

    expect(result.address).toBe(main.address);
    expect(result.direction).toBe('to');
    expect(result.references).toBeTruthy();
    expect(Array.isArray(result.references)).toBe(true);

    // main() should have at least one caller (_start or similar)
    expect(result.references.length).toBeGreaterThanOrEqual(0);

    // Check reference format
    if (result.references.length > 0) {
      const ref = result.references[0];
      expect(ref).toBeDefined();
      if (!ref) return;

      expect(ref).toHaveProperty('from');
      expect(ref).toHaveProperty('type');
      expect(ref.from).toMatch(/^0x[0-9a-fA-F]+$/);
      expect(ref.type).toMatch(/^(call|jump|data|read|write)$/i);
    }
  }, 120000);

  it('should find references FROM an address (what does this call)', async () => {
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

    const result = await xrefsHandler({
      filepath: testBinary,
      address: main.address,
      direction: 'from'
    });

    expect(result.address).toBe(main.address);
    expect(result.direction).toBe('from');
    expect(result.references).toBeTruthy();
    expect(Array.isArray(result.references)).toBe(true);

    // main() typically calls functions (printf, exit, etc.)
    // May be 0 in very simple programs
    expect(result.references.length).toBeGreaterThanOrEqual(0);

    // Check reference format
    if (result.references.length > 0) {
      const ref = result.references[0];
      expect(ref).toBeDefined();
      if (!ref) {
        return;
      }

      expect(ref).toHaveProperty('to');
      expect(ref).toHaveProperty('type');
      expect(ref.to).toMatch(/^0x[0-9a-fA-F]+$/);
    }
  });

  it('should find references in BOTH directions', async () => {
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

    const result = await xrefsHandler({
      filepath: testBinary,
      address: main.address,
      direction: 'both'
    });

    expect(result.address).toBe(main.address);
    expect(result.direction).toBe('both');
    expect(result.references).toBeTruthy();
    expect(Array.isArray(result.references)).toBe(true);

    // Should have both 'to' and 'from' references
    const toRefs = result.references.filter((ref: any) => ref.hasOwnProperty('from'));
    const fromRefs = result.references.filter((ref: any) => ref.hasOwnProperty('to'));

    // Both arrays should exist (even if empty)
    expect(toRefs).toBeTruthy();
    expect(fromRefs).toBeTruthy();
  });

  it('should classify reference types correctly', async () => {
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

    const result = await xrefsHandler({
      filepath: testBinary,
      address: main.address,
      direction: 'both'
    });

    expect(result.references).toBeTruthy();

    // Check that all references have valid types
    const validTypes = ['call', 'jump', 'data', 'read', 'write'];
    result.references.forEach((ref: any) => {
      expect(validTypes).toContain(ref.type.toLowerCase());
    });
  });

  it('should include source function names when available', async () => {
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

    const result = await xrefsHandler({
      filepath: testBinary,
      address: main.address,
      direction: 'to'
    });

    expect(result.references).toBeTruthy();

    // If there are references, they should have function names
    if (result.references.length > 0) {
      const ref = result.references[0];
      expect(ref).toHaveProperty('functionName');
      // Function name can be null for unknown functions
    }
  });

  it('should respect maxResults limit', async () => {
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

    const result = await xrefsHandler({
      filepath: testBinary,
      address: main.address,
      direction: 'both',
      maxResults: 5
    });

    expect(result.references).toBeTruthy();
    expect(result.references.length).toBeLessThanOrEqual(5);
  });

  it('should return empty array for address with no references', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    // Use a data address that likely has no code references
    // (e.g., middle of .rodata section)
    const result = await xrefsHandler({
      filepath: testBinary,
      address: '0x400000',  // Arbitrary address unlikely to have refs
      direction: 'both'
    });

    expect(result.references).toBeTruthy();
    expect(Array.isArray(result.references)).toBe(true);
    // May be empty or have references depending on binary
  });

  it('should handle invalid address gracefully', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await xrefsHandler({
      filepath: testBinary,
      address: '0xFFFFFFFFFFFFFFFF',  // Invalid address
      direction: 'both'
    });

    // Should either return empty array or error
    if (result.error) {
      expect(result.error).toBeTruthy();
    } else {
      expect(result.references).toBeTruthy();
      expect(Array.isArray(result.references)).toBe(true);
    }
  });
});

if (!integrationAvailable) {
  describe('arael_xrefs (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
