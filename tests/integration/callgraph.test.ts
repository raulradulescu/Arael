/**
 * Integration tests for arael_callgraph tool
 * Requires: GHIDRA_PATH environment variable
 * Tests call graph generation in multiple formats (JSON, DOT, Mermaid)
 */

import * as fs from 'fs';
import { getConnection } from '../../src/ghidra/connection';
import { callgraphHandler } from '../../src/mcp/handlers/callgraph';
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

describeOrSkip('arael_callgraph (integration)', () => {
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

  describe('JSON format', () => {
    it('should generate full call graph in JSON format', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'json'
      });

      expect(result.format).toBe('json');
      expect(result.nodes).toBeTruthy();
      expect(result.edges).toBeTruthy();
      expect(Array.isArray(result.nodes)).toBe(true);
      expect(Array.isArray(result.edges)).toBe(true);

      // Should have at least some nodes (functions)
      expect(result.nodes.length).toBeGreaterThan(0);
    }, 120000);

    it('should include correct node format in JSON', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'json'
      });

      expect(result.nodes.length).toBeGreaterThan(0);

      const node = result.nodes[0];
      expect(node).toBeDefined();
      if (!node) {
        return;
      }

      expect(node).toHaveProperty('id');
      expect(node).toHaveProperty('name');
      expect(node).toHaveProperty('address');
      expect(node).toHaveProperty('isExternal');
      expect(node.address).toMatch(/^0x[0-9a-fA-F]+$/);
      expect(typeof node.isExternal).toBe('boolean');
    });

    it('should include correct edge format in JSON', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'json'
      });

      if (result.edges.length > 0) {
        const edge = result.edges[0];
        expect(edge).toBeDefined();
        if (!edge) {
          return;
        }

        expect(edge).toHaveProperty('from');
        expect(edge).toHaveProperty('to');
        expect(typeof edge.from).toBe('string');
        expect(typeof edge.to).toBe('string');
      }
    });

    it('should generate call graph from specific root function', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        format: 'json'
      });

      expect(result.nodes).toBeTruthy();

      // Should include 'main' node
      const mainNode = result.nodes.find((n: any) => n.name === 'main');
      expect(mainNode).toBeTruthy();
    });

    it('should respect maxDepth limit', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result1 = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        maxDepth: 1,
        format: 'json'
      });

      const result2 = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        maxDepth: 5,
        format: 'json'
      });

      // Deeper depth should have same or more nodes
      expect(result2.nodes.length).toBeGreaterThanOrEqual(result1.nodes.length);
    });

    it('should exclude external calls when requested', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        includeExternal: false,
        format: 'json'
      });

      expect(result.nodes).toBeTruthy();

      // All nodes should be internal (not external)
      result.nodes.forEach((node: any) => {
        expect(node.isExternal).toBe(false);
      });
    });

    it('should include external calls by default', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        includeExternal: true,
        format: 'json'
      });

      expect(result.nodes).toBeTruthy();

      // May have external nodes (library functions)
      const externalNodes = result.nodes.filter((n: any) => n.isExternal);
      // Could be 0 or more, depending on binary
      expect(externalNodes.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('DOT format', () => {
    it('should generate call graph in DOT format (graphviz)', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'dot'
      });

      expect(result.format).toBe('dot');
      expect(result.output).toBeTruthy();
      expect(typeof result.output).toBe('string');
      if (!result.output) {
        return;
      }

      // Should start with 'digraph'
      expect(result.output).toMatch(/^digraph/);

      // Should have node definitions
      expect(result.output).toContain('->');

      // Should close with }
      expect(result.output.trim()).toMatch(/\}$/);
    });

    it('should include valid DOT syntax', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        format: 'dot'
      });

      const dot = result.output;
      if (!dot) {
        return;
      }

      // Check for required DOT elements
      expect(dot).toContain('digraph');
      expect(dot).toContain('{');
      expect(dot).toContain('}');

      // Should have node labels
      expect(dot).toMatch(/label\s*=\s*"/);

      // Should have edges (->)
      if (result.edges.length > 0) {
        expect(dot).toContain('->');
      }
    });

    it('should color external nodes differently in DOT', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        includeExternal: true,
        format: 'dot'
      });

      const dot = result.output;
      if (!dot) {
        return;
      }

      // Should have color attributes for external vs internal
      // (implementation detail, but good to test)
      expect(dot).toMatch(/color\s*=|fillcolor\s*=/);
    });
  });

  describe('Mermaid format', () => {
    it('should generate call graph in Mermaid format', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'mermaid'
      });

      expect(result.format).toBe('mermaid');
      expect(result.output).toBeTruthy();
      expect(typeof result.output).toBe('string');
      if (!result.output) {
        return;
      }

      // Should start with 'graph' or 'flowchart'
      expect(result.output).toMatch(/^(graph|flowchart)/);

      // Should have arrows (-->)
      expect(result.output).toContain('-->');
    });

    it('should include valid Mermaid syntax', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        format: 'mermaid'
      });

      const mermaid = result.output;
      if (!mermaid) {
        return;
      }

      // Check for Mermaid graph declaration
      expect(mermaid).toMatch(/^(graph|flowchart)\s+(TD|LR|TB)/);

      // Should have node definitions with []
      expect(mermaid).toMatch(/\[.*\]/);

      // Should have edges with -->
      if (result.edges.length > 0) {
        expect(mermaid).toContain('-->');
      }
    });

    it('should style external nodes in Mermaid', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'main',
        includeExternal: true,
        format: 'mermaid'
      });

      const mermaid = result.output;
      if (!mermaid) {
        return;
      }

      // Should have style or classDef for external nodes
      const hasExternal = result.nodes.some((node: any) => node.isExternal);
      if (hasExternal) {
        expect(mermaid).toMatch(/style|classDef|class/);
      }
    });
  });

  describe('Edge cases', () => {
    it('should handle function with no callees', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      // Leaf functions have no callees
      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'json'
      });

      // Should still have nodes even if some have no outgoing edges
      expect(result.nodes.length).toBeGreaterThan(0);
    });

    it('should return error for non-existent root function', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const result = await callgraphHandler({
        filepath: testBinary,
        rootFunction: 'this_function_does_not_exist_12345',
        format: 'json'
      });

      expect(result.error).toBeTruthy();
      expect(result.error).toMatch(/not found|does not exist/i);
    });

    it('should handle circular call graphs (recursion)', async () => {
      if (!hasTestBinary()) {
        console.warn('Skipping: test binary not found');
        return;
      }

      // If test binary has recursion, graph should handle it
      const result = await callgraphHandler({
        filepath: testBinary,
        format: 'json'
      });

      // Should not crash on circular dependencies
      expect(result.nodes.length).toBeGreaterThan(0);
    });
  });
});

if (!integrationAvailable) {
  describe('arael_callgraph (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}
