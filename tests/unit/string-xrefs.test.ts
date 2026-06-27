/**
 * Tests for String Cross-Reference Analysis (src/analysis/string-xrefs.ts).
 *
 * Builds a minimal AnalysisResult (only functions + strings are read by this
 * module) and exercises the real function-centric and string-centric views,
 * suspicious-pattern detection, and xref statistics.
 */

import {
  getStringsUsedByFunction,
  getFunctionsUsingString,
  getStringUsageByFunction,
  findSuspiciousFunctions,
  getXrefStats
} from '../../src/analysis/string-xrefs';
import type { AnalysisResult, FunctionInfo, StringInfo } from '../../src/output/schema';

function fn(name: string, address: string): FunctionInfo {
  return {
    name,
    address,
    size: 64,
    signature: `void ${name}()`,
    isThunk: false,
    isExternal: false,
    callers: [],
    callees: [],
    pseudocode: null
  };
}

function str(value: string, address: string, refs: Array<[string, string, 'data' | 'code']>): StringInfo {
  return {
    value,
    address,
    length: value.length,
    encoding: 'ascii',
    section: '.rodata',
    xrefs: refs.map(([func, refAddr, type]) => ({ function: func, address: refAddr, type }))
  };
}

function makeAnalysis(): AnalysisResult {
  const functions = [fn('main', '0x401000'), fn('connect_c2', '0x401100'), fn('helper', '0x401200')];
  const strings = [
    str('http://evil.example.com/c2', '0x402000', [['connect_c2', '0x401120', 'data']]),
    str('192.168.1.50', '0x402010', [['connect_c2', '0x401130', 'data']]),
    str('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '0x402020', [['main', '0x401010', 'data']]),
    str('cmd.exe /c whoami', '0x402030', [['main', '0x401020', 'code']]),
    str('just a friendly status message', '0x402040', [['helper', '0x401210', 'data']]),
    str('orphan string with no refs', '0x402050', [])
  ];
  return { functions, strings } as unknown as AnalysisResult;
}

describe('String Cross-Reference Analysis', () => {
  let analysis: AnalysisResult;

  beforeEach(() => {
    analysis = makeAnalysis();
  });

  describe('getStringsUsedByFunction', () => {
    it('returns strings referenced by a function looked up by name', () => {
      const usage = getStringsUsedByFunction(analysis, 'connect_c2');
      expect(usage).not.toBeNull();
      expect(usage?.functionAddress).toBe('0x401100');
      expect(usage?.strings.map(s => s.value)).toEqual(
        expect.arrayContaining(['http://evil.example.com/c2', '192.168.1.50'])
      );
    });

    it('also resolves a function by address (with or without 0x)', () => {
      expect(getStringsUsedByFunction(analysis, '0x401100')?.functionName).toBe('connect_c2');
    });

    it('categorizes the referenced strings', () => {
      const usage = getStringsUsedByFunction(analysis, 'main');
      expect(usage?.categories.registryKeys.length).toBe(1);
      expect(usage?.categories.commands).toContain('cmd.exe /c whoami');
    });

    it('returns null for an unknown function', () => {
      expect(getStringsUsedByFunction(analysis, 'does_not_exist')).toBeNull();
    });
  });

  describe('getFunctionsUsingString', () => {
    it('finds functions referencing a string by case-insensitive substring', () => {
      const matches = getFunctionsUsingString(analysis, 'HTTP');
      expect(matches).toHaveLength(1);
      expect(matches[0]?.category).toBe('url');
      expect(matches[0]?.referencedBy.map(r => r.functionName)).toEqual(['connect_c2']);
    });

    it('supports regex matching', () => {
      const matches = getFunctionsUsingString(analysis, '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', true);
      expect(matches).toHaveLength(1);
      expect(matches[0]?.value).toBe('192.168.1.50');
      expect(matches[0]?.category).toBe('ip');
    });

    it('excludes strings that have no xrefs', () => {
      const matches = getFunctionsUsingString(analysis, 'orphan');
      expect(matches).toHaveLength(0);
    });
  });

  describe('getStringUsageByFunction', () => {
    it('includes every function and attributes strings to the referencing function', () => {
      const map = getStringUsageByFunction(analysis);
      expect(new Set(map.keys())).toEqual(new Set(['main', 'connect_c2', 'helper']));
      expect(map.get('connect_c2')?.strings).toHaveLength(2);
      expect(map.get('main')?.strings).toHaveLength(2);
      expect(map.get('helper')?.strings).toHaveLength(1);
    });
  });

  describe('findSuspiciousFunctions', () => {
    it('flags functions referencing suspicious strings with reasons', () => {
      const suspicious = findSuspiciousFunctions(analysis);
      const byName = new Map(suspicious.map(s => [s.functionName, s]));

      expect(byName.has('connect_c2')).toBe(true);
      expect(byName.has('main')).toBe(true);
      // helper only references a benign string.
      expect(byName.has('helper')).toBe(false);

      expect(byName.get('connect_c2')?.reason).toMatch(/URL reference|IP address/);
      expect(byName.get('main')?.reason).toMatch(/Registry access|Shell execution/);
    });
  });

  describe('getXrefStats', () => {
    it('reports consistent cross-reference statistics', () => {
      const stats = getXrefStats(analysis);
      expect(stats.totalStrings).toBe(6);
      expect(stats.stringsWithXrefs).toBe(5);
      expect(stats.totalXrefs).toBe(5);
      expect(stats.functionsWithStrings).toBe(3);
      expect(stats.topFunctions[0]?.stringCount).toBeGreaterThanOrEqual(
        stats.topFunctions[stats.topFunctions.length - 1]?.stringCount ?? 0
      );
    });
  });
});
