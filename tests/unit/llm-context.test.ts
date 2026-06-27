/**
 * Tests for LLM analysis-context generation.
 *
 * Covers the umbrella builder (src/llm/context.ts -> buildAnalysisContext)
 * end-to-end, plus the two extractors it composes: IOC extraction
 * (src/analysis/ioc-extractor.ts) and behavior detection
 * (src/analysis/behavior-detector.ts).
 */

import { buildAnalysisContext } from '../../src/llm/context';
import { extractIOCs } from '../../src/analysis/ioc-extractor';
import { detectBehaviors } from '../../src/analysis/behavior-detector';
import type { AnalysisResult } from '../../src/output/schema';

const MALWARE_IMPORTS = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'connect', 'RegSetValueExA'];
const MALWARE_STRINGS = [
  'http://malicious-drop.xyz/payload.bin',
  '45.77.32.100',
  'c2.badactor.io',
  'HKEY_CURRENT_USER\\Software\\EvilCorp\\Run',
  'C:\\Users\\victim\\AppData\\Roaming\\dropper.exe'
];

function makeAnalysis(): AnalysisResult {
  return {
    binary: {
      filename: 'sample.exe',
      format: 'PE',
      architecture: 'x86_64',
      bits: 64,
      size: 102400
    },
    functions: [
      { name: 'main', address: '0x401000', size: 800, signature: 'int main()', isThunk: false, isExternal: false, callers: [], callees: [], pseudocode: null },
      { name: 'inject', address: '0x401400', size: 1200, signature: 'void inject()', isThunk: false, isExternal: false, callers: [], callees: [], pseudocode: null },
      { name: 'tiny', address: '0x401900', size: 16, signature: 'void tiny()', isThunk: false, isExternal: false, callers: [], callees: [], pseudocode: null },
      { name: 'thunk_connect', address: '0x401a00', size: 6, signature: 'thunk', isThunk: true, isExternal: false, callers: [], callees: [], pseudocode: null },
      { name: 'imp_connect', address: '0x401b00', size: 0, signature: 'extern', isThunk: false, isExternal: true, callers: [], callees: [], pseudocode: null }
    ],
    strings: MALWARE_STRINGS.map((value, i) => ({
      value,
      address: `0x40300${i}`,
      length: value.length,
      encoding: 'ascii',
      section: '.rodata',
      xrefs: []
    })),
    imports: MALWARE_IMPORTS.map((name, i) => ({
      name,
      library: 'kernel32.dll',
      address: `0x40400${i}`,
      ordinal: null
    })),
    exports: [],
    sections: []
  } as unknown as AnalysisResult;
}

describe('buildAnalysisContext', () => {
  it('classifies an injection-capable binary as malware', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    expect(ctx.classification.type).toBe('malware');
    expect(ctx.classification.malwareType).toBeDefined();
    expect(ctx.classification.confidence).toBeGreaterThanOrEqual(0.85);
    expect(ctx.classification.reasoning.length).toBeGreaterThan(0);
  });

  it('detects behaviors including process injection', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    expect(ctx.behaviors.length).toBeGreaterThan(0);
    expect(ctx.behaviors.some(b => b.id === 'process_injection')).toBe(true);
    // Evidence is capped at 5 entries per behavior.
    expect(ctx.behaviors.every(b => b.evidence.length <= 5)).toBe(true);
  });

  it('surfaces a critical/high risk assessment', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    expect(['high', 'critical']).toContain(ctx.riskAssessment.overall);
    expect(ctx.riskAssessment.criticalBehaviors.length).toBeGreaterThan(0);
  });

  it('extracts IOCs into the context', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    expect(ctx.iocs.ips).toContain('45.77.32.100');
    expect(ctx.iocs.urls).toContain('http://malicious-drop.xyz/payload.bin');
    expect(ctx.iocs.registryKeys.length).toBeGreaterThan(0);
  });

  it('maps to MITRE ATT&CK techniques (incl. T1055 from injection)', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    expect(ctx.mitreAttack.tactics.length).toBeGreaterThan(0);
    expect(ctx.mitreAttack.techniques.some(t => t.id === 'T1055')).toBe(true);
    expect(ctx.mitreAttack.summary.length).toBeGreaterThan(0);
  });

  it('selects key functions by size, excluding thunks and externals', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    const names = ctx.keyFunctions.map(f => f.name);
    expect(names).not.toContain('thunk_connect');
    expect(names).not.toContain('imp_connect');
    // Sorted by descending size: inject (1200) before main (800).
    expect(names[0]).toBe('inject');
    const sizes = ctx.keyFunctions.map(f => f.size);
    expect(sizes).toEqual([...sizes].sort((a, b) => b - a));
  });

  it('reports internally consistent statistics', () => {
    const analysis = makeAnalysis();
    const ctx = buildAnalysisContext(analysis);
    expect(ctx.stats.functions).toBe(analysis.functions.length);
    expect(ctx.stats.strings).toBe(analysis.strings.length);
    expect(ctx.stats.imports).toBe(analysis.imports.length);
    expect(ctx.stats.behaviorsDetected).toBe(ctx.raw.behaviors.length);
    expect(ctx.stats.techniquesMatched).toBe(ctx.raw.mitre.techniques.length);
  });

  it('produces actionable suggestions and a non-empty summary', () => {
    const ctx = buildAnalysisContext(makeAnalysis());
    expect(ctx.summary.length).toBeGreaterThan(0);
    expect(ctx.suggestedAnalysis.length).toBeGreaterThan(0);
    expect(ctx.suggestedAnalysis.length).toBeLessThanOrEqual(6);
    expect(ctx.suggestedAnalysis.some(s => /injection|WriteProcessMemory/i.test(s))).toBe(true);
  });

  it('classifies a benign binary with no malicious indicators', () => {
    const benign = makeAnalysis();
    (benign as unknown as { imports: Array<{ name: string }> }).imports = [{ name: 'printf' }, { name: 'malloc' }];
    (benign as unknown as { strings: Array<{ value: string }> }).strings = [{ value: 'Hello, world' } as never];
    const ctx = buildAnalysisContext(benign);
    expect(ctx.classification.type).not.toBe('malware');
    expect(ctx.behaviors.length).toBe(0);
  });
});

describe('extractIOCs', () => {
  it('extracts IPs, URLs, domains, registry keys and file paths', () => {
    const iocs = extractIOCs(MALWARE_STRINGS);
    expect(iocs.ips).toContain('45.77.32.100');
    expect(iocs.urls).toContain('http://malicious-drop.xyz/payload.bin');
    expect(iocs.domains).toContain('c2.badactor.io');
    expect(iocs.registryKeys.some(k => k.includes('HKEY_CURRENT_USER'))).toBe(true);
    expect(iocs.filePaths.some(p => p.includes('dropper.exe'))).toBe(true);
  });

  it('excludes loopback/placeholder IPs and domains', () => {
    const iocs = extractIOCs(['127.0.0.1', '0.0.0.0', 'example.com', 'localhost']);
    expect(iocs.ips).not.toContain('127.0.0.1');
    expect(iocs.ips).not.toContain('0.0.0.0');
    expect(iocs.domains).not.toContain('example.com');
  });

  it('returns empty collections for strings with no indicators', () => {
    const iocs = extractIOCs(['just some words', 'another harmless line']);
    expect(iocs.ips).toHaveLength(0);
    expect(iocs.urls).toHaveLength(0);
  });
});

describe('detectBehaviors', () => {
  it('detects process injection from the canonical API trio', () => {
    const behaviors = detectBehaviors(['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'], []);
    const injection = behaviors.find(b => b.id === 'process_injection');
    expect(injection).toBeDefined();
    expect(injection?.riskLevel).toBe('critical');
    expect(injection?.mitreId).toBe('T1055');
    expect(injection?.evidence.length).toBeGreaterThan(0);
  });

  it('detects network client activity', () => {
    const behaviors = detectBehaviors(['connect'], ['http://example-c2.io']);
    expect(behaviors.some(b => b.id === 'network_client')).toBe(true);
  });

  it('returns no behaviors for an empty binary', () => {
    expect(detectBehaviors([], [])).toEqual([]);
  });
});
