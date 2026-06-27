/**
 * Tests for the Import Capability Database (src/analysis/import-database.ts).
 *
 * Exercises the real lookup/aggregation API: case-insensitive metadata lookup
 * (incl. aliases), capability bucketing, risk scoring, category filtering,
 * MITRE technique extraction, and database statistics.
 */

import {
  getImportMetadata,
  categorizeImportsByCapability,
  assessImportRisk,
  getImportsByCategory,
  getMITRETechniquesFromImports,
  getDatabaseStats
} from '../../src/analysis/import-database';

describe('Import Capability Database', () => {
  describe('getImportMetadata', () => {
    it('looks up a function case-insensitively', () => {
      const lower = getImportMetadata('virtualallocex');
      const mixed = getImportMetadata('VirtualAllocEx');

      expect(lower).not.toBeNull();
      expect(mixed).not.toBeNull();
      expect(mixed?.name).toBe('virtualallocex');
      expect(mixed).toEqual(lower);
    });

    it('returns the documented capability/risk/mitre metadata', () => {
      const meta = getImportMetadata('VirtualAllocEx');
      expect(meta?.capabilities).toEqual(expect.arrayContaining(['Memory', 'Injection']));
      expect(meta?.riskLevel).toBe('critical');
      expect(meta?.category).toBe('injection');
      expect(meta?.mitreId).toBe('T1055');
    });

    it('resolves aliases to their canonical entry', () => {
      const alias = getImportMetadata('URLDownloadToFileA');
      const canonical = getImportMetadata('urldownloadtofile');
      expect(alias).not.toBeNull();
      expect(alias).toEqual(canonical);
    });

    it('returns null for unknown functions', () => {
      expect(getImportMetadata('definitely_not_a_real_import_xyz')).toBeNull();
    });
  });

  describe('categorizeImportsByCapability', () => {
    it('buckets imports under each of their capabilities', () => {
      const result = categorizeImportsByCapability(['socket', 'connect', 'VirtualAllocEx']);

      expect(result.get('Network')).toEqual(expect.arrayContaining(['socket', 'connect']));
      expect(result.get('Memory')).toEqual(['VirtualAllocEx']);
      expect(result.get('Injection')).toEqual(['VirtualAllocEx']);
    });

    it('ignores imports that are not in the database', () => {
      const result = categorizeImportsByCapability(['connect', 'totally_unknown_fn']);
      const all = Array.from(result.values()).flat();
      expect(all).toContain('connect');
      expect(all).not.toContain('totally_unknown_fn');
    });

    it('returns an empty map when nothing matches', () => {
      const result = categorizeImportsByCapability(['nope_1', 'nope_2']);
      expect(result.size).toBe(0);
    });
  });

  describe('assessImportRisk', () => {
    it('scores a benign import set as low risk', () => {
      const assessment = assessImportRisk(['select', 'getsockopt']);
      expect(assessment.overallRisk).toBe('low');
      expect(assessment.score).toBeLessThan(10);
      expect(assessment.riskFactors).toHaveLength(0);
    });

    it('escalates to critical and lists factors for many dangerous imports', () => {
      const assessment = assessImportRisk([
        'VirtualAllocEx',
        'WriteProcessMemory',
        'VirtualProtectEx',
        'NtWriteVirtualMemory',
        'system'
      ]);
      // Five critical imports x weight 10 = 50 -> critical.
      expect(assessment.score).toBeGreaterThanOrEqual(50);
      expect(assessment.overallRisk).toBe('critical');
      expect(assessment.riskFactors.length).toBeGreaterThan(0);
      expect(assessment.riskFactors.some(f => f.startsWith('Critical:'))).toBe(true);
    });

    it('ignores unknown imports when scoring', () => {
      const known = assessImportRisk(['VirtualAllocEx']);
      const withNoise = assessImportRisk(['VirtualAllocEx', 'unknown_fn_a', 'unknown_fn_b']);
      expect(withNoise.score).toBe(known.score);
    });
  });

  describe('getImportsByCategory', () => {
    it('returns only metadata in the requested category', () => {
      const injection = getImportsByCategory(['socket', 'VirtualAllocEx', 'WriteProcessMemory'], 'injection');
      expect(injection.length).toBeGreaterThanOrEqual(2);
      expect(injection.every(m => m.category === 'injection')).toBe(true);
      expect(injection.map(m => m.name)).toEqual(
        expect.arrayContaining(['virtualallocex', 'writeprocessmemory'])
      );
    });
  });

  describe('getMITRETechniquesFromImports', () => {
    it('groups imports by their MITRE technique id', () => {
      const techniques = getMITRETechniquesFromImports(['VirtualAllocEx', 'WriteProcessMemory', 'connect']);
      expect(techniques.get('T1055')).toEqual(
        expect.arrayContaining(['VirtualAllocEx', 'WriteProcessMemory'])
      );
      expect(techniques.get('T1071')).toEqual(['connect']);
    });

    it('omits imports without a mapped technique', () => {
      const techniques = getMITRETechniquesFromImports(['socket']);
      // socket has no mitreId in the database.
      expect(techniques.has('T1071')).toBe(false);
    });
  });

  describe('getDatabaseStats', () => {
    it('reports a populated, internally consistent database', () => {
      const stats = getDatabaseStats();
      expect(stats.totalFunctions).toBeGreaterThan(100);

      const categorySum = Object.values(stats.byCategory).reduce((sum, n) => sum + n, 0);
      const riskSum = Object.values(stats.byRisk).reduce((sum, n) => sum + n, 0);
      expect(categorySum).toBe(stats.totalFunctions);
      expect(riskSum).toBe(stats.totalFunctions);

      expect(stats.byRisk).toHaveProperty('critical');
      expect(stats.withMitre).toBeGreaterThan(0);
      expect(stats.withMitre).toBeLessThanOrEqual(stats.totalFunctions);
    });
  });
});
