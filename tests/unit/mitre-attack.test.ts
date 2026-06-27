/**
 * Tests for MITRE ATT&CK Mapping (src/analysis/mitre-mapper.ts).
 *
 * Exercises the real mapper: behaviors carrying a `mitreId` are resolved
 * against the technique database, tactics are aggregated, duplicate techniques
 * merge evidence and ramp confidence, and the lookup helpers behave.
 */

import {
  mapToATTACK,
  getTechniqueById,
  getTechniquesByTactic,
  getTactics,
  hasTechnique,
  getTechniqueCountByTactic,
  getAllTactics,
  getMITREDatabaseStats
} from '../../src/analysis/mitre-mapper';
import type { DetectedBehavior } from '../../src/analysis/behavior-detector';

function behavior(partial: Partial<DetectedBehavior> & Pick<DetectedBehavior, 'id'>): DetectedBehavior {
  return {
    category: 'execution',
    description: partial.description ?? `${partial.id} behavior`,
    evidence: [],
    riskLevel: 'medium',
    confidence: 0.8,
    ...partial
  };
}

describe('MITRE ATT&CK Mapping', () => {
  let mockBehaviors: DetectedBehavior[];

  beforeEach(() => {
    mockBehaviors = [
      behavior({
        id: 'process_injection',
        category: 'execution',
        evidence: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
        riskLevel: 'critical',
        confidence: 0.9,
        mitreId: 'T1055'
      }),
      behavior({
        id: 'persistence_registry',
        category: 'persistence',
        evidence: ['RegSetValueExA', 'CurrentVersion\\Run'],
        riskLevel: 'high',
        confidence: 0.85,
        mitreId: 'T1547.001'
      }),
      behavior({
        id: 'network_client',
        category: 'network',
        evidence: ['WSAStartup', 'connect', 'send'],
        riskLevel: 'medium',
        confidence: 0.7,
        mitreId: 'T1071'
      }),
      behavior({
        id: 'credential_theft',
        category: 'credential_access',
        evidence: ['CredEnumerateA', 'CryptUnprotectData'],
        riskLevel: 'critical',
        confidence: 0.88,
        mitreId: 'T1555'
      }),
      behavior({
        id: 'file_encryption',
        category: 'impact',
        evidence: ['CryptEncrypt', '.encrypted'],
        riskLevel: 'critical',
        confidence: 0.92,
        mitreId: 'T1486'
      })
    ];
  });

  describe('mapToATTACK', () => {
    it('returns the ATT&CK mapping structure', () => {
      const mapping = mapToATTACK(mockBehaviors);

      expect(mapping).toHaveProperty('tactics');
      expect(mapping).toHaveProperty('techniques');
      expect(mapping).toHaveProperty('summary');
      expect(Array.isArray(mapping.tactics)).toBe(true);
      expect(Array.isArray(mapping.techniques)).toBe(true);
      expect(typeof mapping.summary).toBe('string');
    });

    it('maps process injection to T1055 (Defense Evasion)', () => {
      const mapping = mapToATTACK([mockBehaviors[0]!]);

      const t1055 = mapping.techniques.find(t => t.id === 'T1055');
      expect(t1055).toBeDefined();
      expect(t1055?.name).toBe('Process Injection');
      expect(t1055?.tactic).toBe('Defense Evasion');
      expect(mapping.tactics).toContain('Defense Evasion');
    });

    it('maps registry persistence to T1547.001 (Persistence)', () => {
      const mapping = mapToATTACK([mockBehaviors[1]!]);

      expect(hasTechnique(mapping, 'T1547.001')).toBe(true);
      expect(mapping.tactics).toContain('Persistence');
    });

    it('maps network activity to a T1071 technique (Command and Control)', () => {
      const mapping = mapToATTACK([mockBehaviors[2]!]);

      expect(mapping.techniques.some(t => t.id.startsWith('T1071'))).toBe(true);
      expect(mapping.tactics).toContain('Command and Control');
    });

    it('maps credential theft to T1555 and file encryption to T1486', () => {
      const mapping = mapToATTACK([mockBehaviors[3]!, mockBehaviors[4]!]);

      expect(hasTechnique(mapping, 'T1555')).toBe(true);
      expect(hasTechnique(mapping, 'T1486')).toBe(true);
      expect(mapping.tactics).toEqual(expect.arrayContaining(['Credential Access', 'Impact']));
    });

    it('carries behavior evidence onto the mapped technique', () => {
      const mapping = mapToATTACK([mockBehaviors[0]!]);
      const t1055 = mapping.techniques.find(t => t.id === 'T1055');

      expect(t1055?.evidence).toEqual(
        expect.arrayContaining(['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'])
      );
    });

    it('preserves the behavior confidence on the technique', () => {
      const mapping = mapToATTACK([mockBehaviors[0]!]);
      const t1055 = mapping.techniques.find(t => t.id === 'T1055');

      expect(t1055?.confidence).toBeCloseTo(0.9);
    });

    it('merges duplicate techniques, deduping evidence and ramping confidence', () => {
      const mapping = mapToATTACK([
        behavior({ id: 'inj-a', evidence: ['VirtualAllocEx'], confidence: 0.8, mitreId: 'T1055' }),
        behavior({ id: 'inj-b', evidence: ['VirtualAllocEx', 'CreateRemoteThread'], confidence: 0.8, mitreId: 'T1055' })
      ]);

      const matches = mapping.techniques.filter(t => t.id === 'T1055');
      expect(matches).toHaveLength(1);
      const merged = matches[0]!;
      // Evidence deduplicated across both behaviors.
      expect(merged.evidence.sort()).toEqual(['CreateRemoteThread', 'VirtualAllocEx']);
      // Second occurrence bumps confidence by 0.1 (capped at 0.95).
      expect(merged.confidence).toBeCloseTo(0.9);
    });

    it('sorts techniques by descending confidence', () => {
      const mapping = mapToATTACK(mockBehaviors);
      const confidences = mapping.techniques.map(t => t.confidence);
      const sorted = [...confidences].sort((a, b) => b - a);
      expect(confidences).toEqual(sorted);
    });

    it('ignores behaviors without a known mitreId', () => {
      const mapping = mapToATTACK([
        behavior({ id: 'no-mitre', evidence: ['foo'] }),
        behavior({ id: 'unknown-mitre', evidence: ['bar'], mitreId: 'T9999' })
      ]);

      expect(mapping.techniques).toHaveLength(0);
      expect(mapping.tactics).toHaveLength(0);
    });

    it('returns an explicit summary when nothing maps', () => {
      const mapping = mapToATTACK([]);
      expect(mapping.techniques).toHaveLength(0);
      expect(mapping.summary).toBe('No MITRE ATT&CK techniques identified.');
    });

    it('summarises high-confidence mappings', () => {
      const mapping = mapToATTACK(mockBehaviors);
      // mockBehaviors has 5 techniques, four with confidence >= 0.8.
      expect(mapping.summary).toMatch(/ATT&CK technique/);
      expect(mapping.summary.length).toBeGreaterThan(0);
    });
  });

  describe('tactic aggregation', () => {
    it('collects every distinct tactic represented in the behaviors', () => {
      const mapping = mapToATTACK(mockBehaviors);
      expect(getTactics(mapping)).toEqual(
        expect.arrayContaining([
          'Defense Evasion',
          'Persistence',
          'Command and Control',
          'Credential Access',
          'Impact'
        ])
      );
    });

    it('counts techniques per tactic', () => {
      const mapping = mapToATTACK(mockBehaviors);
      const counts = getTechniqueCountByTactic(mapping);
      const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
      expect(total).toBe(mapping.techniques.length);
      expect(counts['Defense Evasion']).toBeGreaterThanOrEqual(1);
    });
  });

  describe('technique database lookups', () => {
    it('resolves a technique by id', () => {
      const tech = getTechniqueById('T1055');
      expect(tech).not.toBeNull();
      expect(tech?.name).toBe('Process Injection');
      expect(tech?.tactic).toBe('Defense Evasion');
      expect(tech?.url).toContain('attack.mitre.org');
    });

    it('returns null for an unknown technique id', () => {
      expect(getTechniqueById('T0000')).toBeNull();
    });

    it('lists techniques for a tactic case-insensitively', () => {
      const persistence = getTechniquesByTactic('persistence');
      expect(persistence.length).toBeGreaterThan(0);
      expect(persistence.every(t => t.tactic === 'Persistence')).toBe(true);
      expect(persistence.map(t => t.id)).toContain('T1547.001');
    });

    it('exposes the full tactic catalogue', () => {
      const tactics = getAllTactics();
      expect(tactics).toEqual(expect.arrayContaining(['Execution', 'Persistence', 'Impact']));
      // No duplicates.
      expect(new Set(tactics).size).toBe(tactics.length);
    });

    it('reports database statistics consistent with the catalogue', () => {
      const stats = getMITREDatabaseStats();
      expect(stats.totalTechniques).toBeGreaterThan(20);
      const summed = Object.values(stats.byTactic).reduce((sum, n) => sum + n, 0);
      expect(summed).toBe(stats.totalTechniques);
    });
  });
});
