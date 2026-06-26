import type { AnalysisResult } from '../output/schema';
import { extractIOCs, countIOCs } from '../analysis/ioc-extractor';
import { detectBehaviors, assessBehaviorRisk, classifyBinaryType, type DetectedBehavior } from '../analysis/behavior-detector';
import { mapToATTACK, type ATTACKMapping } from '../analysis/mitre-mapper';
import { assessImportRisk } from '../analysis/import-database';

export interface AraelAnalysisContext {
  summary: string;
  classification: {
    type: string;
    malwareType?: string;
    confidence: number;
    reasoning: string[];
  };
  binary: {
    filename: string;
    format: string;
    architecture: string;
    bits?: number;
    size: number;
    isPacked: boolean;
    entropy?: number;
  };
  behaviors: Array<{
    id: string;
    category: string;
    description: string;
    riskLevel: string;
    evidence: string[];
  }>;
  riskAssessment: {
    overall: string;
    importRisk: string;
    criticalBehaviors: string[];
  };
  iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    registryKeys: string[];
    filePaths: string[];
  };
  mitreAttack: {
    tactics: string[];
    techniques: Array<{
      id: string;
      name: string;
      confidence: number;
    }>;
    summary: string;
  };
  keyFunctions: Array<{
    name: string;
    address: string;
    size: number;
  }>;
  suggestedAnalysis: string[];
  stats: {
    functions: number;
    strings: number;
    imports: number;
    behaviorsDetected: number;
    iocsFound: number;
    techniquesMatched: number;
  };
  raw: {
    behaviors: DetectedBehavior[];
    mitre: ATTACKMapping;
    iocs: ReturnType<typeof extractIOCs>;
  };
}

export function buildAnalysisContext(result: AnalysisResult): AraelAnalysisContext {
  const importNames = result.imports.map(i => i.name);
  const stringValues = result.strings.map(s => s.value);
  const behaviors = detectBehaviors(importNames, stringValues);
  const behaviorRisk = assessBehaviorRisk(behaviors);
  const classification = classifyBinaryType(behaviors);
  const iocs = extractIOCs(stringValues);
  const mitreMapping = mapToATTACK(behaviors);
  const importRisk = assessImportRisk(importNames);

  return {
    summary: generateContextSummary(result, classification, behaviorRisk),
    classification: {
      type: classification.classification,
      malwareType: classification.malwareType,
      confidence: classification.confidence,
      reasoning: classification.reasoning,
    },
    binary: {
      filename: result.binary.filename,
      format: result.binary.format,
      architecture: result.binary.architecture,
      bits: result.binary.bits,
      size: result.binary.size,
      isPacked: result.binary.packing?.isPacked ?? false,
      entropy: result.binary.packing?.entropy?.overall,
    },
    behaviors: behaviors.map(b => ({
      id: b.id,
      category: b.category,
      description: b.description,
      riskLevel: b.riskLevel,
      evidence: b.evidence.slice(0, 5),
    })),
    riskAssessment: {
      overall: behaviorRisk.overallRisk,
      importRisk: importRisk.overallRisk,
      criticalBehaviors: behaviorRisk.criticalBehaviors,
    },
    iocs: {
      ips: iocs.ips,
      domains: iocs.domains,
      urls: iocs.urls,
      registryKeys: iocs.registryKeys,
      filePaths: iocs.filePaths.slice(0, 10),
    },
    mitreAttack: {
      tactics: mitreMapping.tactics,
      techniques: mitreMapping.techniques.slice(0, 10).map(t => ({
        id: t.id,
        name: t.name,
        confidence: t.confidence,
      })),
      summary: mitreMapping.summary,
    },
    keyFunctions: result.functions
      .filter(f => !f.isThunk && !f.isExternal)
      .sort((a, b) => b.size - a.size)
      .slice(0, 15)
      .map(f => ({
        name: f.name,
        address: f.address,
        size: f.size,
      })),
    suggestedAnalysis: generateSuggestedAnalysis(behaviors, iocs, classification),
    stats: {
      functions: result.functions.length,
      strings: result.strings.length,
      imports: result.imports.length,
      behaviorsDetected: behaviors.length,
      iocsFound: countIOCs(iocs),
      techniquesMatched: mitreMapping.techniques.length,
    },
    raw: {
      behaviors,
      mitre: mitreMapping,
      iocs,
    },
  };
}

function generateContextSummary(
  result: AnalysisResult,
  classification: { classification: string; malwareType?: string; confidence: number },
  risk: { overallRisk: string; criticalBehaviors: string[] }
): string {
  const format = `${result.binary.format} ${result.binary.architecture} ${result.binary.bits}-bit`;
  const packed = result.binary.packing?.isPacked ? 'packed ' : '';

  if (classification.classification === 'malware') {
    const type = classification.malwareType ?? 'malicious';
    const critical = risk.criticalBehaviors.length > 0
      ? ` Critical behaviors: ${risk.criticalBehaviors.slice(0, 2).join(', ')}.`
      : '';
    return `${packed}${format} executable classified as ${type} with ${(classification.confidence * 100).toFixed(0)}% confidence.${critical}`;
  }

  if (classification.classification === 'suspicious') {
    return `${packed}${format} executable with suspicious characteristics. Risk level: ${risk.overallRisk}. Requires further analysis to confirm malicious intent.`;
  }

  return `${packed}${format} executable with ${result.functions.length} functions and ${result.imports.length} imports. No obvious malicious indicators detected.`;
}

function generateSuggestedAnalysis(
  behaviors: Array<{ id: string; category: string; evidence: string[] }>,
  iocs: { urls: string[]; ips: string[]; registryKeys: string[] },
  classification: { classification: string; malwareType?: string }
): string[] {
  const suggestions: string[] = [];

  if (classification.classification === 'malware' || classification.classification === 'suspicious') {
    suggestions.push('Examine network-related functions for C2 communication patterns');
  }

  if (behaviors.some(b => b.id === 'process_injection')) {
    suggestions.push('Analyze injection target selection and payload in WriteProcessMemory calls');
  }

  if (behaviors.some(b => b.id === 'persistence_registry')) {
    suggestions.push('Check registry key values for persistence payload paths');
  }

  if (iocs.urls.length > 0) {
    suggestions.push(`Investigate URLs: ${iocs.urls.slice(0, 2).join(', ')}`);
  }

  if (behaviors.some(b => b.id === 'credential_theft')) {
    suggestions.push('Examine credential access functions for targeted applications');
  }

  if (behaviors.some(b => b.id === 'file_encryption')) {
    suggestions.push('Analyze encryption routine and look for ransom note generation');
  }

  if (behaviors.some(b => b.category === 'defense_evasion')) {
    suggestions.push('Review anti-analysis checks for sandbox/VM detection logic');
  }

  if (suggestions.length === 0) {
    suggestions.push('Review main entry point and initialization routines');
    suggestions.push('Examine string references for configuration data');
  }

  return suggestions.slice(0, 6);
}
