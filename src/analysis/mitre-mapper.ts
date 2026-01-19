/**
 * MITRE ATT&CK Mapper (v2.6)
 *
 * Maps detected behaviors to ATT&CK techniques and tactics.
 */

import type { DetectedBehavior } from './behavior-detector';

export interface ATTACKTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
}

export interface ATTACKMapping {
  tactics: string[];
  techniques: Array<{
    id: string;
    name: string;
    tactic: string;
    confidence: number;
    evidence: string[];
  }>;
  summary: string;
}

// ============================================================================
// ATT&CK TECHNIQUE DATABASE
// ============================================================================

const TECHNIQUE_DATABASE: Record<string, ATTACKTechnique> = {
  // Execution
  'T1059': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters to execute commands',
    url: 'https://attack.mitre.org/techniques/T1059/',
  },
  'T1106': {
    id: 'T1106',
    name: 'Native API',
    tactic: 'Execution',
    description: 'Adversaries may interact with the native OS API to execute behaviors',
    url: 'https://attack.mitre.org/techniques/T1106/',
  },
  'T1129': {
    id: 'T1129',
    name: 'Shared Modules',
    tactic: 'Execution',
    description: 'Adversaries may execute malicious payloads via loading shared modules',
    url: 'https://attack.mitre.org/techniques/T1129/',
  },

  // Persistence
  'T1547': {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    description: 'Adversaries may configure system settings to automatically execute a program',
    url: 'https://attack.mitre.org/techniques/T1547/',
  },
  'T1547.001': {
    id: 'T1547.001',
    name: 'Registry Run Keys / Startup Folder',
    tactic: 'Persistence',
    description: 'Adversaries may achieve persistence by adding a program to the Registry Run keys',
    url: 'https://attack.mitre.org/techniques/T1547/001/',
  },
  'T1543': {
    id: 'T1543',
    name: 'Create or Modify System Process',
    tactic: 'Persistence',
    description: 'Adversaries may create or modify system-level processes to repeatedly execute',
    url: 'https://attack.mitre.org/techniques/T1543/',
  },
  'T1543.003': {
    id: 'T1543.003',
    name: 'Windows Service',
    tactic: 'Persistence',
    description: 'Adversaries may create or modify Windows services to repeatedly execute',
    url: 'https://attack.mitre.org/techniques/T1543/003/',
  },
  'T1053': {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    description: 'Adversaries may abuse task scheduling to facilitate execution',
    url: 'https://attack.mitre.org/techniques/T1053/',
  },

  // Privilege Escalation
  'T1134': {
    id: 'T1134',
    name: 'Access Token Manipulation',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may modify access tokens to operate under different user context',
    url: 'https://attack.mitre.org/techniques/T1134/',
  },

  // Defense Evasion
  'T1622': {
    id: 'T1622',
    name: 'Debugger Evasion',
    tactic: 'Defense Evasion',
    description: 'Adversaries may employ various means to detect and avoid debuggers',
    url: 'https://attack.mitre.org/techniques/T1622/',
  },
  'T1497': {
    id: 'T1497',
    name: 'Virtualization/Sandbox Evasion',
    tactic: 'Defense Evasion',
    description: 'Adversaries may detect and avoid virtualization and analysis environments',
    url: 'https://attack.mitre.org/techniques/T1497/',
  },
  'T1497.003': {
    id: 'T1497.003',
    name: 'Time Based Evasion',
    tactic: 'Defense Evasion',
    description: 'Adversaries may employ various time-based evasion methods',
    url: 'https://attack.mitre.org/techniques/T1497/003/',
  },
  'T1070': {
    id: 'T1070',
    name: 'Indicator Removal',
    tactic: 'Defense Evasion',
    description: 'Adversaries may delete or modify artifacts generated during an intrusion',
    url: 'https://attack.mitre.org/techniques/T1070/',
  },
  'T1070.004': {
    id: 'T1070.004',
    name: 'File Deletion',
    tactic: 'Defense Evasion',
    description: 'Adversaries may delete files left behind by the actions of their intrusion',
    url: 'https://attack.mitre.org/techniques/T1070/004/',
  },
  'T1070.006': {
    id: 'T1070.006',
    name: 'Timestomp',
    tactic: 'Defense Evasion',
    description: 'Adversaries may modify file time attributes to hide malicious activity',
    url: 'https://attack.mitre.org/techniques/T1070/006/',
  },
  'T1055': {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into processes to evade defenses',
    url: 'https://attack.mitre.org/techniques/T1055/',
  },
  'T1055.004': {
    id: 'T1055.004',
    name: 'Asynchronous Procedure Call',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into processes via APC queue',
    url: 'https://attack.mitre.org/techniques/T1055/004/',
  },
  'T1055.012': {
    id: 'T1055.012',
    name: 'Process Hollowing',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into suspended processes',
    url: 'https://attack.mitre.org/techniques/T1055/012/',
  },

  // Credential Access
  'T1555': {
    id: 'T1555',
    name: 'Credentials from Password Stores',
    tactic: 'Credential Access',
    description: 'Adversaries may search for common password storage locations',
    url: 'https://attack.mitre.org/techniques/T1555/',
  },
  'T1003': {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description: 'Adversaries may dump credentials to obtain account login information',
    url: 'https://attack.mitre.org/techniques/T1003/',
  },
  'T1003.001': {
    id: 'T1003.001',
    name: 'LSASS Memory',
    tactic: 'Credential Access',
    description: 'Adversaries may attempt to access credential material stored in LSASS',
    url: 'https://attack.mitre.org/techniques/T1003/001/',
  },

  // Discovery
  'T1057': {
    id: 'T1057',
    name: 'Process Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get information about running processes',
    url: 'https://attack.mitre.org/techniques/T1057/',
  },
  'T1082': {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get detailed information about the OS',
    url: 'https://attack.mitre.org/techniques/T1082/',
  },
  'T1083': {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may enumerate files and directories',
    url: 'https://attack.mitre.org/techniques/T1083/',
  },
  'T1033': {
    id: 'T1033',
    name: 'System Owner/User Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to identify the primary user or current user',
    url: 'https://attack.mitre.org/techniques/T1033/',
  },

  // Collection
  'T1056': {
    id: 'T1056',
    name: 'Input Capture',
    tactic: 'Collection',
    description: 'Adversaries may use methods of capturing user input',
    url: 'https://attack.mitre.org/techniques/T1056/',
  },
  'T1056.001': {
    id: 'T1056.001',
    name: 'Keylogging',
    tactic: 'Collection',
    description: 'Adversaries may log user keystrokes to intercept credentials',
    url: 'https://attack.mitre.org/techniques/T1056/001/',
  },
  'T1115': {
    id: 'T1115',
    name: 'Clipboard Data',
    tactic: 'Collection',
    description: 'Adversaries may collect data stored in the clipboard',
    url: 'https://attack.mitre.org/techniques/T1115/',
  },
  'T1113': {
    id: 'T1113',
    name: 'Screen Capture',
    tactic: 'Collection',
    description: 'Adversaries may attempt to take screen captures of the desktop',
    url: 'https://attack.mitre.org/techniques/T1113/',
  },

  // Command and Control
  'T1071': {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols',
    url: 'https://attack.mitre.org/techniques/T1071/',
  },
  'T1071.001': {
    id: 'T1071.001',
    name: 'Web Protocols',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using HTTP/HTTPS',
    url: 'https://attack.mitre.org/techniques/T1071/001/',
  },
  'T1571': {
    id: 'T1571',
    name: 'Non-Standard Port',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using a non-standard port',
    url: 'https://attack.mitre.org/techniques/T1571/',
  },
  'T1105': {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    description: 'Adversaries may transfer tools from an external system',
    url: 'https://attack.mitre.org/techniques/T1105/',
  },

  // Exfiltration
  'T1048': {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    description: 'Adversaries may steal data by exfiltrating over a different protocol',
    url: 'https://attack.mitre.org/techniques/T1048/',
  },

  // Impact
  'T1486': {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries may encrypt data on target systems to interrupt availability',
    url: 'https://attack.mitre.org/techniques/T1486/',
  },
  'T1489': {
    id: 'T1489',
    name: 'Service Stop',
    tactic: 'Impact',
    description: 'Adversaries may stop or disable services on a system',
    url: 'https://attack.mitre.org/techniques/T1489/',
  },
};

// ============================================================================
// MAPPING FUNCTIONS
// ============================================================================

/**
 * Map detected behaviors to ATT&CK techniques
 */
export function mapToATTACK(behaviors: DetectedBehavior[]): ATTACKMapping {
  const techniqueMap = new Map<string, { confidence: number; evidence: string[] }>();
  const tactics = new Set<string>();

  for (const behavior of behaviors) {
    if (behavior.mitreId) {
      const technique = TECHNIQUE_DATABASE[behavior.mitreId];
      if (technique) {
        tactics.add(technique.tactic);

        const existing = techniqueMap.get(behavior.mitreId);
        if (existing) {
          // Merge evidence and increase confidence
          existing.evidence.push(...behavior.evidence);
          existing.confidence = Math.min(existing.confidence + 0.1, 0.95);
        } else {
          techniqueMap.set(behavior.mitreId, {
            confidence: behavior.confidence,
            evidence: [...behavior.evidence],
          });
        }
      }
    }
  }

  // Build techniques array
  const techniques: ATTACKMapping['techniques'] = [];
  techniqueMap.forEach((data, id) => {
    const technique = TECHNIQUE_DATABASE[id];
    if (technique) {
      techniques.push({
        id: technique.id,
        name: technique.name,
        tactic: technique.tactic,
        confidence: data.confidence,
        evidence: [...new Set(data.evidence)], // Deduplicate evidence
      });
    }
  });

  // Sort by confidence
  techniques.sort((a, b) => b.confidence - a.confidence);

  // Generate summary
  const summary = generateSummary(Array.from(tactics), techniques);

  return {
    tactics: Array.from(tactics),
    techniques,
    summary,
  };
}

/**
 * Generate human-readable summary
 */
function generateSummary(
  tactics: string[],
  techniques: ATTACKMapping['techniques']
): string {
  if (techniques.length === 0) {
    return 'No MITRE ATT&CK techniques identified.';
  }

  const highConfidence = techniques.filter((t) => t.confidence >= 0.8);
  const tacticsStr = tactics.slice(0, 4).join(', ');

  if (highConfidence.length >= 3) {
    return `High-confidence mapping to ${highConfidence.length} ATT&CK techniques across ${tactics.length} tactic(s): ${tacticsStr}. Primary techniques: ${highConfidence.slice(0, 3).map((t) => t.id).join(', ')}.`;
  } else if (highConfidence.length > 0) {
    return `Mapped to ${techniques.length} ATT&CK technique(s) with ${highConfidence.length} high-confidence match(es). Tactics: ${tacticsStr}.`;
  } else {
    return `Potential mapping to ${techniques.length} ATT&CK technique(s) with moderate confidence. Tactics: ${tacticsStr}.`;
  }
}

/**
 * Get technique details by ID
 */
export function getTechniqueById(id: string): ATTACKTechnique | null {
  return TECHNIQUE_DATABASE[id] || null;
}

/**
 * Get all techniques for a tactic
 */
export function getTechniquesByTactic(tactic: string): ATTACKTechnique[] {
  return Object.values(TECHNIQUE_DATABASE).filter(
    (t) => t.tactic.toLowerCase() === tactic.toLowerCase()
  );
}

/**
 * Get tactics from behaviors
 */
export function getTactics(mapping: ATTACKMapping): string[] {
  return mapping.tactics;
}

/**
 * Check if mapping contains specific technique
 */
export function hasTechnique(mapping: ATTACKMapping, techniqueId: string): boolean {
  return mapping.techniques.some((t) => t.id === techniqueId);
}

/**
 * Get technique count by tactic
 */
export function getTechniqueCountByTactic(
  mapping: ATTACKMapping
): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const technique of mapping.techniques) {
    counts[technique.tactic] = (counts[technique.tactic] || 0) + 1;
  }

  return counts;
}

/**
 * Get all available tactics
 */
export function getAllTactics(): string[] {
  const tactics = new Set<string>();
  Object.values(TECHNIQUE_DATABASE).forEach((t) => tactics.add(t.tactic));
  return Array.from(tactics);
}

/**
 * Get database statistics
 */
export function getMITREDatabaseStats(): {
  totalTechniques: number;
  byTactic: Record<string, number>;
} {
  const byTactic: Record<string, number> = {};

  Object.values(TECHNIQUE_DATABASE).forEach((t) => {
    byTactic[t.tactic] = (byTactic[t.tactic] || 0) + 1;
  });

  return {
    totalTechniques: Object.keys(TECHNIQUE_DATABASE).length,
    byTactic,
  };
}
