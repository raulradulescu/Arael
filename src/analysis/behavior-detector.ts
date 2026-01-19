/**
 * Behavior Detector (v2.6)
 *
 * Detects malicious behaviors from imports and strings:
 * - Network activity (client, server, C2)
 * - Process injection
 * - Credential theft
 * - Persistence mechanisms
 * - Anti-analysis techniques
 * - File encryption (ransomware)
 * - Keylogging
 */

// Import database available for future enhancements
// import { getImportMetadata, type ImportMetadata } from './import-database';

export type BehaviorCategory =
  | 'network'
  | 'filesystem'
  | 'process'
  | 'registry'
  | 'crypto'
  | 'execution'
  | 'persistence'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'collection'
  | 'exfiltration'
  | 'impact';

export interface DetectedBehavior {
  id: string;
  category: BehaviorCategory;
  description: string;
  evidence: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  mitreId?: string;
}

interface BehaviorRule {
  id: string;
  category: BehaviorCategory;
  description: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  mitreId?: string;
  triggers: {
    imports?: string[];
    importPatterns?: RegExp[];
    strings?: RegExp[];
    requiredCount?: number; // Minimum number of triggers that must match
    requireAll?: boolean; // All triggers must match
  };
}

// ============================================================================
// BEHAVIOR RULES
// ============================================================================

const BEHAVIOR_RULES: BehaviorRule[] = [
  // Network behaviors
  {
    id: 'network_client',
    category: 'network',
    description: 'Establishes outbound network connections',
    riskLevel: 'medium',
    mitreId: 'T1071',
    triggers: {
      imports: ['connect', 'WSAConnect', 'InternetOpen', 'WinHttpOpen', 'HttpOpenRequest'],
      strings: [/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, /https?:\/\//i],
      requiredCount: 1,
    },
  },
  {
    id: 'network_server',
    category: 'network',
    description: 'Listens for incoming network connections',
    riskLevel: 'high',
    mitreId: 'T1571',
    triggers: {
      imports: ['bind', 'listen', 'accept'],
      requiredCount: 2,
    },
  },
  {
    id: 'http_communication',
    category: 'network',
    description: 'Performs HTTP/HTTPS communication',
    riskLevel: 'medium',
    mitreId: 'T1071.001',
    triggers: {
      imports: ['InternetOpenUrl', 'HttpSendRequest', 'WinHttpSendRequest', 'URLDownloadToFile'],
      requiredCount: 1,
    },
  },
  {
    id: 'download_execute',
    category: 'execution',
    description: 'Downloads and executes remote content',
    riskLevel: 'critical',
    mitreId: 'T1105',
    triggers: {
      imports: ['URLDownloadToFile', 'URLDownloadToCacheFile'],
      requiredCount: 1,
    },
  },

  // Process injection
  {
    id: 'process_injection',
    category: 'execution',
    description: 'Injects code into other processes',
    riskLevel: 'critical',
    mitreId: 'T1055',
    triggers: {
      imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
      requiredCount: 2,
    },
  },
  {
    id: 'process_hollowing',
    category: 'execution',
    description: 'Process hollowing technique detected',
    riskLevel: 'critical',
    mitreId: 'T1055.012',
    triggers: {
      imports: ['NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'WriteProcessMemory'],
      requiredCount: 2,
    },
  },
  {
    id: 'apc_injection',
    category: 'execution',
    description: 'APC queue injection technique',
    riskLevel: 'critical',
    mitreId: 'T1055.004',
    triggers: {
      imports: ['QueueUserAPC', 'NtQueueApcThread'],
      requiredCount: 1,
    },
  },
  {
    id: 'thread_hijacking',
    category: 'execution',
    description: 'Thread context manipulation (hijacking)',
    riskLevel: 'critical',
    mitreId: 'T1055',
    triggers: {
      imports: ['GetThreadContext', 'SetThreadContext', 'SuspendThread', 'ResumeThread'],
      requiredCount: 3,
    },
  },

  // Credential access
  {
    id: 'credential_theft',
    category: 'credential_access',
    description: 'Accesses credential storage',
    riskLevel: 'critical',
    mitreId: 'T1555',
    triggers: {
      imports: ['CredEnumerate', 'CredRead', 'CryptUnprotectData'],
      strings: [/password/i, /credential/i, /login/i],
      requiredCount: 1,
    },
  },
  {
    id: 'lsass_access',
    category: 'credential_access',
    description: 'Potential LSASS memory access',
    riskLevel: 'critical',
    mitreId: 'T1003.001',
    triggers: {
      imports: ['OpenProcess', 'ReadProcessMemory', 'MiniDumpWriteDump'],
      strings: [/lsass/i],
      requiredCount: 2,
    },
  },
  {
    id: 'token_manipulation',
    category: 'credential_access',
    description: 'Token manipulation for privilege escalation',
    riskLevel: 'critical',
    mitreId: 'T1134',
    triggers: {
      imports: ['OpenProcessToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser', 'AdjustTokenPrivileges'],
      requiredCount: 2,
    },
  },

  // Persistence
  {
    id: 'persistence_registry',
    category: 'persistence',
    description: 'Modifies registry for persistence',
    riskLevel: 'high',
    mitreId: 'T1547.001',
    triggers: {
      imports: ['RegSetValueEx', 'RegCreateKeyEx', 'NtSetValueKey'],
      strings: [/CurrentVersion\\Run/i, /SOFTWARE\\Microsoft\\Windows/i],
      requiredCount: 1,
    },
  },
  {
    id: 'persistence_service',
    category: 'persistence',
    description: 'Creates Windows service for persistence',
    riskLevel: 'high',
    mitreId: 'T1543.003',
    triggers: {
      imports: ['CreateService', 'ChangeServiceConfig'],
      requiredCount: 1,
    },
  },
  {
    id: 'persistence_scheduled_task',
    category: 'persistence',
    description: 'Creates scheduled task for persistence',
    riskLevel: 'high',
    mitreId: 'T1053',
    triggers: {
      strings: [/schtasks/i, /ITaskScheduler/i, /\\Tasks\\/i],
      requiredCount: 1,
    },
  },

  // Defense evasion
  {
    id: 'anti_debug',
    category: 'defense_evasion',
    description: 'Contains debugger detection techniques',
    riskLevel: 'high',
    mitreId: 'T1622',
    triggers: {
      imports: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
      requiredCount: 1,
    },
  },
  {
    id: 'anti_vm',
    category: 'defense_evasion',
    description: 'Contains VM/sandbox detection',
    riskLevel: 'high',
    mitreId: 'T1497',
    triggers: {
      strings: [/vmware/i, /virtualbox/i, /vbox/i, /qemu/i, /sandbox/i, /wine/i],
      imports: ['GetSystemMetrics', 'EnumDisplayDevices'],
      requiredCount: 2,
    },
  },
  {
    id: 'timing_evasion',
    category: 'defense_evasion',
    description: 'Uses timing-based evasion',
    riskLevel: 'medium',
    mitreId: 'T1497.003',
    triggers: {
      imports: ['Sleep', 'GetTickCount', 'QueryPerformanceCounter'],
      requiredCount: 2,
    },
  },
  {
    id: 'file_deletion',
    category: 'defense_evasion',
    description: 'Deletes files (indicator removal)',
    riskLevel: 'medium',
    mitreId: 'T1070.004',
    triggers: {
      imports: ['DeleteFile', 'remove', 'unlink'],
      requiredCount: 1,
    },
  },
  {
    id: 'timestomping',
    category: 'defense_evasion',
    description: 'Modifies file timestamps',
    riskLevel: 'high',
    mitreId: 'T1070.006',
    triggers: {
      imports: ['SetFileTime'],
      requiredCount: 1,
    },
  },

  // Discovery
  {
    id: 'process_discovery',
    category: 'discovery',
    description: 'Enumerates running processes',
    riskLevel: 'medium',
    mitreId: 'T1057',
    triggers: {
      imports: ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'EnumProcesses'],
      requiredCount: 2,
    },
  },
  {
    id: 'system_discovery',
    category: 'discovery',
    description: 'Gathers system information',
    riskLevel: 'low',
    mitreId: 'T1082',
    triggers: {
      imports: ['GetSystemInfo', 'GetVersionEx', 'GetComputerName', 'GetUserName'],
      requiredCount: 2,
    },
  },
  {
    id: 'file_discovery',
    category: 'discovery',
    description: 'Enumerates files and directories',
    riskLevel: 'low',
    mitreId: 'T1083',
    triggers: {
      imports: ['FindFirstFile', 'FindNextFile', 'opendir', 'readdir'],
      requiredCount: 2,
    },
  },

  // Collection
  {
    id: 'keylogging',
    category: 'collection',
    description: 'Captures keyboard input',
    riskLevel: 'critical',
    mitreId: 'T1056.001',
    triggers: {
      imports: ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx'],
      requiredCount: 1,
    },
  },
  {
    id: 'clipboard_capture',
    category: 'collection',
    description: 'Accesses clipboard data',
    riskLevel: 'high',
    mitreId: 'T1115',
    triggers: {
      imports: ['OpenClipboard', 'GetClipboardData'],
      requiredCount: 2,
    },
  },
  {
    id: 'screen_capture',
    category: 'collection',
    description: 'Captures screen content',
    riskLevel: 'high',
    mitreId: 'T1113',
    triggers: {
      imports: ['BitBlt', 'GetDC', 'GetDIBits', 'CreateCompatibleDC'],
      requiredCount: 3,
    },
  },

  // Impact
  {
    id: 'file_encryption',
    category: 'impact',
    description: 'Encrypts files (ransomware indicator)',
    riskLevel: 'critical',
    mitreId: 'T1486',
    triggers: {
      imports: ['FindFirstFile', 'FindNextFile', 'CryptEncrypt', 'BCryptEncrypt'],
      strings: [/\.encrypted/i, /\.locked/i, /ransom/i, /your files/i],
      requiredCount: 3,
    },
  },
  {
    id: 'service_stop',
    category: 'impact',
    description: 'Stops system services',
    riskLevel: 'high',
    mitreId: 'T1489',
    triggers: {
      imports: ['ControlService', 'TerminateProcess'],
      strings: [/SERVICE_CONTROL_STOP/i],
      requiredCount: 2,
    },
  },

  // Execution
  {
    id: 'command_execution',
    category: 'execution',
    description: 'Executes shell commands',
    riskLevel: 'high',
    mitreId: 'T1059',
    triggers: {
      imports: ['system', 'popen', 'WinExec', 'ShellExecute'],
      strings: [/cmd\.exe/i, /powershell/i, /\/bin\/sh/i, /\/bin\/bash/i],
      requiredCount: 1,
    },
  },
  {
    id: 'process_creation',
    category: 'execution',
    description: 'Creates new processes',
    riskLevel: 'medium',
    mitreId: 'T1106',
    triggers: {
      imports: ['CreateProcess', 'CreateProcessAsUser', 'fork', 'execve'],
      requiredCount: 1,
    },
  },
  {
    id: 'dll_loading',
    category: 'execution',
    description: 'Dynamically loads DLLs',
    riskLevel: 'medium',
    mitreId: 'T1129',
    triggers: {
      imports: ['LoadLibrary', 'LoadLibraryEx', 'LdrLoadDll', 'dlopen'],
      requiredCount: 1,
    },
  },

  // Crypto (non-malicious indicator)
  {
    id: 'encryption_usage',
    category: 'crypto',
    description: 'Uses encryption/decryption',
    riskLevel: 'medium',
    triggers: {
      imports: ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt', 'EVP_EncryptInit_ex'],
      requiredCount: 1,
    },
  },
  {
    id: 'hashing',
    category: 'crypto',
    description: 'Uses cryptographic hashing',
    riskLevel: 'low',
    triggers: {
      imports: ['CryptHashData', 'BCryptHashData', 'MD5', 'SHA1', 'SHA256'],
      requiredCount: 1,
    },
  },
];

// ============================================================================
// DETECTION ENGINE
// ============================================================================

/**
 * Detect behaviors from imports and strings
 */
export function detectBehaviors(
  imports: string[],
  strings: string[]
): DetectedBehavior[] {
  const detected: DetectedBehavior[] = [];
  const importLower = imports.map((i) => i.toLowerCase());
  const importSet = new Set(importLower);

  for (const rule of BEHAVIOR_RULES) {
    const evidence: string[] = [];
    let matchCount = 0;

    // Check import triggers
    if (rule.triggers.imports) {
      for (const imp of rule.triggers.imports) {
        if (importSet.has(imp.toLowerCase())) {
          evidence.push(`Import: ${imp}`);
          matchCount++;
        }
      }
    }

    // Check import patterns
    if (rule.triggers.importPatterns) {
      for (const pattern of rule.triggers.importPatterns) {
        for (const imp of imports) {
          if (pattern.test(imp)) {
            evidence.push(`Import pattern: ${imp}`);
            matchCount++;
            break;
          }
        }
      }
    }

    // Check string triggers
    if (rule.triggers.strings) {
      for (const pattern of rule.triggers.strings) {
        for (const str of strings) {
          if (pattern.test(str)) {
            evidence.push(`String: ${str.substring(0, 50)}${str.length > 50 ? '...' : ''}`);
            matchCount++;
            break; // One match per pattern is enough
          }
        }
      }
    }

    // Evaluate if rule matches
    const requiredCount = rule.triggers.requiredCount || 1;
    const matches = rule.triggers.requireAll
      ? evidence.length >= getTotalTriggerCount(rule)
      : matchCount >= requiredCount;

    if (matches && evidence.length > 0) {
      // Calculate confidence based on evidence
      const confidence = Math.min(0.5 + (matchCount * 0.15), 0.95);

      detected.push({
        id: rule.id,
        category: rule.category,
        description: rule.description,
        evidence,
        riskLevel: rule.riskLevel,
        confidence,
        mitreId: rule.mitreId,
      });
    }
  }

  // Sort by risk level and confidence
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  detected.sort((a, b) => {
    const riskDiff = riskOrder[a.riskLevel] - riskOrder[b.riskLevel];
    if (riskDiff !== 0) return riskDiff;
    return b.confidence - a.confidence;
  });

  return detected;
}

function getTotalTriggerCount(rule: BehaviorRule): number {
  let count = 0;
  if (rule.triggers.imports) count += rule.triggers.imports.length;
  if (rule.triggers.importPatterns) count += rule.triggers.importPatterns.length;
  if (rule.triggers.strings) count += rule.triggers.strings.length;
  return count;
}

/**
 * Get behaviors by category
 */
export function getBehaviorsByCategory(
  behaviors: DetectedBehavior[]
): Map<BehaviorCategory, DetectedBehavior[]> {
  const result = new Map<BehaviorCategory, DetectedBehavior[]>();

  for (const behavior of behaviors) {
    const existing = result.get(behavior.category) || [];
    existing.push(behavior);
    result.set(behavior.category, existing);
  }

  return result;
}

/**
 * Get overall risk assessment from behaviors
 */
export function assessBehaviorRisk(behaviors: DetectedBehavior[]): {
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  criticalBehaviors: string[];
  summary: string;
} {
  const riskWeights = { low: 1, medium: 2, high: 5, critical: 10 };
  let riskScore = 0;
  const criticalBehaviors: string[] = [];

  for (const behavior of behaviors) {
    riskScore += riskWeights[behavior.riskLevel] * behavior.confidence;
    if (behavior.riskLevel === 'critical') {
      criticalBehaviors.push(behavior.description);
    }
  }

  let overallRisk: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 30 || criticalBehaviors.length >= 2) {
    overallRisk = 'critical';
  } else if (riskScore >= 15 || criticalBehaviors.length === 1) {
    overallRisk = 'high';
  } else if (riskScore >= 5) {
    overallRisk = 'medium';
  } else {
    overallRisk = 'low';
  }

  // Generate summary
  let summary: string;
  if (overallRisk === 'critical') {
    summary = `Critical threat detected with ${criticalBehaviors.length} critical behavior(s): ${criticalBehaviors.slice(0, 3).join(', ')}`;
  } else if (overallRisk === 'high') {
    summary = `High-risk binary with ${behaviors.length} suspicious behavior(s) detected`;
  } else if (overallRisk === 'medium') {
    summary = `Moderate risk with ${behaviors.length} behavior(s) worth investigating`;
  } else {
    summary = behaviors.length > 0
      ? `Low risk with ${behaviors.length} benign behavior(s) detected`
      : 'No suspicious behaviors detected';
  }

  return { overallRisk, riskScore, criticalBehaviors, summary };
}

/**
 * Classify binary type based on behaviors
 */
export function classifyBinaryType(behaviors: DetectedBehavior[]): {
  classification: 'benign' | 'suspicious' | 'malware' | 'unknown';
  malwareType?: string;
  confidence: number;
  reasoning: string[];
} {
  const behaviorIds = new Set(behaviors.map((b) => b.id));
  const reasoning: string[] = [];
  let classification: 'benign' | 'suspicious' | 'malware' | 'unknown' = 'unknown';
  let malwareType: string | undefined;
  let confidence = 0.5;

  // Check for ransomware indicators
  if (behaviorIds.has('file_encryption')) {
    classification = 'malware';
    malwareType = 'ransomware';
    confidence = 0.9;
    reasoning.push('File encryption behavior detected');
  }

  // Check for backdoor/RAT indicators
  if (
    behaviorIds.has('network_server') ||
    (behaviorIds.has('network_client') && behaviorIds.has('command_execution'))
  ) {
    classification = 'malware';
    malwareType = malwareType || 'backdoor';
    confidence = Math.max(confidence, 0.85);
    reasoning.push('Remote access/command execution capability');
  }

  // Check for trojan indicators
  if (behaviorIds.has('process_injection') || behaviorIds.has('process_hollowing')) {
    classification = 'malware';
    malwareType = malwareType || 'trojan';
    confidence = Math.max(confidence, 0.9);
    reasoning.push('Process injection technique detected');
  }

  // Check for stealer indicators
  if (behaviorIds.has('credential_theft') || behaviorIds.has('keylogging')) {
    classification = 'malware';
    malwareType = malwareType || 'stealer';
    confidence = Math.max(confidence, 0.85);
    reasoning.push('Credential/input theft capability');
  }

  // Check for dropper indicators
  if (behaviorIds.has('download_execute')) {
    classification = 'malware';
    malwareType = malwareType || 'dropper';
    confidence = Math.max(confidence, 0.8);
    reasoning.push('Download and execute capability');
  }

  // Suspicious but not definitively malware
  if (classification === 'unknown') {
    const suspiciousBehaviors = behaviors.filter(
      (b) => b.riskLevel === 'high' || b.riskLevel === 'critical'
    );

    if (suspiciousBehaviors.length >= 2) {
      classification = 'suspicious';
      confidence = 0.7;
      reasoning.push(`${suspiciousBehaviors.length} high-risk behaviors detected`);
    } else if (suspiciousBehaviors.length === 1) {
      classification = 'suspicious';
      confidence = 0.6;
      reasoning.push('Single high-risk behavior detected');
    } else if (behaviors.length > 0) {
      classification = 'benign';
      confidence = 0.6;
      reasoning.push('Only low/medium risk behaviors detected');
    }
  }

  // Anti-analysis increases suspicion
  if (behaviorIds.has('anti_debug') || behaviorIds.has('anti_vm')) {
    if (classification === 'benign') {
      classification = 'suspicious';
    }
    confidence = Math.min(confidence + 0.1, 0.95);
    reasoning.push('Anti-analysis techniques present');
  }

  return { classification, malwareType, confidence, reasoning };
}

/**
 * Get behavior detection summary
 */
export function getBehaviorSummary(behaviors: DetectedBehavior[]): string[] {
  const summary: string[] = [];
  const categories = getBehaviorsByCategory(behaviors);

  categories.forEach((behavs, category) => {
    const criticalCount = behavs.filter((b) => b.riskLevel === 'critical').length;
    const highCount = behavs.filter((b) => b.riskLevel === 'high').length;

    let line = `${category}: ${behavs.length} behavior(s)`;
    if (criticalCount > 0) line += ` [${criticalCount} critical]`;
    else if (highCount > 0) line += ` [${highCount} high-risk]`;

    summary.push(line);
  });

  return summary;
}
