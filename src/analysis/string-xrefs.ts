/**
 * String Cross-Reference Analysis (v2.6)
 *
 * Provides function-centric and string-centric views of string references.
 */

import { AnalysisResult } from '../output/schema';

export interface FunctionStringUsage {
  functionName: string;
  functionAddress: string;
  strings: {
    value: string;
    address: string;
    refType: 'data' | 'code';
  }[];
  categories: {
    urls: string[];
    paths: string[];
    registryKeys: string[];
    commands: string[];
    errors: string[];
    other: string[];
  };
}

export interface StringUsage {
  value: string;
  address: string;
  referencedBy: {
    functionName: string;
    functionAddress: string;
    refAddress: string;
    refType: 'data' | 'code';
  }[];
  category: 'url' | 'path' | 'registry' | 'command' | 'error' | 'ip' | 'other';
}

/**
 * Get all strings used by a specific function
 */
export function getStringsUsedByFunction(
  analysis: AnalysisResult,
  functionNameOrAddress: string
): FunctionStringUsage | null {
  const func = analysis.functions.find(
    f => f.name === functionNameOrAddress ||
         f.address === functionNameOrAddress ||
         f.address === functionNameOrAddress.replace(/^0x/, '')
  );

  if (!func) return null;

  const usedStrings: FunctionStringUsage['strings'] = [];

  for (const str of analysis.strings) {
    for (const xref of str.xrefs || []) {
      if (xref.function === func.name || xref.function === func.address) {
        usedStrings.push({
          value: str.value,
          address: str.address,
          refType: xref.type
        });
        break;
      }
    }
  }

  return {
    functionName: func.name,
    functionAddress: func.address,
    strings: usedStrings,
    categories: categorizeStrings(usedStrings.map(s => s.value))
  };
}

/**
 * Get all functions that reference a string (exact or pattern match)
 */
export function getFunctionsUsingString(
  analysis: AnalysisResult,
  pattern: string,
  isRegex: boolean = false
): StringUsage[] {
  const results: StringUsage[] = [];
  const matcher = isRegex ? new RegExp(pattern, 'i') : null;

  for (const str of analysis.strings) {
    const matches = matcher
      ? matcher.test(str.value)
      : str.value.toLowerCase().includes(pattern.toLowerCase());

    if (matches && str.xrefs && str.xrefs.length > 0) {
      results.push({
        value: str.value,
        address: str.address,
        referencedBy: str.xrefs.map(xref => ({
          functionName: xref.function,
          functionAddress: xref.address,
          refAddress: xref.address,
          refType: xref.type
        })),
        category: categorizeString(str.value)
      });
    }
  }

  return results;
}

/**
 * Get string usage summary grouped by function
 */
export function getStringUsageByFunction(analysis: AnalysisResult): Map<string, FunctionStringUsage> {
  const functionMap = new Map<string, FunctionStringUsage>();

  // Initialize with all functions
  for (const func of analysis.functions) {
    functionMap.set(func.name, {
      functionName: func.name,
      functionAddress: func.address,
      strings: [],
      categories: { urls: [], paths: [], registryKeys: [], commands: [], errors: [], other: [] }
    });
  }

  // Map strings to functions
  for (const str of analysis.strings) {
    for (const xref of str.xrefs || []) {
      const usage = functionMap.get(xref.function);
      if (usage) {
        usage.strings.push({
          value: str.value,
          address: str.address,
          refType: xref.type
        });
      }
    }
  }

  // Categorize strings for each function
  for (const usage of functionMap.values()) {
    usage.categories = categorizeStrings(usage.strings.map(s => s.value));
  }

  return functionMap;
}

/**
 * Find functions that use suspicious string patterns
 */
export function findSuspiciousFunctions(analysis: AnalysisResult): {
  functionName: string;
  functionAddress: string;
  suspiciousStrings: string[];
  reason: string;
}[] {
  const suspiciousPatterns = [
    { pattern: /^https?:\/\//i, reason: 'URL reference' },
    { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, reason: 'IP address' },
    { pattern: /HKEY_|HKLM|HKCU/i, reason: 'Registry access' },
    { pattern: /cmd\.exe|powershell|\/bin\/sh/i, reason: 'Shell execution' },
    { pattern: /password|passwd|credential|secret|token/i, reason: 'Credential handling' },
    { pattern: /\\AppData\\|\\Temp\\|\/tmp\//i, reason: 'Temp/AppData access' },
    { pattern: /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory/i, reason: 'Injection APIs' },
    { pattern: /IsDebuggerPresent|CheckRemoteDebugger/i, reason: 'Anti-debug' },
  ];

  const results: Map<string, { strings: string[]; reasons: Set<string> }> = new Map();
  const usageMap = getStringUsageByFunction(analysis);

  for (const [funcName, usage] of usageMap) {
    for (const str of usage.strings) {
      for (const { pattern, reason } of suspiciousPatterns) {
        if (pattern.test(str.value)) {
          if (!results.has(funcName)) {
            results.set(funcName, { strings: [], reasons: new Set() });
          }
          const entry = results.get(funcName)!;
          entry.strings.push(str.value);
          entry.reasons.add(reason);
        }
      }
    }
  }

  return Array.from(results.entries()).map(([funcName, data]) => {
    const usage = usageMap.get(funcName)!;
    return {
      functionName: funcName,
      functionAddress: usage.functionAddress,
      suspiciousStrings: [...new Set(data.strings)],
      reason: Array.from(data.reasons).join(', ')
    };
  });
}

/**
 * Get xref statistics
 */
export function getXrefStats(analysis: AnalysisResult): {
  totalStrings: number;
  stringsWithXrefs: number;
  totalXrefs: number;
  functionsWithStrings: number;
  avgStringsPerFunction: number;
  topFunctions: { name: string; stringCount: number }[];
} {
  const stringsWithXrefs = analysis.strings.filter(s => s.xrefs && s.xrefs.length > 0);
  const totalXrefs = analysis.strings.reduce((sum, s) => sum + (s.xrefs?.length || 0), 0);

  const usageMap = getStringUsageByFunction(analysis);
  const functionsWithStrings = Array.from(usageMap.values()).filter(u => u.strings.length > 0);

  const topFunctions = functionsWithStrings
    .map(u => ({ name: u.functionName, stringCount: u.strings.length }))
    .sort((a, b) => b.stringCount - a.stringCount)
    .slice(0, 10);

  return {
    totalStrings: analysis.strings.length,
    stringsWithXrefs: stringsWithXrefs.length,
    totalXrefs,
    functionsWithStrings: functionsWithStrings.length,
    avgStringsPerFunction: functionsWithStrings.length > 0
      ? Math.round(totalXrefs / functionsWithStrings.length * 10) / 10
      : 0,
    topFunctions
  };
}

// Helper functions

function categorizeString(value: string): StringUsage['category'] {
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(value)) return 'ip';
  if (/HKEY_|HKLM|HKCU/i.test(value)) return 'registry';
  if (/[A-Z]:\\|^\/[a-z]/i.test(value)) return 'path';
  if (/cmd|powershell|bash|sh\s/i.test(value)) return 'command';
  if (/error|fail|exception/i.test(value)) return 'error';
  return 'other';
}

function categorizeStrings(strings: string[]): FunctionStringUsage['categories'] {
  const categories: FunctionStringUsage['categories'] = {
    urls: [],
    paths: [],
    registryKeys: [],
    commands: [],
    errors: [],
    other: []
  };

  for (const str of strings) {
    const cat = categorizeString(str);
    switch (cat) {
      case 'url': categories.urls.push(str); break;
      case 'path': categories.paths.push(str); break;
      case 'registry': categories.registryKeys.push(str); break;
      case 'command': categories.commands.push(str); break;
      case 'error': categories.errors.push(str); break;
      default: categories.other.push(str);
    }
  }

  return categories;
}
