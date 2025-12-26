/**
 * TypeScript types matching the Arael JSON output schema.
 */

export interface AnalysisMetadata {
  analysisId: string;
  timestamp: string;
  araelVersion: string;
  ghidraVersion: string;
  analysisDurationMs: number;
  connectionMode: 'bridge' | 'headless';
  cached: boolean;
}

export interface BinaryHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface BinaryInfo {
  filename: string;
  filepath: string;
  size: number;
  hashes: BinaryHashes;
  format: 'ELF' | 'PE' | 'Mach-O' | 'unknown';
  architecture: string;
  endianness: 'little' | 'big';
  entryPoint: string;
  imageBase: string;
}

export interface FunctionHexdump {
  address: string;
  bytes: string;
  formatted: string;
}

export interface AgentFunctionAnalysis {
  purpose: string;
  semanticName: string;
  securityNotes: string;
  confidence: number;
}

export interface FunctionInfo {
  name: string;
  address: string;
  size: number;
  signature: string;
  isThunk: boolean;
  isExternal: boolean;
  callers: string[];
  callees: string[];
  pseudocode: string | null;
  decompileError?: string;
  hexdump?: FunctionHexdump;
  agentAnalysis?: AgentFunctionAnalysis;
}

export interface StringXref {
  address: string;
  function: string;
  type: 'data' | 'code';
}

export interface StringInfo {
  address: string;
  value: string;
  length: number;
  encoding: 'ascii' | 'utf8' | 'utf16le' | 'utf16be';
  section?: string;
  xrefs: StringXref[];
}

export interface ImportInfo {
  name: string;
  library: string;
  address: string;
  type: 'function' | 'data';
}

export interface ExportInfo {
  name: string;
  address: string;
  ordinal?: number;
}

export interface AgentAnalysis {
  summary: string;
  suspiciousIndicators: string[];
  confidence: number;
}

export interface AnalysisResult {
  $schema?: string;
  version: string;
  metadata: AnalysisMetadata;
  binary: BinaryInfo;
  functions: FunctionInfo[];
  strings: StringInfo[];
  imports: ImportInfo[];
  exports?: ExportInfo[];
  agentAnalysis?: AgentAnalysis;
}

/**
 * Error response structure.
 */
export interface AnalysisError {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

/**
 * Type guard for AnalysisResult.
 */
export function isAnalysisResult(obj: unknown): obj is AnalysisResult {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'version' in obj &&
    'metadata' in obj &&
    'binary' in obj &&
    'functions' in obj
  );
}

/**
 * Type guard for AnalysisError.
 */
export function isAnalysisError(obj: unknown): obj is AnalysisError {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'error' in obj &&
    'code' in obj
  );
}
