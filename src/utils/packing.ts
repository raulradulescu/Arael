import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { logger } from './logger';

export interface PackerSignature {
  name: string;
  confidence: number;
  version?: string;
  canUnpack: boolean;
  indicators: string[];
}

export interface SectionEntropy {
  name: string;
  entropy: number;
}

export interface PackingEntropy {
  overall: number;
  sections: SectionEntropy[];
}

export interface PackingDetectionResult {
  isPacked: boolean;
  packers: PackerSignature[];
  entropy: PackingEntropy;
  suspiciousIndicators: string[];
}

const HIGH_ENTROPY_THRESHOLD = 7.0;

// Data-driven packer configuration
interface PackerConfig {
  name: string;
  confidence: number;
  canUnpack: boolean;
  signatures: string[];
  sectionPrefixes?: string[];
  magicBytes?: { bytes: number[]; searchLimit?: number };
}

const PACKER_CONFIGS: PackerConfig[] = [
  {
    name: 'UPX',
    confidence: 0.9,
    canUnpack: true,
    signatures: ['UPX0', 'UPX1', 'UPX2'],
    sectionPrefixes: ['.upx'],
    magicBytes: { bytes: [0x55, 0x50, 0x58, 0x21], searchLimit: 2048 } // "UPX!"
  },
  {
    name: 'PyInstaller',
    confidence: 0.85,
    canUnpack: true,
    signatures: ['pyi-runtime-tmpdir', 'PyInstaller'],
    magicBytes: { bytes: [0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e], searchLimit: 4096 }
  },
  {
    name: 'Py2Exe',
    confidence: 0.85,
    canUnpack: false,
    signatures: ['Py2Exe', 'py2exe']
  },
  {
    name: 'ASPack',
    confidence: 0.9,
    canUnpack: false,
    signatures: ['.aspack', 'ASPack'],
    sectionPrefixes: ['.aspack']
  },
  {
    name: 'PECompact',
    confidence: 0.9,
    canUnpack: false,
    signatures: ['PECompact2', '.pec1', '.pec2'],
    sectionPrefixes: ['.pec']
  },
  {
    name: 'Themida',
    confidence: 0.9,
    canUnpack: false,
    signatures: ['Themida', '.themida', 'WinLicense'],
    sectionPrefixes: ['.themida']
  },
  {
    name: 'VMProtect',
    confidence: 0.9,
    canUnpack: false,
    signatures: ['.vmp0', '.vmp1', 'VMProtect'],
    sectionPrefixes: ['.vmp']
  },
  {
    name: 'MPRESS',
    confidence: 0.9,
    canUnpack: false,
    signatures: ['.MPRESS1', '.MPRESS2', 'MPRESS'],
    sectionPrefixes: ['.mpress']
  },
  {
    name: 'PETite',
    confidence: 0.9,
    canUnpack: false,
    signatures: ['.petite', 'PETite'],
    sectionPrefixes: ['.petite']
  },
  {
    name: 'Enigma',
    confidence: 0.85,
    canUnpack: false,
    signatures: ['Enigma', '.enigma'],
    sectionPrefixes: ['.enigma']
  }
];

const SUSPICIOUS_SECTION_NAMES = ['.packed', '.enigma', '.protect', '.hidden', 'CODE', 'DATA', 'BSS'];

/**
 * Detect if a binary is packed and identify the packer.
 */
export async function detectPacking(
  binary: string | Buffer,
  _binaryFilename?: string,
  sections?: SectionEntropy[]
): Promise<PackingDetectionResult> {
  const buffer = Buffer.isBuffer(binary) ? binary : fs.readFileSync(binary);

  const result: PackingDetectionResult = {
    isPacked: false,
    packers: [],
    entropy: {
      overall: calculateEntropy(buffer),
      sections: sections ?? []
    },
    suspiciousIndicators: []
  };

  // High entropy is suspicious
  if (result.entropy.overall > HIGH_ENTROPY_THRESHOLD) {
    result.suspiciousIndicators.push('High entropy detected (possible encryption/compression)');
    result.isPacked = true;
  }

  // Detect packers using config-driven approach
  const detected = detectPackersFromConfig(buffer, sections);
  result.packers = Array.from(detected.values()).sort((a, b) => b.confidence - a.confidence);

  if (result.packers.length > 0) {
    result.isPacked = true;
  }

  // Check for suspicious section names
  const suspiciousSections = checkSuspiciousSections(buffer);
  if (suspiciousSections.length > 0) {
    result.suspiciousIndicators.push(...suspiciousSections);
    result.isPacked = true;
  }

  return result;
}

/**
 * Detect packers using the configuration array.
 */
function detectPackersFromConfig(
  buffer: Buffer,
  sections?: SectionEntropy[]
): Map<string, PackerSignature> {
  const detected = new Map<string, PackerSignature>();

  for (const config of PACKER_CONFIGS) {
    const indicators: string[] = [];
    let maxConfidence = 0;

    // Check magic bytes (highest confidence)
    if (config.magicBytes) {
      const magic = Buffer.from(config.magicBytes.bytes);
      const limit = Math.min(buffer.length - magic.length, config.magicBytes.searchLimit ?? 2048);

      for (let i = 0; i < limit; i++) {
        if (buffer.subarray(i, i + magic.length).equals(magic)) {
          indicators.push(`${config.name} magic bytes`);
          maxConfidence = Math.max(maxConfidence, config.confidence + 0.05);
          break;
        }
      }
    }

    // Check string signatures
    for (const sig of config.signatures) {
      if (buffer.includes(Buffer.from(sig))) {
        indicators.push(`${config.name} signature: ${sig}`);
        maxConfidence = Math.max(maxConfidence, config.confidence);
      }
    }

    // Check section prefixes
    if (config.sectionPrefixes && sections) {
      for (const section of sections) {
        const name = section.name.toLowerCase();
        for (const prefix of config.sectionPrefixes) {
          if (name.startsWith(prefix)) {
            indicators.push(`${config.name} section: ${section.name}`);
            maxConfidence = Math.max(maxConfidence, config.confidence - 0.05);
          }
        }
      }
    }

    if (indicators.length > 0) {
      const existing = detected.get(config.name);
      if (existing) {
        // Merge indicators and take max confidence
        detected.set(config.name, {
          ...existing,
          confidence: Math.max(existing.confidence, maxConfidence),
          indicators: [...new Set([...existing.indicators, ...indicators])]
        });
      } else {
        detected.set(config.name, {
          name: config.name,
          confidence: maxConfidence,
          canUnpack: config.canUnpack,
          indicators
        });
      }
    }
  }

  return detected;
}

/**
 * Calculate Shannon entropy of a buffer.
 */
export function calculateEntropy(buffer: Buffer): number {
  const frequencies = new Array(256).fill(0);

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte !== undefined) {
      frequencies[byte]++;
    }
  }

  let entropy = 0;
  const length = buffer.length;

  for (let i = 0; i < 256; i++) {
    const freq = frequencies[i];
    if (freq === undefined || freq === 0) continue;
    const p = freq / length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check for suspicious section names that may indicate packing.
 */
function checkSuspiciousSections(buffer: Buffer): string[] {
  const suspicious: string[] = [];

  for (const name of SUSPICIOUS_SECTION_NAMES) {
    if (buffer.includes(Buffer.from(name))) {
      suspicious.push(`Suspicious section name: ${name}`);
    }
  }

  return suspicious;
}

/**
 * Attempt to automatically unpack a UPX-packed binary.
 */
export async function unpackUPX(
  binaryPath: string,
  outputPath?: string
): Promise<{ success: boolean; unpackedPath?: string; error?: string }> {
  const output = outputPath ?? binaryPath.replace(/(\.[^.]+)?$/, '_unpacked$1');

  logger.info('Attempting UPX unpacking', { input: binaryPath, output });

  return new Promise((resolve) => {
    const proc = spawn('upx', ['-d', binaryPath, '-o', output]);
    let stderr = '';

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      if (code === 0 && fs.existsSync(output)) {
        logger.info('UPX unpacking successful', { output });
        resolve({ success: true, unpackedPath: output });
      } else {
        logger.error('UPX unpacking failed', { code, stderr });
        resolve({ success: false, error: `UPX unpacking failed: ${stderr}` });
      }
    });

    proc.on('error', (err) => {
      logger.error('Failed to spawn UPX', { error: err.message });
      resolve({
        success: false,
        error: 'UPX tool not found. Install with: apt-get install upx (Linux) or brew install upx (macOS)'
      });
    });
  });
}

/**
 * Extract PyInstaller archive.
 */
export async function extractPyInstaller(
  binaryPath: string,
  outputDir?: string
): Promise<{ success: boolean; extractedPath?: string; error?: string }> {
  const output = outputDir ?? path.join(path.dirname(binaryPath), 'pyinstaller_extracted');

  logger.info('Attempting PyInstaller extraction', { input: binaryPath, output });

  if (!fs.existsSync(output)) {
    fs.mkdirSync(output, { recursive: true });
  }

  return new Promise((resolve) => {
    const proc = spawn('python3', ['-m', 'pyinstxtractor', binaryPath, '-o', output]);
    let stderr = '';

    proc.stdout.on('data', () => {});
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      if (code === 0 && fs.existsSync(output)) {
        logger.info('PyInstaller extraction successful', { output });
        resolve({ success: true, extractedPath: output });
      } else {
        logger.error('PyInstaller extraction failed', { code, stderr });
        resolve({ success: false, error: `PyInstaller extraction failed: ${stderr}` });
      }
    });

    proc.on('error', (err) => {
      logger.error('Failed to run pyinstxtractor', { error: err.message });
      resolve({
        success: false,
        error: 'pyinstxtractor not found. Install with: pip install pyinstxtractor'
      });
    });
  });
}

export async function unpackBinary(
  binaryPath: string,
  packer: string
): Promise<{
  success: boolean;
  method?: string;
  unpackedPath?: string;
  extractedDir?: string;
  error?: string;
}> {
  const normalized = packer.toLowerCase();

  if (normalized === 'upx') {
    const result = await unpackUPX(binaryPath);
    return {
      success: result.success,
      unpackedPath: result.unpackedPath,
      method: 'upx -d',
      error: result.error
    };
  }

  if (normalized === 'pyinstaller') {
    const result = await extractPyInstaller(binaryPath);
    return {
      success: result.success,
      extractedDir: result.extractedPath,
      method: 'pyinstxtractor',
      error: result.error
    };
  }

  return { success: false, error: `Unsupported packer: ${packer}` };
}
