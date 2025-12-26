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

/**
 * Detect if a binary is packed and identify the packer.
 */
export async function detectPacking(
  binary: string | Buffer,
  binaryFilename?: string,
  sections?: SectionEntropy[]
): Promise<PackingDetectionResult> {
  const buffer = Buffer.isBuffer(binary) ? binary : fs.readFileSync(binary);
  const filename = binaryFilename ?? (typeof binary === 'string' ? path.basename(binary) : 'unknown');

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

  const detected = new Map<string, PackerSignature>();
  const registerPacker = (packer: PackerSignature | null): void => {
    if (!packer) return;
    const existing = detected.get(packer.name);
    if (!existing) {
      detected.set(packer.name, packer);
      return;
    }

    const indicators = Array.from(new Set([...existing.indicators, ...packer.indicators]));
    detected.set(packer.name, {
      ...existing,
      confidence: Math.max(existing.confidence, packer.confidence),
      canUnpack: existing.canUnpack || packer.canUnpack,
      indicators,
      version: existing.version ?? packer.version
    });
  };

  // Buffer-based detection
  registerPacker(checkUPX(buffer));
  registerPacker(checkPyInstaller(buffer, filename));
  registerPacker(checkPy2Exe(buffer));
  registerPacker(checkASPack(buffer));
  registerPacker(checkPECompact(buffer));
  registerPacker(checkThemida(buffer));
  registerPacker(checkVMProtect(buffer));
  registerPacker(checkMPress(buffer));
  registerPacker(checkPETite(buffer));
  registerPacker(checkEnigma(buffer));

  // Section-based detection
  if (sections && sections.length > 0) {
    registerSectionPackers(sections, registerPacker);
  }

  result.packers = Array.from(detected.values()).sort((a, b) => b.confidence - a.confidence);
  if (result.packers.length > 0) {
    result.isPacked = true;
  }

  // Check for suspicious section names in raw buffer
  const suspiciousSections = checkSuspiciousSections(buffer);
  if (suspiciousSections.length > 0) {
    result.suspiciousIndicators.push(...suspiciousSections);
    result.isPacked = true;
  }

  return result;
}

/**
 * Calculate Shannon entropy of a buffer.
 */
export function calculateEntropy(buffer: Buffer): number {
  const frequencies = new Array(256).fill(0);

  // Count byte frequencies
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte !== undefined) {
      frequencies[byte]++;
    }
  }

  // Calculate entropy
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
 * Check for UPX packer signature.
 */
function checkUPX(buffer: Buffer): PackerSignature | null {
  // UPX magic bytes: "UPX!" at various offsets
  const upxMagic = Buffer.from([0x55, 0x50, 0x58, 0x21]); // "UPX!"

  for (let i = 0; i < Math.min(buffer.length - 4, 2048); i++) {
    if (buffer.slice(i, i + 4).equals(upxMagic)) {
      return {
        name: 'UPX',
        confidence: 0.95,
        canUnpack: true,
        indicators: ['UPX magic bytes']
      };
    }
  }

  // Check for UPX section names
  if (buffer.includes(Buffer.from('UPX0')) || buffer.includes(Buffer.from('UPX1'))) {
    return {
      name: 'UPX',
      confidence: 0.9,
      canUnpack: true,
      indicators: ['UPX section names']
    };
  }

  return null;
}

/**
 * Check for PyInstaller signature.
 */
function checkPyInstaller(buffer: Buffer, _filename: string): PackerSignature | null {
  // PyInstaller magic: "MEI\x0c\x0b\x0a\x0b\x0e"
  const pyiMagic = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]);

  for (let i = 0; i < Math.min(buffer.length - 8, 4096); i++) {
    if (buffer.slice(i, i + 8).equals(pyiMagic)) {
      return {
        name: 'PyInstaller',
        confidence: 0.98,
        canUnpack: true,
        indicators: ['PyInstaller magic bytes']
      };
    }
  }

  // Check for PyInstaller strings
  if (
    buffer.includes(Buffer.from('pyi-runtime-tmpdir')) ||
    buffer.includes(Buffer.from('PyInstaller'))
  ) {
    return {
      name: 'PyInstaller',
      confidence: 0.85,
      canUnpack: true,
      indicators: ['PyInstaller strings']
    };
  }

  return null;
}

/**
 * Check for Py2Exe signature.
 */
function checkPy2Exe(buffer: Buffer): PackerSignature | null {
  if (buffer.includes(Buffer.from('Py2Exe')) || buffer.includes(Buffer.from('py2exe'))) {
    return {
      name: 'Py2Exe',
      confidence: 0.85,
      canUnpack: false,
      indicators: ['Py2Exe strings']
    };
  }

  return null;
}

/**
 * Check for ASPack packer.
 */
function checkASPack(buffer: Buffer): PackerSignature | null {
  if (buffer.includes(Buffer.from('.aspack')) || buffer.includes(Buffer.from('ASPack'))) {
    return {
      name: 'ASPack',
      confidence: 0.9,
      canUnpack: false,
      indicators: ['ASPack signature']
    };
  }
  return null;
}

/**
 * Check for PECompact packer.
 */
function checkPECompact(buffer: Buffer): PackerSignature | null {
  if (
    buffer.includes(Buffer.from('PECompact2')) ||
    buffer.includes(Buffer.from('.pec1')) ||
    buffer.includes(Buffer.from('.pec2'))
  ) {
    return {
      name: 'PECompact',
      confidence: 0.9,
      canUnpack: false,
      indicators: ['PECompact signature']
    };
  }
  return null;
}

/**
 * Check for Themida/WinLicense packer.
 */
function checkThemida(buffer: Buffer): PackerSignature | null {
  if (
    buffer.includes(Buffer.from('Themida')) ||
    buffer.includes(Buffer.from('.themida')) ||
    buffer.includes(Buffer.from('WinLicense'))
  ) {
    return {
      name: 'Themida',
      confidence: 0.9,
      canUnpack: false,
      indicators: ['Themida signature']
    };
  }
  return null;
}

/**
 * Check for VMProtect packer.
 */
function checkVMProtect(buffer: Buffer): PackerSignature | null {
  if (
    buffer.includes(Buffer.from('.vmp0')) ||
    buffer.includes(Buffer.from('.vmp1')) ||
    buffer.includes(Buffer.from('VMProtect'))
  ) {
    return {
      name: 'VMProtect',
      confidence: 0.9,
      canUnpack: false,
      indicators: ['VMProtect signature']
    };
  }
  return null;
}

/**
 * Check for MPRESS packer.
 */
function checkMPress(buffer: Buffer): PackerSignature | null {
  if (
    buffer.includes(Buffer.from('.MPRESS1')) ||
    buffer.includes(Buffer.from('.MPRESS2')) ||
    buffer.includes(Buffer.from('MPRESS'))
  ) {
    return {
      name: 'MPRESS',
      confidence: 0.9,
      canUnpack: false,
      indicators: ['MPRESS signature']
    };
  }
  return null;
}

/**
 * Check for PETite packer.
 */
function checkPETite(buffer: Buffer): PackerSignature | null {
  if (buffer.includes(Buffer.from('.petite')) || buffer.includes(Buffer.from('PETite'))) {
    return {
      name: 'PETite',
      confidence: 0.9,
      canUnpack: false,
      indicators: ['PETite signature']
    };
  }
  return null;
}

/**
 * Check for Enigma packer.
 */
function checkEnigma(buffer: Buffer): PackerSignature | null {
  if (buffer.includes(Buffer.from('Enigma')) || buffer.includes(Buffer.from('.enigma'))) {
    return {
      name: 'Enigma',
      confidence: 0.85,
      canUnpack: false,
      indicators: ['Enigma strings']
    };
  }
  return null;
}

function registerSectionPackers(
  sections: SectionEntropy[],
  registerPacker: (packer: PackerSignature | null) => void
): void {
  for (const section of sections) {
    const name = section.name.toLowerCase();
    if (name.startsWith('.upx')) {
      registerPacker({
        name: 'UPX',
        confidence: 0.9,
        canUnpack: true,
        indicators: ['UPX section names']
      });
    }
    if (name.startsWith('.aspack')) {
      registerPacker({
        name: 'ASPack',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['ASPack section names']
      });
    }
    if (name.startsWith('.themida')) {
      registerPacker({
        name: 'Themida',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['Themida section names']
      });
    }
    if (name.startsWith('.vmp')) {
      registerPacker({
        name: 'VMProtect',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['VMProtect section names']
      });
    }
    if (name.startsWith('.pec')) {
      registerPacker({
        name: 'PECompact',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['PECompact section names']
      });
    }
    if (name.startsWith('.mpress')) {
      registerPacker({
        name: 'MPRESS',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['MPRESS section names']
      });
    }
    if (name.startsWith('.petite')) {
      registerPacker({
        name: 'PETite',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['PETite section names']
      });
    }
    if (name.startsWith('.enigma')) {
      registerPacker({
        name: 'Enigma',
        confidence: 0.85,
        canUnpack: false,
        indicators: ['Enigma section names']
      });
    }
  }
}

/**
 * Check for suspicious section names that may indicate packing.
 */
function checkSuspiciousSections(buffer: Buffer): string[] {
  const suspicious: string[] = [];
  const suspiciousNames = [
    '.packed',
    '.enigma',
    '.protect',
    '.hidden',
    'CODE',
    'DATA',
    'BSS'
  ];

  for (const name of suspiciousNames) {
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
    // Try to use upx command-line tool
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
        resolve({
          success: false,
          error: `UPX unpacking failed: ${stderr}`
        });
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

  // Ensure output directory exists
  if (!fs.existsSync(output)) {
    fs.mkdirSync(output, { recursive: true });
  }

  return new Promise((resolve) => {
    // Try to use pyinstxtractor
    const proc = spawn('python3', ['-m', 'pyinstxtractor', binaryPath, '-o', output]);

    let stderr = '';
    let stdout = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      if (code === 0 && fs.existsSync(output)) {
        logger.info('PyInstaller extraction successful', { output });
        resolve({ success: true, extractedPath: output });
      } else {
        logger.error('PyInstaller extraction failed', { code, stderr });
        resolve({
          success: false,
          error: `PyInstaller extraction failed: ${stderr}`
        });
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

  return {
    success: false,
    error: `Unsupported packer: ${packer}`
  };
}
