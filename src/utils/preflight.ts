import * as fs from 'fs';
import * as path from 'path';

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]); // \x7fELF

export interface PreflightResult {
  valid: boolean;
  filepath: string;
  absolutePath: string;
  size: number;
  format: 'ELF' | 'unknown';
  architecture?: string;
  endianness?: 'little' | 'big';
}

export class PreflightError extends Error {
  constructor(
    message: string,
    public readonly code: 'FILE_NOT_FOUND' | 'NOT_READABLE' | 'UNSUPPORTED_FORMAT' | 'EMPTY_FILE'
  ) {
    super(message);
    this.name = 'PreflightError';
  }
}

/**
 * Validates that a file exists, is readable, and is a supported binary format.
 * For v1.0, only ELF x86_64 binaries are supported.
 */
export async function validateBinary(filepath: string): Promise<PreflightResult> {
  const absolutePath = path.resolve(filepath);

  // Check file exists
  if (!fs.existsSync(absolutePath)) {
    throw new PreflightError(
      `File does not exist: ${absolutePath}`,
      'FILE_NOT_FOUND'
    );
  }

  // Check file is readable
  try {
    fs.accessSync(absolutePath, fs.constants.R_OK);
  } catch {
    throw new PreflightError(
      `File is not readable: ${absolutePath}`,
      'NOT_READABLE'
    );
  }

  // Get file stats
  const stats = fs.statSync(absolutePath);
  if (stats.size === 0) {
    throw new PreflightError(
      `File is empty: ${absolutePath}`,
      'EMPTY_FILE'
    );
  }

  // Read magic bytes
  const fd = fs.openSync(absolutePath, 'r');
  const header = Buffer.alloc(64); // ELF header is 64 bytes for ELF64
  fs.readSync(fd, header, 0, header.length, 0);
  fs.closeSync(fd);

  // Check ELF magic
  if (!header.subarray(0, 4).equals(ELF_MAGIC)) {
    throw new PreflightError(
      `Not an ELF binary (unsupported format in v1.0): ${absolutePath}`,
      'UNSUPPORTED_FORMAT'
    );
  }

  // Detect architecture from ELF header
  // Byte 4: EI_CLASS (1 = 32-bit, 2 = 64-bit)
  // Byte 5: EI_DATA (1 = little endian, 2 = big endian)
  const is64Bit = header[4] === 2;
  const isLittleEndian = header[5] === 1;
  const isBigEndian = header[5] === 2;

  const endianness = isLittleEndian ? 'little' : isBigEndian ? 'big' : undefined;
  if (!endianness) {
    throw new PreflightError(
      `Unknown ELF endianness: ${absolutePath}`,
      'UNSUPPORTED_FORMAT'
    );
  }

  const eMachine = header.readUInt16LE(18);
  const isX86_64 = eMachine === 0x3e;

  if (!is64Bit || !isLittleEndian || !isX86_64) {
    throw new PreflightError(
      `Unsupported ELF architecture (v1.0 supports x86_64 only): ${absolutePath}`,
      'UNSUPPORTED_FORMAT'
    );
  }

  return {
    valid: true,
    filepath,
    absolutePath,
    size: stats.size,
    format: 'ELF',
    architecture: 'x86_64',
    endianness
  };
}

/**
 * Quick check if a file looks like an ELF binary.
 * Does not throw, returns boolean.
 */
export function isElfBinary(filepath: string): boolean {
  try {
    if (!fs.existsSync(filepath)) return false;

    const fd = fs.openSync(filepath, 'r');
    const magic = Buffer.alloc(4);
    fs.readSync(fd, magic, 0, 4, 0);
    fs.closeSync(fd);

    return magic.equals(ELF_MAGIC);
  } catch {
    return false;
  }
}
