import * as fs from 'fs';
import * as path from 'path';

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]); // \x7fELF
const MZ_MAGIC = Buffer.from([0x4d, 0x5a]); // MZ
const MACHO_MAGIC_32 = Buffer.from([0xce, 0xfa, 0xed, 0xfe]); // MH_MAGIC (little-endian)
const MACHO_MAGIC_64 = Buffer.from([0xcf, 0xfa, 0xed, 0xfe]); // MH_MAGIC_64 (little-endian)
const MACHO_CIGAM_32 = Buffer.from([0xfe, 0xed, 0xfa, 0xce]); // MH_CIGAM (big-endian)
const MACHO_CIGAM_64 = Buffer.from([0xfe, 0xed, 0xfa, 0xcf]); // MH_CIGAM_64 (big-endian)
const MACHO_FAT = Buffer.from([0xca, 0xfe, 0xba, 0xbe]); // FAT_MAGIC (universal binary)

/**
 * Cheap synchronous check for the ELF magic number.
 * Returns false for missing/unreadable files or any non-ELF content.
 */
export function isElfBinary(filepath: string): boolean {
  try {
    const fd = fs.openSync(filepath, 'r');
    try {
      const header = Buffer.alloc(4);
      const bytesRead = fs.readSync(fd, header, 0, 4, 0);
      return bytesRead === 4 && header.equals(ELF_MAGIC);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

export interface PreflightResult {
  valid: boolean;
  filepath: string;
  absolutePath: string;
  size: number;
  format: 'ELF' | 'PE' | 'MZ' | 'Mach-O' | 'COM' | 'RAW' | 'unknown';
  architecture?: string;
  machine?: string;
  bits?: 16 | 32 | 64;
  endianness?: 'little' | 'big';
  entryPoint?: string;
  imageBase?: string;
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

  // Read header bytes
  const fd = fs.openSync(absolutePath, 'r');
  const header = Buffer.alloc(512);
  fs.readSync(fd, header, 0, header.length, 0);
  fs.closeSync(fd);

  const ext = path.extname(absolutePath).toLowerCase();

  if (header.subarray(0, 4).equals(ELF_MAGIC)) {
    return parseElf(filepath, absolutePath, stats.size, header);
  }

  if (header.subarray(0, 2).equals(MZ_MAGIC)) {
    return parseMzOrPe(filepath, absolutePath, stats.size, header);
  }

  // Check for Mach-O formats
  const magic4 = header.subarray(0, 4);
  if (magic4.equals(MACHO_MAGIC_64) || magic4.equals(MACHO_CIGAM_64)) {
    return parseMachO(filepath, absolutePath, stats.size, header, 64, magic4.equals(MACHO_CIGAM_64));
  }
  if (magic4.equals(MACHO_MAGIC_32) || magic4.equals(MACHO_CIGAM_32)) {
    return parseMachO(filepath, absolutePath, stats.size, header, 32, magic4.equals(MACHO_CIGAM_32));
  }
  if (magic4.equals(MACHO_FAT)) {
    // Universal binary - report as 64-bit by default
    return parseMachO(filepath, absolutePath, stats.size, header, 64, false);
  }

  if (ext === '.com') {
    return {
      valid: true,
      filepath,
      absolutePath,
      size: stats.size,
      format: 'COM',
      architecture: '8086',
      machine: '8086',
      bits: 16,
      endianness: 'little',
      entryPoint: '0x100',
      imageBase: '0x0'
    };
  }

  if (ext === '.bin' && header.length >= 512 && header[510] === 0x55 && header[511] === 0xaa) {
    return {
      valid: true,
      filepath,
      absolutePath,
      size: stats.size,
      format: 'RAW',
      architecture: '8086',
      machine: '8086',
      bits: 16,
      endianness: 'little',
      entryPoint: '0x7c00',
      imageBase: '0x0'
    };
  }

  throw new PreflightError(
    `Unsupported binary format: ${absolutePath}`,
    'UNSUPPORTED_FORMAT'
  );
}

function parseElf(
  filepath: string,
  absolutePath: string,
  size: number,
  header: Buffer
): PreflightResult {
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

  const eMachine = isLittleEndian ? header.readUInt16LE(18) : header.readUInt16BE(18);
  const machine = machineFromElf(eMachine);
  const bits = is64Bit ? 64 : 32;

  return {
    valid: true,
    filepath,
    absolutePath,
    size,
    format: 'ELF',
    architecture: machine,
    machine,
    bits,
    endianness
  };
}

function parseMzOrPe(
  filepath: string,
  absolutePath: string,
  size: number,
  header: Buffer
): PreflightResult {
  const e_lfanew = header.readUInt32LE(0x3c);
  let peHeader: Buffer | null = null;

  if (e_lfanew > 0) {
    if (e_lfanew + 4 <= header.length) {
      peHeader = header.subarray(e_lfanew);
    } else {
      try {
        const fd = fs.openSync(absolutePath, 'r');
        const buffer = Buffer.alloc(256);
        const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, e_lfanew);
        fs.closeSync(fd);
        if (bytesRead >= 4) {
          peHeader = buffer.subarray(0, bytesRead);
        }
      } catch {
        peHeader = null;
      }
    }
  }

  const hasPeHeader =
    !!peHeader &&
    peHeader.length >= 4 &&
    peHeader.readUInt32LE(0) === 0x00004550;

  if (!hasPeHeader) {
    const ip = header.readUInt16LE(0x14);
    const cs = header.readUInt16LE(0x16);
    const entry = (cs << 4) + ip;

    return {
      valid: true,
      filepath,
      absolutePath,
      size,
      format: 'MZ',
      architecture: '8086',
      machine: '8086',
      bits: 16,
      endianness: 'little',
      entryPoint: `0x${entry.toString(16)}`,
      imageBase: '0x0'
    };
  }

  const machine = peHeader!.readUInt16LE(4);
  const optionalHeaderOffset = 24;
  if (peHeader!.length < optionalHeaderOffset + 28) {
    throw new PreflightError(
      `Unsupported PE header size: ${absolutePath}`,
      'UNSUPPORTED_FORMAT'
    );
  }

  const magic = peHeader!.readUInt16LE(optionalHeaderOffset);
  const bits = magic === 0x20b ? 64 : 32;
  const addressOfEntryPoint = peHeader!.readUInt32LE(optionalHeaderOffset + 16);
  const imageBase = magic === 0x20b
    ? Number(peHeader!.readBigUInt64LE(optionalHeaderOffset + 24))
    : peHeader!.readUInt32LE(optionalHeaderOffset + 28);

  return {
    valid: true,
    filepath,
    absolutePath,
    size,
    format: 'PE',
    architecture: machineFromPe(machine),
    machine: machineFromPe(machine),
    bits,
    endianness: 'little',
    entryPoint: `0x${addressOfEntryPoint.toString(16)}`,
    imageBase: `0x${imageBase.toString(16)}`
  };
}

function parseMachO(
  filepath: string,
  absolutePath: string,
  size: number,
  header: Buffer,
  bits: 32 | 64,
  isBigEndian: boolean
): PreflightResult {
  // CPU type is at offset 4 in Mach-O header
  const cpuType = isBigEndian ? header.readUInt32BE(4) : header.readUInt32LE(4);
  const machine = machineFromMachO(cpuType);

  return {
    valid: true,
    filepath,
    absolutePath,
    size,
    format: 'Mach-O',
    architecture: machine,
    machine,
    bits,
    endianness: isBigEndian ? 'big' : 'little'
  };
}

function machineFromMachO(cpuType: number): string {
  // Mask off CPU_ARCH_ABI64 (0x01000000) for comparison
  const baseCpuType = cpuType & ~0x01000000;
  switch (baseCpuType) {
    case 7:   // CPU_TYPE_X86
      return cpuType & 0x01000000 ? 'x86_64' : 'i386';
    case 12:  // CPU_TYPE_ARM
      return cpuType & 0x01000000 ? 'aarch64' : 'arm';
    case 18:  // CPU_TYPE_POWERPC
      return cpuType & 0x01000000 ? 'ppc64' : 'ppc';
    default:
      return `unknown(0x${cpuType.toString(16)})`;
  }
}

function machineFromElf(machine: number): string {
  switch (machine) {
    case 0x03:
      return 'i386';
    case 0x3e:
      return 'x86_64';
    case 0x28:
      return 'arm';
    case 0xb7:
      return 'aarch64';
    case 0xf3:
      return 'riscv';
    case 0x08:
      return 'mips';
    case 0x14:
      return 'ppc';
    case 0x15:
      return 'ppc64';
    default:
      return `unknown(0x${machine.toString(16)})`;
  }
}

function machineFromPe(machine: number): string {
  switch (machine) {
    case 0x14c:
      return 'i386';
    case 0x8664:
      return 'x86_64';
    case 0x1c0:
      return 'arm';
    case 0x1c4:
      return 'armnt';  // ARM Thumb-2 little-endian
    case 0xaa64:
      return 'aarch64';
    default:
      return `unknown(0x${machine.toString(16)})`;
  }
}

/**
 * Get Ghidra processor/language ID for architecture
 */
export function getGhidraLanguageId(architecture: string, bits: number): string {
  const arch = architecture.toLowerCase();

  if (arch === 'x86_64' || arch === 'amd64') {
    return 'x86:LE:64:default';
  }
  if (arch === 'i386' || arch === 'x86') {
    return 'x86:LE:32:default';
  }
  if (arch === '8086') {
    return 'x86:LE:16:Real Mode';
  }
  if (arch === 'arm' || arch === 'armnt') {
    return 'ARM:LE:32:v8';
  }
  if (arch === 'aarch64' || arch === 'arm64') {
    return 'AARCH64:LE:64:v8A';
  }
  if (arch === 'mips') {
    return bits === 64 ? 'MIPS:BE:64:default' : 'MIPS:BE:32:default';
  }
  if (arch === 'ppc' || arch === 'powerpc') {
    return 'PowerPC:BE:32:default';
  }
  if (arch === 'ppc64') {
    return 'PowerPC:BE:64:default';
  }
  if (arch === 'riscv') {
    return bits === 64 ? 'RISCV:LE:64:default' : 'RISCV:LE:32:default';
  }

  return 'default';
}

/**
 * List of supported architectures
 */
export const SUPPORTED_ARCHITECTURES = [
  { name: 'x86_64', description: '64-bit x86 (AMD64/Intel 64)', status: 'full' },
  { name: 'i386', description: '32-bit x86 (IA-32)', status: 'full' },
  { name: '8086', description: '16-bit x86 (Real Mode/DOS)', status: 'full' },
  { name: 'arm', description: '32-bit ARM', status: 'supported' },
  { name: 'aarch64', description: '64-bit ARM (ARM64)', status: 'supported' },
  { name: 'mips', description: 'MIPS (32/64-bit)', status: 'basic' },
  { name: 'ppc', description: 'PowerPC (32/64-bit)', status: 'basic' },
  { name: 'riscv', description: 'RISC-V (32/64-bit)', status: 'basic' },
] as const;
