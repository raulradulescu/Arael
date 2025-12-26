import * as fs from 'fs';
import { calculateEntropy } from './packing';
import { logger } from './logger';

export interface SectionPermissions {
  read: boolean;
  write: boolean;
  execute: boolean;
}

export interface SectionAnomaly {
  type: 'rwx' | 'high_entropy' | 'suspicious_name';
  severity: 'low' | 'medium' | 'high';
  description: string;
}

export interface SectionInfo {
  name: string;
  start: string;
  end: string;
  size: number;
  permissions: SectionPermissions;
  entropy: number;
  anomalies: SectionAnomaly[];
}

export interface SectionAnalysisResult {
  sections: SectionInfo[];
  totalAnomalies: number;
  highEntropyCount: number;
  rwxCount: number;
}

export interface SectionInput {
  name: string;
  start: string;
  end?: string;
  size: number;
  permissions: SectionPermissions;
}

const HIGH_ENTROPY_THRESHOLD = 7.5;

/**
 * Analyze PE/ELF sections for suspicious characteristics.
 */
export async function analyzeSections(
  target: string | SectionInput[],
  buffer?: Buffer
): Promise<SectionAnalysisResult> {
  if (Array.isArray(target)) {
    return analyzeSectionSpecs(target, buffer ?? Buffer.alloc(0));
  }

  const fileBuffer = fs.readFileSync(target);

  // Detect file type
  const isPE = fileBuffer.slice(0, 2).toString('ascii') === 'MZ';
  const isELF = fileBuffer.slice(0, 4).toString('ascii') === '\x7fELF';

  if (isPE) {
    return analyzePESections(fileBuffer);
  }

  if (isELF) {
    return analyzeELFSections(fileBuffer);
  }

  logger.warn('Unknown binary format, skipping section analysis');
  return {
    sections: [],
    totalAnomalies: 0,
    highEntropyCount: 0,
    rwxCount: 0
  };
}

function analyzeSectionSpecs(sections: SectionInput[], buffer: Buffer): SectionAnalysisResult {
  const analyzed: SectionInfo[] = [];
  let highEntropyCount = 0;
  let rwxCount = 0;
  let offset = 0;

  for (const section of sections) {
    const size = Math.max(0, section.size);
    const start = normalizeHex(section.start);
    const end = section.end ? normalizeHex(section.end) : formatHex((parseAddress(start) ?? 0) + size);

    // Treat the buffer as concatenated sections in order (unit-test helper).
    const sectionData = buffer.slice(offset, Math.min(offset + size, buffer.length));
    offset += size;

    const { section: analyzedSection, highEntropy, rwx } = buildSectionAnalysis({
      name: section.name,
      start,
      end,
      size,
      permissions: section.permissions,
      data: sectionData
    });

    analyzed.push(analyzedSection);
    if (highEntropy) highEntropyCount += 1;
    if (rwx) rwxCount += 1;
  }

  const totalAnomalies = analyzed.reduce((sum, section) => sum + section.anomalies.length, 0);

  return {
    sections: analyzed,
    totalAnomalies,
    highEntropyCount,
    rwxCount
  };
}

/**
 * Analyze PE (Windows) sections.
 */
function analyzePESections(buffer: Buffer): SectionAnalysisResult {
  const sections: SectionInfo[] = [];
  let highEntropyCount = 0;
  let rwxCount = 0;

  try {
    // Find PE header offset (at offset 0x3C)
    const peOffset = buffer.readUInt32LE(0x3c);

    // Check PE signature
    if (buffer.slice(peOffset, peOffset + 4).toString('ascii') !== 'PE\x00\x00') {
      logger.error('Invalid PE signature');
      return { sections: [], totalAnomalies: 0, highEntropyCount: 0, rwxCount: 0 };
    }

    // Read COFF header
    const numberOfSections = buffer.readUInt16LE(peOffset + 6);
    const optionalHeaderSize = buffer.readUInt16LE(peOffset + 20);

    // Section table starts after COFF header + optional header
    const sectionTableOffset = peOffset + 24 + optionalHeaderSize;

    // Parse each section (40 bytes each)
    for (let i = 0; i < numberOfSections; i++) {
      const sectionOffset = sectionTableOffset + i * 40;

      // Read section name (8 bytes)
      let name = '';
      for (let j = 0; j < 8; j++) {
        const char = buffer[sectionOffset + j];
        if (char === undefined || char === 0) break;
        name += String.fromCharCode(char);
      }

      const virtualSize = buffer.readUInt32LE(sectionOffset + 8);
      const virtualAddress = buffer.readUInt32LE(sectionOffset + 12);
      const rawSize = buffer.readUInt32LE(sectionOffset + 16);
      const rawOffset = buffer.readUInt32LE(sectionOffset + 20);
      const characteristics = buffer.readUInt32LE(sectionOffset + 36);

      // Calculate entropy for this section
      const sectionData = buffer.slice(rawOffset, Math.min(rawOffset + rawSize, buffer.length));
      const size = virtualSize > 0 ? virtualSize : rawSize;

      // Parse characteristics
      const IMAGE_SCN_MEM_READ = 0x40000000;
      const IMAGE_SCN_MEM_WRITE = 0x80000000;
      const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

      const permissions = {
        read: (characteristics & IMAGE_SCN_MEM_READ) !== 0,
        write: (characteristics & IMAGE_SCN_MEM_WRITE) !== 0,
        execute: (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0
      };

      const { section: analyzedSection, highEntropy, rwx } = buildSectionAnalysis({
        name,
        start: formatHex(virtualAddress),
        end: formatHex(virtualAddress + size),
        size,
        permissions,
        data: sectionData
      });

      sections.push(analyzedSection);
      if (highEntropy) highEntropyCount += 1;
      if (rwx) rwxCount += 1;
    }
  } catch (e) {
    logger.error('Failed to parse PE sections', { error: String(e) });
  }

  const totalAnomalies = sections.reduce((sum, s) => sum + s.anomalies.length, 0);

  return {
    sections,
    totalAnomalies,
    highEntropyCount,
    rwxCount
  };
}

/**
 * Analyze ELF (Linux) sections.
 */
function analyzeELFSections(buffer: Buffer): SectionAnalysisResult {
  const sections: SectionInfo[] = [];
  let highEntropyCount = 0;
  let rwxCount = 0;

  try {
    // Check ELF class (32-bit or 64-bit)
    const elfClass = buffer[4]; // 1 = 32-bit, 2 = 64-bit
    const is64Bit = elfClass === 2;

    // Read section header offset and count
    const sectionHeaderOffset = is64Bit
      ? Number(buffer.readBigUInt64LE(40) ?? 0)
      : (buffer.readUInt32LE(32) ?? 0);

    const sectionHeaderSize = buffer.readUInt16LE(is64Bit ? 58 : 46);
    const numberOfSections = buffer.readUInt16LE(is64Bit ? 60 : 48);
    const stringTableIndex = buffer.readUInt16LE(is64Bit ? 62 : 50);

    // Get string table section
    const stringTableHeaderOffset = sectionHeaderOffset + stringTableIndex * sectionHeaderSize;
    const stringTableDataOffset = is64Bit
      ? Number(buffer.readBigUInt64LE(stringTableHeaderOffset + 24) ?? 0)
      : (buffer.readUInt32LE(stringTableHeaderOffset + 16) ?? 0);

    // Parse each section
    for (let i = 0; i < numberOfSections; i++) {
      const headerOffset = sectionHeaderOffset + i * sectionHeaderSize;

      // Read section name offset
      const nameOffset = buffer.readUInt32LE(headerOffset);
      let name = '';
      let strOffset = stringTableDataOffset + nameOffset;
      while (strOffset < buffer.length) {
        const byte = buffer[strOffset++];
        if (byte === undefined || byte === 0) break;
        name += String.fromCharCode(byte);
      }

      const sectionType = buffer.readUInt32LE(headerOffset + 4);
      const flags = is64Bit
        ? Number(buffer.readBigUInt64LE(headerOffset + 8))
        : buffer.readUInt32LE(headerOffset + 8);

      const virtualAddress = is64Bit
        ? Number(buffer.readBigUInt64LE(headerOffset + 16))
        : buffer.readUInt32LE(headerOffset + 12);

      const offset = is64Bit
        ? Number(buffer.readBigUInt64LE(headerOffset + 24))
        : buffer.readUInt32LE(headerOffset + 16);

      const size = is64Bit
        ? Number(buffer.readBigUInt64LE(headerOffset + 32))
        : buffer.readUInt32LE(headerOffset + 20);

      // Skip null sections
      if (sectionType === 0 || size === 0) continue;

      // Calculate entropy
      const sectionData = buffer.slice(offset, Math.min(offset + size, buffer.length));

      // Parse flags
      const SHF_WRITE = 0x1;
      const SHF_ALLOC = 0x2;
      const SHF_EXECINSTR = 0x4;

      const permissions = {
        read: (flags & SHF_ALLOC) !== 0, // Allocated sections are readable
        write: (flags & SHF_WRITE) !== 0,
        execute: (flags & SHF_EXECINSTR) !== 0
      };

      const { section: analyzedSection, highEntropy, rwx } = buildSectionAnalysis({
        name: name || `<unnamed_${i}>`,
        start: formatHex(virtualAddress),
        end: formatHex(virtualAddress + size),
        size,
        permissions,
        data: sectionData
      });

      sections.push(analyzedSection);
      if (highEntropy) highEntropyCount += 1;
      if (rwx) rwxCount += 1;
    }
  } catch (e) {
    logger.error('Failed to parse ELF sections', { error: String(e) });
  }

  const totalAnomalies = sections.reduce((sum, s) => sum + s.anomalies.length, 0);

  return {
    sections,
    totalAnomalies,
    highEntropyCount,
    rwxCount
  };
}

function buildSectionAnalysis(params: {
  name: string;
  start: string;
  end: string;
  size: number;
  permissions: SectionPermissions;
  data: Buffer;
}): { section: SectionInfo; highEntropy: boolean; rwx: boolean } {
  const entropy = params.data.length > 0 ? calculateEntropy(params.data) : 0;
  const anomalies: SectionAnomaly[] = [];
  let highEntropy = false;
  let rwx = false;

  if (params.permissions.read && params.permissions.write && params.permissions.execute) {
    anomalies.push({
      type: 'rwx',
      severity: 'high',
      description: 'RWX permissions (suspicious)'
    });
    rwx = true;
  }

  if (params.permissions.execute && entropy >= HIGH_ENTROPY_THRESHOLD) {
    anomalies.push({
      type: 'high_entropy',
      severity: params.permissions.write ? 'high' : 'medium',
      description: 'High entropy in executable section (possible packing/encryption)'
    });
    highEntropy = true;
  }

  const suspiciousNameAnomaly = getSuspiciousNameAnomaly(params.name);
  if (suspiciousNameAnomaly) {
    anomalies.push(suspiciousNameAnomaly);
  }

  return {
    section: {
      name: params.name,
      start: normalizeHex(params.start),
      end: normalizeHex(params.end),
      size: params.size,
      permissions: params.permissions,
      entropy,
      anomalies
    },
    highEntropy,
    rwx
  };
}

function getSuspiciousNameAnomaly(name: string): SectionAnomaly | null {
  if (!name) return null;

  const lowerName = name.toLowerCase();
  if (isCommonSectionName(lowerName)) {
    return null;
  }

  if (isPackerSectionName(lowerName)) {
    return {
      type: 'suspicious_name',
      severity: 'medium',
      description: `Suspicious packer section name: ${name}`
    };
  }

  if (lowerName.startsWith('.')) {
    return {
      type: 'suspicious_name',
      severity: 'low',
      description: `Unusual section name: ${name}`
    };
  }

  return null;
}

function isPackerSectionName(name: string): boolean {
  const patterns = [
    /^\.upx\d*/i,
    /^\.aspack/i,
    /^\.themida/i,
    /^\.vmp/i,
    /^\.mpress/i,
    /^\.pec/i,
    /^\.petite/i,
    /^\.enigma/i
  ];

  return patterns.some((pattern) => pattern.test(name));
}

/**
 * Check if a section name is commonly seen in binaries.
 */
function isCommonSectionName(name: string): boolean {
  const commonNames = [
    '.text',
    '.data',
    '.bss',
    '.rodata',
    '.rdata',
    '.idata',
    '.edata',
    '.rsrc',
    '.reloc',
    '.init',
    '.fini',
    '.plt',
    '.got',
    '.dynsym',
    '.dynstr',
    '.symtab',
    '.strtab',
    '.shstrtab',
    '.comment',
    '.debug',
    '.pdata',
    '.xdata'
  ];

  return commonNames.includes(name);
}

function formatHex(value: number): string {
  return `0x${value.toString(16)}`;
}

function normalizeHex(value: string): string {
  const parsed = parseAddress(value);
  if (parsed === null) return value;
  return `0x${parsed.toString(16)}`;
}

function parseAddress(value: string): number | null {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;
  const parsed = trimmed.startsWith('0x')
    ? Number.parseInt(trimmed.slice(2), 16)
    : Number.parseInt(trimmed, 10);
  return Number.isNaN(parsed) ? null : parsed;
}
