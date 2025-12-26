import * as fs from 'fs';

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const PT_LOAD = 1;

export interface ElfAddressMapping {
  fileOffset: number;
  maxLength: number;
}

function readUInt16(buf: Buffer, offset: number, littleEndian: boolean): number {
  return littleEndian ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset);
}

function readUInt32(buf: Buffer, offset: number, littleEndian: boolean): number {
  return littleEndian ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
}

function readUInt64(buf: Buffer, offset: number, littleEndian: boolean): number {
  const value = littleEndian ? buf.readBigUInt64LE(offset) : buf.readBigUInt64BE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('ELF value exceeds MAX_SAFE_INTEGER');
  }
  return Number(value);
}

/**
 * Map a virtual address to a file offset using ELF program headers.
 * Returns null if the address is not within a loadable file-backed segment.
 */
export function mapElfVirtualAddressToFileOffset(
  filepath: string,
  virtualAddress: number
): ElfAddressMapping | null {
  const fd = fs.openSync(filepath, 'r');
  try {
    const header = Buffer.alloc(64);
    const bytesRead = fs.readSync(fd, header, 0, header.length, 0);
    if (bytesRead < 16 || !header.subarray(0, 4).equals(ELF_MAGIC)) {
      return null;
    }

    const elfClass = header[4];
    const dataEncoding = header[5];
    const is64Bit = elfClass === 2;
    const is32Bit = elfClass === 1;
    const littleEndian = dataEncoding === 1;
    const bigEndian = dataEncoding === 2;

    if ((!is64Bit && !is32Bit) || (!littleEndian && !bigEndian)) {
      return null;
    }

    const phoff = is64Bit
      ? readUInt64(header, 32, littleEndian)
      : readUInt32(header, 28, littleEndian);
    const phentsize = is64Bit
      ? readUInt16(header, 54, littleEndian)
      : readUInt16(header, 42, littleEndian);
    const phnum = is64Bit
      ? readUInt16(header, 56, littleEndian)
      : readUInt16(header, 44, littleEndian);

    const minPhentsize = is64Bit ? 56 : 32;
    if (phoff <= 0 || phnum <= 0 || phentsize < minPhentsize) {
      return null;
    }

    for (let i = 0; i < phnum; i++) {
      const ph = Buffer.alloc(phentsize);
      const offset = phoff + i * phentsize;
      const phRead = fs.readSync(fd, ph, 0, phentsize, offset);
      if (phRead < minPhentsize) {
        break;
      }

      const pType = readUInt32(ph, 0, littleEndian);
      if (pType !== PT_LOAD) {
        continue;
      }

      const pOffset = is64Bit
        ? readUInt64(ph, 8, littleEndian)
        : readUInt32(ph, 4, littleEndian);
      const pVaddr = is64Bit
        ? readUInt64(ph, 16, littleEndian)
        : readUInt32(ph, 8, littleEndian);
      const pFilesz = is64Bit
        ? readUInt64(ph, 32, littleEndian)
        : readUInt32(ph, 16, littleEndian);
      const pMemsz = is64Bit
        ? readUInt64(ph, 40, littleEndian)
        : readUInt32(ph, 20, littleEndian);

      if (virtualAddress < pVaddr || virtualAddress >= pVaddr + pMemsz) {
        continue;
      }

      const offsetInSegment = virtualAddress - pVaddr;
      if (offsetInSegment >= pFilesz) {
        return null;
      }

      return {
        fileOffset: pOffset + offsetInSegment,
        maxLength: pFilesz - offsetInSegment
      };
    }

    return null;
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}
