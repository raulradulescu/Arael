import * as fs from 'fs';
import { validateBinary } from '../../utils/preflight';
import { hexdump as formatHexdump, bytesToHex } from '../../utils/hexdump';
import { mapElfVirtualAddressToFileOffset } from '../../utils/elf';

export interface HexdumpArgs {
  filepath: string;
  start: string;
  length?: number;
  width?: 8 | 16 | 32;
}

export interface HexdumpResult {
  address: string;
  length: number;
  bytes: string;
  formatted: string;
}

export async function hexdumpHandler(args: HexdumpArgs): Promise<HexdumpResult> {
  const { filepath, start, length = 256, width = 16 } = args;

  // Validate binary
  const preflight = await validateBinary(filepath);

  // Parse start address
  let startOffset: number;
  if (start.startsWith('0x') || start.startsWith('0X')) {
    startOffset = parseInt(start, 16);
  } else {
    startOffset = parseInt(start, 10);
  }

  if (isNaN(startOffset)) {
    throw new Error(`Invalid start address: ${start}`);
  }

  const mapping = mapElfVirtualAddressToFileOffset(preflight.absolutePath, startOffset);
  const fileOffset = mapping ? mapping.fileOffset : startOffset;

  // Read bytes from file
  const fd = fs.openSync(preflight.absolutePath, 'r');
  const stats = fs.fstatSync(fd);

  // Clamp length to file size
  const maxFromFile = stats.size - fileOffset;
  const maxFromSegment = mapping ? Math.min(maxFromFile, mapping.maxLength) : maxFromFile;
  const actualLength = Math.min(length, maxFromSegment);
  if (actualLength <= 0) {
    fs.closeSync(fd);
    throw new Error(`Address ${start} is beyond file size (${stats.size} bytes)`);
  }

  const buffer = Buffer.alloc(actualLength);
  fs.readSync(fd, buffer, 0, actualLength, fileOffset);
  fs.closeSync(fd);

  // Format hexdump
  const formatted = formatHexdump(buffer, {
    width: width as 8 | 16 | 32,
    startAddress: startOffset
  });

  return {
    address: `0x${startOffset.toString(16)}`,
    length: actualLength,
    bytes: bytesToHex(buffer),
    formatted
  };
}
