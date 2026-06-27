export interface HexdumpOptions {
  width?: 8 | 16 | 32;
  startAddress?: number;
  uppercase?: boolean;
}

/**
 * Generate a formatted hexdump from a buffer.
 */
export function hexdump(
  buffer: Buffer,
  options: HexdumpOptions = {}
): string {
  const { width = 16, startAddress = 0, uppercase = false } = options;
  const lines: string[] = [];
  const formatByte = uppercase
    ? (b: number) => b.toString(16).toUpperCase().padStart(2, '0')
    : (b: number) => b.toString(16).padStart(2, '0');

  for (let offset = 0; offset < buffer.length; offset += width) {
    const address = (startAddress + offset).toString(16).padStart(8, '0');
    const slice = buffer.subarray(offset, offset + width);

    // Hex bytes
    const hexParts: string[] = [];
    for (let i = 0; i < width; i++) {
      if (i < slice.length) {
        hexParts.push(formatByte(slice[i]!));
      } else {
        hexParts.push('  ');
      }
    }

    // Group bytes for readability (8 bytes per group)
    const hexGroups: string[] = [];
    for (let i = 0; i < hexParts.length; i += 8) {
      hexGroups.push(hexParts.slice(i, i + 8).join(' '));
    }
    const hex = hexGroups.join('  ');

    // ASCII representation
    const ascii = Array.from(slice)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'))
      .join('');

    lines.push(`${address}  ${hex}  |${ascii}|`);
  }

  return lines.join('\n');
}

/**
 * Convert bytes to a compact hex string.
 */
export function bytesToHex(buffer: Buffer, separator = ' '): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(separator);
}

/**
 * Parse a hex string (with or without separators) into a buffer.
 * Inverse of {@link bytesToHex}. Throws on odd-length input.
 */
export function hexToBytes(hex: string): Buffer {
  const compact = hex.replace(/[\s:]/g, '');
  if (compact.length % 2 !== 0) {
    throw new Error(`Invalid hex string: odd length (${compact.length})`);
  }
  if (compact.length > 0 && !/^[0-9a-fA-F]+$/.test(compact)) {
    throw new Error('Invalid hex string: contains non-hex characters');
  }
  const bytes = new Uint8Array(compact.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(compact.substr(i * 2, 2), 16);
  }
  return Buffer.from(bytes);
}
