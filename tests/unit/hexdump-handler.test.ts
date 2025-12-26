import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { hexdumpHandler } from '../../src/mcp/handlers/hexdump';

function createElfWithSegment(): { filePath: string; vaddr: number; data: Buffer } {
  const tempDir = os.tmpdir();
  const filePath = path.join(tempDir, `arael_test_hexdump_${Date.now()}.bin`);

  const vaddr = 0x400000;
  const fileOffset = 0x100;
  const segmentSize = 0x40;
  const segmentMemSize = 0x80;

  const header = Buffer.alloc(64, 0);
  header[0] = 0x7f;
  header[1] = 0x45;
  header[2] = 0x4c;
  header[3] = 0x46;
  header[4] = 2; // ELF64
  header[5] = 1; // little endian
  header[6] = 1; // EI_VERSION
  header.writeUInt16LE(2, 16); // e_type = EXEC
  header.writeUInt16LE(0x3e, 18); // e_machine = x86_64
  header.writeUInt32LE(1, 20); // e_version
  header.writeBigUInt64LE(BigInt(vaddr), 24); // e_entry
  header.writeBigUInt64LE(BigInt(64), 32); // e_phoff
  header.writeUInt16LE(64, 52); // e_ehsize
  header.writeUInt16LE(56, 54); // e_phentsize
  header.writeUInt16LE(1, 56); // e_phnum

  const ph = Buffer.alloc(56, 0);
  ph.writeUInt32LE(1, 0); // PT_LOAD
  ph.writeUInt32LE(5, 4); // R + X
  ph.writeBigUInt64LE(BigInt(fileOffset), 8);
  ph.writeBigUInt64LE(BigInt(vaddr), 16);
  ph.writeBigUInt64LE(BigInt(vaddr), 24);
  ph.writeBigUInt64LE(BigInt(segmentSize), 32);
  ph.writeBigUInt64LE(BigInt(segmentMemSize), 40);
  ph.writeBigUInt64LE(BigInt(0x1000), 48);

  const data = Buffer.from(
    Array.from({ length: segmentSize }, (_, i) => i & 0xff)
  );

  const fileSize = fileOffset + segmentSize;
  const file = Buffer.alloc(fileSize, 0);
  header.copy(file, 0);
  ph.copy(file, 64);
  data.copy(file, fileOffset);

  fs.writeFileSync(filePath, file);

  return { filePath, vaddr, data };
}

describe('hexdumpHandler', () => {
  it('should map virtual address to file offset', async () => {
    const { filePath, vaddr, data } = createElfWithSegment();

    try {
      const result = await hexdumpHandler({
        filepath: filePath,
        start: `0x${vaddr.toString(16)}`,
        length: 16,
        width: 8
      });

      expect(result.length).toBe(16);
      expect(result.bytes.startsWith('00 01 02 03')).toBe(true);
      expect(result.bytes).toBe(data.subarray(0, 16).toString('hex').match(/../g)!.join(' '));
    } finally {
      fs.unlinkSync(filePath);
    }
  });

  it('should clamp length near end of segment', async () => {
    const { filePath, vaddr } = createElfWithSegment();

    try {
      const result = await hexdumpHandler({
        filepath: filePath,
        start: `0x${(vaddr + 0x30).toString(16)}`,
        length: 64,
        width: 16
      });

      expect(result.length).toBe(16);
      expect(result.address).toBe(`0x${(vaddr + 0x30).toString(16)}`);
    } finally {
      fs.unlinkSync(filePath);
    }
  });
});
