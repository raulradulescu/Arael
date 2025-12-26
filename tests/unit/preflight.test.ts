import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { validateBinary, isElfBinary, PreflightError } from '../../src/utils/preflight';

describe('Preflight Checks', () => {
  const tempDir = os.tmpdir();

  describe('validateBinary', () => {
    it('should reject non-existent file', async () => {
      await expect(validateBinary('/nonexistent/file'))
        .rejects.toThrow(PreflightError);

      await expect(validateBinary('/nonexistent/file'))
        .rejects.toThrow(/does not exist/i);
    });

    it('should reject empty file', async () => {
      const emptyFile = path.join(tempDir, 'arael_test_empty.bin');
      fs.writeFileSync(emptyFile, '');

      try {
        await expect(validateBinary(emptyFile))
          .rejects.toThrow(/empty/i);
      } finally {
        fs.unlinkSync(emptyFile);
      }
    });

    it('should reject non-ELF file', async () => {
      const textFile = path.join(tempDir, 'arael_test_text.txt');
      fs.writeFileSync(textFile, 'This is not a binary file');

      try {
        await expect(validateBinary(textFile))
          .rejects.toThrow(/not an ELF/i);
      } finally {
        fs.unlinkSync(textFile);
      }
    });

    it('should accept valid ELF binary', async () => {
      // Create a minimal ELF header
      const elfHeader = Buffer.alloc(64);
      elfHeader[0] = 0x7f; // ELF magic
      elfHeader[1] = 0x45; // 'E'
      elfHeader[2] = 0x4c; // 'L'
      elfHeader[3] = 0x46; // 'F'
      elfHeader[4] = 2;    // 64-bit
      elfHeader[5] = 1;    // Little endian
      elfHeader.writeUInt16LE(0x3e, 18); // e_machine = x86_64

      const elfFile = path.join(tempDir, 'arael_test_elf.bin');
      fs.writeFileSync(elfFile, elfHeader);

      try {
        const result = await validateBinary(elfFile);
        expect(result.valid).toBe(true);
        expect(result.format).toBe('ELF');
        expect(result.architecture).toBe('x86_64');
        expect(result.endianness).toBe('little');
      } finally {
        fs.unlinkSync(elfFile);
      }
    });

    it('should return correct file info', async () => {
      const elfHeader = Buffer.alloc(64);
      elfHeader[0] = 0x7f;
      elfHeader[1] = 0x45;
      elfHeader[2] = 0x4c;
      elfHeader[3] = 0x46;
      elfHeader[4] = 2;
      elfHeader[5] = 1;
      elfHeader.writeUInt16LE(0x3e, 18);

      const elfFile = path.join(tempDir, 'arael_test_info.bin');
      fs.writeFileSync(elfFile, elfHeader);

      try {
        const result = await validateBinary(elfFile);
        expect(result.filepath).toBe(elfFile);
        expect(result.absolutePath).toBe(path.resolve(elfFile));
        expect(result.size).toBe(64);
      } finally {
        fs.unlinkSync(elfFile);
      }
    });

    it('should reject non-x86_64 ELF binaries', async () => {
      const elfHeader = Buffer.alloc(64);
      elfHeader[0] = 0x7f;
      elfHeader[1] = 0x45;
      elfHeader[2] = 0x4c;
      elfHeader[3] = 0x46;
      elfHeader[4] = 1; // 32-bit
      elfHeader[5] = 1; // Little endian
      elfHeader.writeUInt16LE(0x03, 18); // e_machine = x86

      const elfFile = path.join(tempDir, 'arael_test_elf32.bin');
      fs.writeFileSync(elfFile, elfHeader);

      try {
        await expect(validateBinary(elfFile))
          .rejects.toThrow(/x86_64 only/i);
      } finally {
        fs.unlinkSync(elfFile);
      }
    });
  });

  describe('isElfBinary', () => {
    it('should return false for non-existent file', () => {
      expect(isElfBinary('/nonexistent/file')).toBe(false);
    });

    it('should return false for text file', () => {
      const textFile = path.join(tempDir, 'arael_test_iself.txt');
      fs.writeFileSync(textFile, 'hello world');

      try {
        expect(isElfBinary(textFile)).toBe(false);
      } finally {
        fs.unlinkSync(textFile);
      }
    });

    it('should return true for ELF file', () => {
      const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]);
      const elfFile = path.join(tempDir, 'arael_test_iself.bin');
      fs.writeFileSync(elfFile, elfHeader);

      try {
        expect(isElfBinary(elfFile)).toBe(true);
      } finally {
        fs.unlinkSync(elfFile);
      }
    });
  });
});
