import { hexdump, bytesToHex, hexToBytes } from '../../src/utils/hexdump';

describe('Hexdump Utilities', () => {
  describe('hexdump', () => {
    it('should format bytes with default options', () => {
      const buffer = Buffer.from('Hello, World!');
      const result = hexdump(buffer);

      expect(result).toContain('48 65 6c 6c 6f');
      expect(result).toContain('|Hello, World!|');
    });

    it('should include address prefix', () => {
      const buffer = Buffer.from('Test');
      const result = hexdump(buffer, { startAddress: 0x1000 });

      expect(result).toContain('00001000');
    });

    it('should respect width option', () => {
      const buffer = Buffer.alloc(32).fill(0x41); // 'AAAA...'
      const result8 = hexdump(buffer, { width: 8 });
      const result16 = hexdump(buffer, { width: 16 });

      // Width 8 should have 4 lines, width 16 should have 2 lines
      expect(result8.split('\n').length).toBe(4);
      expect(result16.split('\n').length).toBe(2);
    });

    it('should show dots for non-printable characters', () => {
      const buffer = Buffer.from([0x00, 0x01, 0x41, 0x7f, 0xff]);
      const result = hexdump(buffer);

      expect(result).toContain('|..A..|');
    });

    it('should handle uppercase option', () => {
      const buffer = Buffer.from([0xab, 0xcd]);
      const lower = hexdump(buffer, { uppercase: false });
      const upper = hexdump(buffer, { uppercase: true });

      expect(lower).toContain('ab cd');
      expect(upper).toContain('AB CD');
    });
  });

  describe('bytesToHex', () => {
    it('should convert buffer to hex string', () => {
      const buffer = Buffer.from([0x00, 0x41, 0xff]);
      expect(bytesToHex(buffer)).toBe('00 41 ff');
    });

    it('should use custom separator', () => {
      const buffer = Buffer.from([0xaa, 0xbb]);
      expect(bytesToHex(buffer, '')).toBe('aabb');
      expect(bytesToHex(buffer, ':')).toBe('aa:bb');
    });
  });

  describe('hexToBytes', () => {
    it('should convert hex string to buffer', () => {
      const hex = '00 41 ff';
      const buffer = hexToBytes(hex);

      expect(buffer[0]).toBe(0x00);
      expect(buffer[1]).toBe(0x41);
      expect(buffer[2]).toBe(0xff);
    });

    it('should handle hex without spaces', () => {
      const buffer = hexToBytes('aabbcc');
      expect(buffer.length).toBe(3);
      expect(buffer[0]).toBe(0xaa);
    });

    it('should throw on odd-length hex string', () => {
      expect(() => hexToBytes('abc')).toThrow(/odd length/i);
    });
  });
});
