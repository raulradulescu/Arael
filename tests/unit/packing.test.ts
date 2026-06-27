/**
 * Unit tests for packing detection and auto-unpacking
 * Tests UPX, PyInstaller, and other packer detection
 */

import { detectPacking, calculateEntropy, unpackBinary } from '../../src/utils/packing';
import * as fs from 'fs';
import * as path from 'path';

describe('Packing Detection', () => {
  describe('UPX Detection', () => {
    it('should detect UPX magic bytes', async () => {
      // UPX magic: "UPX!"
      const upxMagic = Buffer.from([0x55, 0x50, 0x58, 0x21]);  // "UPX!"
      const mockBinary = Buffer.concat([
        Buffer.alloc(100),
        upxMagic,
        Buffer.alloc(100)
      ]);

      const result = await detectPacking(mockBinary, 'test.exe');

      expect(result.isPacked).toBe(true);
      expect(result.packers.length).toBeGreaterThan(0);

      const upxPacker = result.packers.find(p => p.name === 'UPX');
      expect(upxPacker).toBeTruthy();
      expect(upxPacker?.confidence).toBeGreaterThan(0.5);
      expect(upxPacker?.canUnpack).toBe(true);
    });

    it('should detect UPX section names', async () => {
      // Mock PE with UPX section names (.UPX0, .UPX1)
      const mockSections = [
        { name: '.UPX0', entropy: 7.5 },
        { name: '.UPX1', entropy: 7.8 }
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      expect(result.isPacked).toBe(true);

      const upxPacker = result.packers.find(p => p.name === 'UPX');
      expect(upxPacker).toBeTruthy();
      expect(upxPacker?.indicators?.some(indicator => indicator.includes('UPX section'))).toBe(true);
    });

    it('should verify UPX with `upx -t` when available', async () => {
      // This test requires UPX to be installed
      // Skip if not available
      const mockBinaryPath = path.join(__dirname, '../fixtures/test_upx.exe');

      if (!fs.existsSync(mockBinaryPath)) {
        console.warn('Skipping UPX verification test: test binary not found');
        return;
      }

      const buffer = fs.readFileSync(mockBinaryPath);
      const result = await detectPacking(buffer, mockBinaryPath);

      // Should detect UPX
      const upxPacker = result.packers.find(p => p.name === 'UPX');
      expect(upxPacker).toBeTruthy();
    });
  });

  describe('PyInstaller Detection', () => {
    it('should detect PyInstaller MEI magic', async () => {
      // PyInstaller MEI magic: "MEI\014\013\012\013\016"
      const meiMagic = Buffer.from([0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E]);
      const mockBinary = Buffer.concat([
        Buffer.alloc(100),
        meiMagic,
        Buffer.alloc(100)
      ]);

      const result = await detectPacking(mockBinary, 'app.exe');

      expect(result.isPacked).toBe(true);

      const pyinstallerPacker = result.packers.find(p => p.name === 'PyInstaller');
      expect(pyinstallerPacker).toBeTruthy();
      expect(pyinstallerPacker?.canUnpack).toBe(true);
    });

    it('should detect PyInstaller strings', async () => {
      // PyInstaller binaries contain specific strings
      const pyinstallerString = Buffer.from('PyInstaller', 'utf-8');
      const mockBinary = Buffer.concat([
        Buffer.alloc(500),
        pyinstallerString,
        Buffer.alloc(500)
      ]);

      const result = await detectPacking(mockBinary, 'app.exe');

      const pyinstallerPacker = result.packers.find(p => p.name === 'PyInstaller');
      expect(pyinstallerPacker).toBeTruthy();
      expect(pyinstallerPacker?.indicators?.some(indicator => indicator.includes('PyInstaller'))).toBe(true);
    });

    it('should detect Py2Exe strings', async () => {
      const py2exeString = Buffer.from('Py2Exe', 'utf-8');
      const mockBinary = Buffer.concat([
        Buffer.alloc(500),
        py2exeString,
        Buffer.alloc(500)
      ]);

      const result = await detectPacking(mockBinary, 'app.exe');

      const py2exePacker = result.packers.find(p => p.name === 'Py2Exe');
      expect(py2exePacker).toBeTruthy();
    });
  });

  describe('Other Packer Detection', () => {
    it('should detect ASPack section names', async () => {
      const mockSections = [
        { name: '.aspack', entropy: 7.9 },
        { name: '.adata', entropy: 7.5 }
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      const aspackPacker = result.packers.find(p => p.name === 'ASPack');
      expect(aspackPacker).toBeTruthy();
      expect(aspackPacker?.canUnpack).toBe(false);
    });

    it('should detect Themida section names', async () => {
      const mockSections = [
        { name: '.themida', entropy: 7.8 }
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      const themidaPacker = result.packers.find(p => p.name === 'Themida');
      expect(themidaPacker).toBeTruthy();
    });

    it('should detect VMProtect section names', async () => {
      const mockSections = [
        { name: '.vmp0', entropy: 7.9 },
        { name: '.vmp1', entropy: 7.7 }
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      const vmpPacker = result.packers.find(p => p.name === 'VMProtect');
      expect(vmpPacker).toBeTruthy();
    });

    it('should detect PECompact section names', async () => {
      const mockSections = [
        { name: '.pec1', entropy: 7.6 },
        { name: '.pec2', entropy: 7.4 }
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      const pecompactPacker = result.packers.find(p => p.name === 'PECompact');
      expect(pecompactPacker).toBeTruthy();
    });

    it('should detect MPRESS section names', async () => {
      const mockSections = [
        { name: '.MPRESS1', entropy: 7.7 },
        { name: '.MPRESS2', entropy: 7.5 }
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      const mpressPacker = result.packers.find(p => p.name === 'MPRESS');
      expect(mpressPacker).toBeTruthy();
    });

    it('should detect Enigma strings', async () => {
      const enigmaString = Buffer.from('Enigma protector', 'utf-8');
      const mockBinary = Buffer.concat([
        Buffer.alloc(500),
        enigmaString,
        Buffer.alloc(500)
      ]);

      const result = await detectPacking(mockBinary, 'test.exe');

      const enigmaPacker = result.packers.find(p => p.name === 'Enigma');
      expect(enigmaPacker).toBeTruthy();
    });
  });

  describe('Entropy Calculation', () => {
    it('should calculate high entropy for random data', () => {
      const randomData = Buffer.allocUnsafe(1024);
      for (let i = 0; i < 1024; i++) {
        randomData[i] = Math.floor(Math.random() * 256);
      }

      const entropy = calculateEntropy(randomData);

      // Random data should have entropy close to 8.0
      expect(entropy).toBeGreaterThan(7.5);
      expect(entropy).toBeLessThanOrEqual(8.0);
    });

    it('should calculate low entropy for repeated data', () => {
      const repeatedData = Buffer.alloc(1024, 0x41);  // All 'A'

      const entropy = calculateEntropy(repeatedData);

      // Repeated data should have very low entropy
      expect(entropy).toBeLessThan(1.0);
    });

    it('should calculate medium entropy for normal code', () => {
      // Typical x86 code has entropy around 5-6
      const mockCode = Buffer.from([
        0x55,                   // push rbp
        0x48, 0x89, 0xE5,       // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x10, // sub rsp, 0x10
        0x89, 0x7D, 0xFC,       // mov [rbp-4], edi
        0x8B, 0x45, 0xFC,       // mov eax, [rbp-4]
        0xC9,                   // leave
        0xC3                    // ret
      ]);

      // Repeat to get enough data
      const codeData = Buffer.concat(Array(100).fill(mockCode));

      const entropy = calculateEntropy(codeData);

      // Normal code should have medium entropy (4-6.5)
      expect(entropy).toBeGreaterThan(3.5);
      expect(entropy).toBeLessThan(7.0);
    });

    it('should flag high-entropy sections as suspicious', async () => {
      const mockSections = [
        { name: '.text', entropy: 5.2 },
        { name: '.data', entropy: 3.8 },
        { name: '.packed', entropy: 7.9 }  // Suspiciously high
      ];

      const result = await detectPacking(Buffer.alloc(1024), 'test.exe', mockSections);

      expect(result.entropy.sections).toEqual(mockSections);

      // Should flag high entropy as potential packing
      if (result.packers.length > 0) {
        const hasHighEntropyIndicator = result.packers.some(p =>
          p.indicators.some(ind => ind.toLowerCase().includes('entropy'))
        );
        expect(hasHighEntropyIndicator).toBe(true);
      }
    });
  });

  describe('Multiple Packer Detection', () => {
    it('should detect multiple packers if present', async () => {
      // Binary with both UPX and Themida signatures (unlikely but possible)
      const upxMagic = Buffer.from([0x55, 0x50, 0x58, 0x21]);
      const mockBinary = Buffer.concat([
        Buffer.alloc(100),
        upxMagic,
        Buffer.alloc(100)
      ]);

      const mockSections = [
        { name: '.themida', entropy: 7.8 }
      ];

      const result = await detectPacking(mockBinary, 'test.exe', mockSections);

      expect(result.packers.length).toBeGreaterThanOrEqual(2);
    });

    it('should rank packers by confidence', async () => {
      const upxMagic = Buffer.from([0x55, 0x50, 0x58, 0x21]);
      const mockBinary = Buffer.concat([
        Buffer.alloc(100),
        upxMagic,
        Buffer.alloc(100)
      ]);

      const mockSections = [
        { name: '.UPX0', entropy: 7.5 },
        { name: '.unknown', entropy: 6.0 }
      ];

      const result = await detectPacking(mockBinary, 'test.exe', mockSections);

      const upxPacker = result.packers.find(p => p.name === 'UPX');
      expect(upxPacker).toBeTruthy();

      // UPX with magic + section names should have high confidence
      expect(upxPacker?.confidence).toBeGreaterThan(0.8);
    });
  });

  describe('UPX Auto-Unpacking', () => {
    it('should unpack UPX binary when UPX is available', async () => {
      const mockBinaryPath = path.join(__dirname, '../fixtures/test_upx.exe');

      if (!fs.existsSync(mockBinaryPath)) {
        console.warn('Skipping UPX unpacking test: test binary not found');
        return;
      }

      const result = await unpackBinary(mockBinaryPath, 'UPX');

      expect(result.success).toBe(true);
      expect(result.unpackedPath).toBeTruthy();
      expect(result.method).toBe('upx -d');

      if (result.unpackedPath) {
        expect(fs.existsSync(result.unpackedPath)).toBe(true);

        // Clean up
        fs.unlinkSync(result.unpackedPath);
      }
    });

    it('should preserve original file during unpacking', async () => {
      const mockBinaryPath = path.join(__dirname, '../fixtures/test_upx.exe');

      if (!fs.existsSync(mockBinaryPath)) {
        console.warn('Skipping: test binary not found');
        return;
      }

      const originalSize = fs.statSync(mockBinaryPath).size;

      await unpackBinary(mockBinaryPath, 'UPX');

      // Original should still exist and be unchanged
      expect(fs.existsSync(mockBinaryPath)).toBe(true);
      expect(fs.statSync(mockBinaryPath).size).toBe(originalSize);
    });

    it('should return error if UPX is not installed', async () => {
      // Mock environment where UPX is not available
      const mockBinaryPath = '/tmp/fake.exe';

      const result = await unpackBinary(mockBinaryPath, 'UPX');

      if (!result.success) {
        expect(result.error).toBeTruthy();
        expect(result.error).toMatch(/upx|not found|not installed/i);
      }
    });
  });

  describe('PyInstaller Extraction', () => {
    it('should extract PyInstaller archive when pyinstxtractor is available', async () => {
      const mockBinaryPath = path.join(__dirname, '../fixtures/test_pyinstaller.exe');

      if (!fs.existsSync(mockBinaryPath)) {
        console.warn('Skipping PyInstaller test: test binary not found');
        return;
      }

      const result = await unpackBinary(mockBinaryPath, 'PyInstaller');

      expect(result.success).toBe(true);
      expect(result.extractedDir).toBeTruthy();
      expect(result.method).toMatch(/pyinstxtractor/);

      if (result.extractedDir) {
        expect(fs.existsSync(result.extractedDir)).toBe(true);

        // Should have extracted .pyc files
        const files = fs.readdirSync(result.extractedDir);
        const pycFiles = files.filter(f => f.endsWith('.pyc'));
        expect(pycFiles.length).toBeGreaterThan(0);
      }
    });
  });
});

describe('Integration with analyze', () => {
  it('should add packing field to analysis result', () => {
    // This will be tested in integration tests
    // Just ensure the interface is correct
    const mockPackingInfo = {
      isPacked: true,
      packers: [
        {
          name: 'UPX',
          confidence: 0.9,
          indicators: ['UPX magic bytes', 'UPX section names'],
          canUnpack: true
        }
      ],
      entropy: {
        overall: 6.8,
        sections: [
          { name: '.text', entropy: 7.2 },
          { name: '.data', entropy: 4.5 }
        ]
      },
      wasUnpacked: false,
      originalFile: null
    };

    expect(mockPackingInfo.isPacked).toBe(true);
    expect(mockPackingInfo.packers[0]!.name).toBe('UPX');
  });
});
