/**
 * Unit tests for analysis enhancements
 * Tests section analysis and import categorization
 */

import { analyzeSections } from '../../src/utils/sections';
import { categorizeImports } from '../../src/utils/import-analysis';

describe('Section Analysis', () => {
  describe('Permission Analysis', () => {
    it('should flag RWX sections as high severity', async () => {
      const mockSections = [
        {
          name: '.text',
          start: '0x401000',
          end: '0x402000',
          size: 4096,
          permissions: { read: true, write: false, execute: true }
        },
        {
          name: '.suspicious',
          start: '0x403000',
          end: '0x404000',
          size: 4096,
          permissions: { read: true, write: true, execute: true }  // RWX!
        }
      ];

      const result = await analyzeSections(mockSections, Buffer.alloc(8192));

      const suspiciousSection = result.sections.find(s => s.name === '.suspicious');
      expect(suspiciousSection).toBeTruthy();
      expect(suspiciousSection?.anomalies).toBeTruthy();

      const rwxAnomaly = suspiciousSection?.anomalies.find(a => a.type === 'rwx');
      expect(rwxAnomaly).toBeTruthy();
      expect(rwxAnomaly?.severity).toBe('high');
    });

    it('should not flag normal RX sections', async () => {
      const mockSections = [
        {
          name: '.text',
          start: '0x401000',
          end: '0x402000',
          size: 4096,
          permissions: { read: true, write: false, execute: true }
        }
      ];

      const result = await analyzeSections(mockSections, Buffer.alloc(4096));

      const textSection = result.sections.find(s => s.name === '.text');
      expect(textSection).toBeTruthy();

      const rwxAnomaly = textSection?.anomalies.find(a => a.type === 'rwx');
      expect(rwxAnomaly).toBeUndefined();
    });

    it('should not flag normal RW sections', async () => {
      const mockSections = [
        {
          name: '.data',
          start: '0x402000',
          end: '0x403000',
          size: 4096,
          permissions: { read: true, write: true, execute: false }
        }
      ];

      const result = await analyzeSections(mockSections, Buffer.alloc(4096));

      const dataSection = result.sections.find(s => s.name === '.data');
      expect(dataSection).toBeTruthy();

      const rwxAnomaly = dataSection?.anomalies.find(a => a.type === 'rwx');
      expect(rwxAnomaly).toBeUndefined();
    });
  });

  describe('Entropy Analysis', () => {
    it('should flag high-entropy executable sections', async () => {
      // High entropy in .text is suspicious (might be packed/encrypted)
      const mockSections = [
        {
          name: '.text',
          start: '0x401000',
          end: '0x402000',
          size: 1024,
          permissions: { read: true, write: false, execute: true }
        }
      ];

      // Create high-entropy data
      const highEntropyData = Buffer.allocUnsafe(1024);
      for (let i = 0; i < 1024; i++) {
        highEntropyData[i] = Math.floor(Math.random() * 256);
      }

      const result = await analyzeSections(mockSections, highEntropyData);

      const textSection = result.sections.find(s => s.name === '.text');
      expect(textSection).toBeTruthy();
      expect(textSection?.entropy).toBeGreaterThan(7.5);

      const entropyAnomaly = textSection?.anomalies.find(a => a.type === 'high_entropy');
      expect(entropyAnomaly).toBeTruthy();
      expect(entropyAnomaly?.severity).toMatch(/medium|high/);
    });

    it('should not flag high-entropy data sections', async () => {
      const mockSections = [
        {
          name: '.data',
          start: '0x402000',
          end: '0x403000',
          size: 1024,
          permissions: { read: true, write: true, execute: false }
        }
      ];

      // High entropy is normal for data sections
      const highEntropyData = Buffer.allocUnsafe(1024);
      for (let i = 0; i < 1024; i++) {
        highEntropyData[i] = Math.floor(Math.random() * 256);
      }

      const result = await analyzeSections(mockSections, highEntropyData);

      const dataSection = result.sections.find(s => s.name === '.data');
      expect(dataSection).toBeTruthy();

      // Should not flag high entropy in data sections
      const entropyAnomaly = dataSection?.anomalies.find(a => a.type === 'high_entropy');
      expect(entropyAnomaly).toBeUndefined();
    });

    it('should calculate entropy for each section', async () => {
      const mockSections = [
        {
          name: '.text',
          start: '0x401000',
          end: '0x402000',
          size: 100,
          permissions: { read: true, write: false, execute: true }
        },
        {
          name: '.data',
          start: '0x402000',
          end: '0x403000',
          size: 100,
          permissions: { read: true, write: true, execute: false }
        }
      ];

      const binaryData = Buffer.concat([
        Buffer.alloc(100, 0x90),  // .text (NOP sled - low entropy)
        Buffer.allocUnsafe(100)   // .data (random - high entropy)
      ]);

      // Randomize data section
      for (let i = 100; i < 200; i++) {
        binaryData[i] = Math.floor(Math.random() * 256);
      }

      const result = await analyzeSections(mockSections, binaryData);

      expect(result.sections[0]!.entropy).toBeLessThan(2.0);  // Low entropy (repeated NOPs)
      expect(result.sections[1]!.entropy).toBeGreaterThan(6.0);  // High entropy (random data)
    });
  });

  describe('Suspicious Section Names', () => {
    it('should flag common packer section names', async () => {
      const suspiciousSections = [
        { name: '.UPX0', permissions: { read: true, write: false, execute: true } },
        { name: '.themida', permissions: { read: true, write: true, execute: true } },
        { name: '.vmp0', permissions: { read: true, write: false, execute: true } },
        { name: '.aspack', permissions: { read: true, write: false, execute: true } }
      ];

      for (const section of suspiciousSections) {
        const mockSections = [{
          ...section,
          start: '0x401000',
          end: '0x402000',
          size: 4096
        }];

        const result = await analyzeSections(mockSections, Buffer.alloc(4096));

        const analyzed = result.sections[0]!;
        const nameAnomaly = analyzed.anomalies.find(a => a.type === 'suspicious_name');
        expect(nameAnomaly).toBeTruthy();
        expect(nameAnomaly?.description).toMatch(/packer|suspicious/i);
      }
    });

    it('should not flag normal section names', async () => {
      const normalSections = [
        { name: '.text' },
        { name: '.data' },
        { name: '.rodata' },
        { name: '.bss' },
        { name: '.rdata' }
      ];

      for (const section of normalSections) {
        const mockSections = [{
          ...section,
          start: '0x401000',
          end: '0x402000',
          size: 4096,
          permissions: { read: true, write: false, execute: false }
        }];

        const result = await analyzeSections(mockSections, Buffer.alloc(4096));

        const analyzed = result.sections[0]!;
        const nameAnomaly = analyzed.anomalies.find(a => a.type === 'suspicious_name');
        expect(nameAnomaly).toBeUndefined();
      }
    });
  });

  describe('Multiple Anomalies', () => {
    it('should detect multiple anomalies in same section', async () => {
      const mockSections = [
        {
          name: '.suspicious',
          start: '0x401000',
          end: '0x402000',
          size: 1024,
          permissions: { read: true, write: true, execute: true }  // RWX
        }
      ];

      // High entropy data
      const highEntropyData = Buffer.allocUnsafe(1024);
      for (let i = 0; i < 1024; i++) {
        highEntropyData[i] = Math.floor(Math.random() * 256);
      }

      const result = await analyzeSections(mockSections, highEntropyData);

      const section = result.sections[0]!;
      expect(section.anomalies.length).toBeGreaterThanOrEqual(2);

      // Should have both RWX and high entropy anomalies
      const rwxAnomaly = section.anomalies.find(a => a.type === 'rwx');
      const entropyAnomaly = section.anomalies.find(a => a.type === 'high_entropy');

      expect(rwxAnomaly).toBeTruthy();
      expect(entropyAnomaly).toBeTruthy();
    });
  });
});

describe('Import Categorization', () => {
  describe('Network Capability', () => {
    it('should categorize network-related imports', () => {
      const mockImports = [
        { name: 'socket', library: 'libc.so.6' },
        { name: 'connect', library: 'libc.so.6' },
        { name: 'send', library: 'libc.so.6' },
        { name: 'recv', library: 'libc.so.6' },
        { name: 'WSAStartup', library: 'ws2_32.dll' },
        { name: 'InternetOpenA', library: 'wininet.dll' }
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.get('Network')).toBe(6);

      // All network imports should be categorized
      const networkImports = ['socket', 'connect', 'send', 'recv', 'WSAStartup', 'InternetOpenA'];
      networkImports.forEach(imp => {
        const match = result.categorizedImports.find(
          (item) => item.name === imp && item.capabilities.includes('Network')
        );
        expect(match).toBeTruthy();
      });
    });
  });

  describe('Crypto Capability', () => {
    it('should categorize crypto-related imports', () => {
      const mockImports = [
        { name: 'CryptEncrypt', library: 'advapi32.dll' },
        { name: 'CryptDecrypt', library: 'advapi32.dll' },
        { name: 'MD5_Init', library: 'libcrypto.so' },
        { name: 'SHA256_Update', library: 'libcrypto.so' },
        { name: 'AES_encrypt', library: 'libcrypto.so' },
        { name: 'RSA_public_encrypt', library: 'libcrypto.so' }
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.get('Crypto')).toBe(6);
    });
  });

  describe('File I/O Capability', () => {
    it('should categorize file I/O imports', () => {
      const mockImports = [
        { name: 'fopen', library: 'libc.so.6' },
        { name: 'fread', library: 'libc.so.6' },
        { name: 'fwrite', library: 'libc.so.6' },
        { name: 'CreateFileA', library: 'kernel32.dll' },
        { name: 'ReadFile', library: 'kernel32.dll' },
        { name: 'WriteFile', library: 'kernel32.dll' },
        { name: 'DeleteFileA', library: 'kernel32.dll' }
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.get('FileIO')).toBe(7);
    });
  });

  describe('Process Capability', () => {
    it('should categorize process-related imports', () => {
      const mockImports = [
        { name: 'CreateProcessA', library: 'kernel32.dll' },
        { name: 'TerminateProcess', library: 'kernel32.dll' },
        { name: 'OpenProcess', library: 'kernel32.dll' },
        { name: 'fork', library: 'libc.so.6' },
        { name: 'execve', library: 'libc.so.6' },
        { name: 'system', library: 'libc.so.6' }
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.get('Process')).toBe(6);
    });
  });

  describe('Registry Capability', () => {
    it('should categorize Windows registry imports', () => {
      const mockImports = [
        { name: 'RegOpenKeyExA', library: 'advapi32.dll' },
        { name: 'RegSetValueExA', library: 'advapi32.dll' },
        { name: 'RegQueryValueExA', library: 'advapi32.dll' },
        { name: 'RegDeleteKeyA', library: 'advapi32.dll' }
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.get('Registry')).toBe(4);
    });
  });

  describe('Multiple Categories', () => {
    it('should categorize imports into multiple capabilities', () => {
      const mockImports = [
        { name: 'socket', library: 'libc.so.6' },          // Network
        { name: 'fopen', library: 'libc.so.6' },           // File I/O
        { name: 'MD5_Init', library: 'libcrypto.so' },     // Crypto
        { name: 'fork', library: 'libc.so.6' },            // Process
        { name: 'RegOpenKeyExA', library: 'advapi32.dll' } // Registry
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.size).toBe(6);
      expect(result.capabilitySummary.has('Network')).toBe(true);
      expect(result.capabilitySummary.has('FileIO')).toBe(true);
      expect(result.capabilitySummary.has('Crypto')).toBe(true);
      expect(result.capabilitySummary.has('Process')).toBe(true);
      expect(result.capabilitySummary.has('Registry')).toBe(true);
      expect(result.capabilitySummary.has('Persistence')).toBe(true);
    });
  });

  describe('Uncategorized Imports', () => {
    it('should keep uncategorized imports separate', () => {
      const mockImports = [
        { name: 'socket', library: 'libc.so.6' },     // Categorized
        { name: 'printf', library: 'libc.so.6' },     // Uncategorized
        { name: 'malloc', library: 'libc.so.6' },     // Uncategorized
        { name: 'fopen', library: 'libc.so.6' }       // Categorized
      ];

      const result = categorizeImports(mockImports);

      const uncategorized = result.categorizedImports.filter((imp) => imp.capabilities.length === 0);

      expect(uncategorized.length).toBe(1);
      expect(uncategorized.some((imp) => imp.name === 'printf')).toBe(true);
      expect(result.capabilitySummary.get('Memory')).toBe(1);
    });
  });

  describe('Case Insensitivity', () => {
    it('should match imports case-insensitively', () => {
      const mockImports = [
        { name: 'SOCKET', library: 'WS2_32.DLL' },      // Uppercase
        { name: 'CreateFileA', library: 'KERNEL32.DLL' }, // Mixed case
        { name: 'md5_init', library: 'libcrypto.so' }   // Lowercase
      ];

      const result = categorizeImports(mockImports);

      expect(result.capabilitySummary.has('Network')).toBe(true);
      expect(result.capabilitySummary.has('FileIO')).toBe(true);
      expect(result.capabilitySummary.has('Crypto')).toBe(true);
    });
  });

  describe('Dangerous Functions', () => {
    it('should flag dangerous functions', () => {
      const mockImports = [
        { name: 'system', library: 'libc.so.6' },
        { name: 'exec', library: 'libc.so.6' },
        { name: 'ShellExecuteA', library: 'shell32.dll' },
        { name: 'WinExec', library: 'kernel32.dll' }
      ];

      const result = categorizeImports(mockImports);

      expect(result.dangerousFunctions.length).toBeGreaterThan(0);

      // All should be flagged as dangerous
      expect(result.dangerousFunctions.some((imp) => imp.name === 'system')).toBe(true);
      expect(result.dangerousFunctions.some((imp) => imp.name === 'exec')).toBe(true);
    });
  });

  describe('Summary Statistics', () => {
    it('should provide summary statistics', () => {
      const mockImports = [
        { name: 'socket', library: 'libc.so.6' },
        { name: 'fopen', library: 'libc.so.6' },
        { name: 'MD5_Init', library: 'libcrypto.so' },
        { name: 'printf', library: 'libc.so.6' }
      ];

      const result = categorizeImports(mockImports);

      const total = result.categorizedImports.length;
      const uncategorizedCount = result.categorizedImports.filter(
        (imp) => imp.capabilities.length === 0
      ).length;
      const categorized = total - uncategorizedCount;
      const capabilityCount = result.capabilitySummary.size;

      expect(total).toBe(4);
      expect(categorized).toBe(3);
      expect(uncategorizedCount).toBe(1);
      expect(capabilityCount).toBe(3);
    });
  });
});
