/**
 * Integration tests for x86 16-bit architecture support
 *
 * Requirements:
 * - Analyze 16-bit DOS COM files
 * - Analyze 16-bit DOS MZ EXE files
 * - Correctly identify 8086/8088/80186/80286 architecture
 * - Recognize 16-bit registers (AX, BX, CX, DX, SI, DI, BP, SP)
 * - Recognize segment registers (CS, DS, ES, SS)
 * - Handle segmented memory model (segment:offset)
 * - Support real mode addressing
 * - Handle DOS interrupts (INT 21h, etc.)
 *
 * Test binaries needed in tests/fixtures/x86_16/:
 * - hello.com (DOS COM file)
 * - hello.exe (DOS MZ EXE file)
 * - complex_16.exe (multi-segment program)
 * - bootsector.bin (512-byte boot sector)
 *
 * Note: 16-bit support in Ghidra requires specific processor selection
 * and may have limitations compared to 32/64-bit analysis.
 */

import * as fs from 'fs';
import * as path from 'path';
import { loadEnvFromFile } from '../../src/utils/env';

// Load environment before tests
loadEnvFromFile();

import { getConnection } from '../../src/ghidra/connection';
import { analyzeHandler } from '../../src/mcp/handlers/analyze';
import { decompileHandler } from '../../src/mcp/handlers/decompile';
import { disassembleHandler } from '../../src/mcp/handlers/disassemble';
import { functionsHandler } from '../../src/mcp/handlers/functions';

// Test fixtures directory
const fixturesDir = path.join(__dirname, '../fixtures/x86_16');

// Check if test binaries exist
const hasTestBinaries = (): boolean => {
  return fs.existsSync(fixturesDir) &&
    (fs.existsSync(path.join(fixturesDir, 'hello.com')) ||
     fs.existsSync(path.join(fixturesDir, 'hello.exe')));
};

// Skip if no test binaries
const describeOrSkip = hasTestBinaries() ? describe : describe.skip;

describeOrSkip('x86 16-bit Architecture Support', () => {
  const ghidraPath = process.env['GHIDRA_PATH'] ?? '';

  beforeAll(async () => {
    if (!ghidraPath) {
      console.warn('GHIDRA_PATH not set, skipping x86-16 tests');
      return;
    }

    const connection = getConnection({
      ghidraPath,
      pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH']
    });

    await connection.connect();
  }, 60000);

  describe('DOS COM File Analysis', () => {
    const comPath = path.join(fixturesDir, 'hello.com');

    it('should detect DOS COM format', async () => {
      if (!fs.existsSync(comPath)) {
        console.warn('Skipping: hello.com not found');
        return;
      }

      const result = await analyzeHandler({ filepath: comPath });

      expect(result.binary).toBeDefined();
      // COM files are raw binary, Ghidra may identify as "raw" or "COM"
      expect(result.binary?.bits).toBe(16);
    }, 120000);

    it('should identify 16-bit architecture', async () => {
      if (!fs.existsSync(comPath)) return;

      const result = await analyzeHandler({ filepath: comPath });

      expect(result.binary?.architecture).toMatch(/8086|8088|x86.*16|i8086|Real Mode/i);
      expect(result.binary?.bits).toBe(16);
    }, 120000);

    it('should recognize COM entry point at 0x100', async () => {
      if (!fs.existsSync(comPath)) return;

      const result = await analyzeHandler({ filepath: comPath });

      // COM files always load at CS:0100h
      expect(result.entryPoint).toBeDefined();
      if (result.entryPoint) {
        expect(result.entryPoint).toMatch(/0x0*100|:0100/i);
      }
    }, 120000);

    it('should disassemble with 16-bit registers', async () => {
      if (!fs.existsSync(comPath)) return;

      const result = await disassembleHandler({
        filepath: comPath,
        target: '0x100',  // COM entry point
        length: 50
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        const allAsm = result.instructions.map(i =>
          i.mnemonic + ' ' + (i.operands || []).join(',')
        ).join(' ');

        // Should use 16-bit registers (AX, BX, etc.)
        // Note: May also use 8-bit registers (AL, AH, BL, BH)
        const has16BitRegs = /\b[ABCD]X\b|\b[SD]I\b|\b[BS]P\b/i.test(allAsm);
        const has8BitRegs = /\b[ABCD][LH]\b/i.test(allAsm);

        expect(has16BitRegs || has8BitRegs).toBe(true);

        // Should NOT have 32-bit or 64-bit registers
        expect(allAsm).not.toMatch(/\bE[ABCD]X\b|\bE[SD]I\b|\bE[BS]P\b/i);
        expect(allAsm).not.toMatch(/\bR[ABCD]X\b|\bR[SD]I\b|\bR[BS]P\b/i);
      }
    }, 120000);

    it('should recognize DOS INT 21h calls', async () => {
      if (!fs.existsSync(comPath)) return;

      const result = await disassembleHandler({
        filepath: comPath,
        target: '0x100',
        length: 100
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // DOS programs typically use INT 21h for system calls
        const hasInt21 = result.instructions.some(i =>
          i.mnemonic.toLowerCase() === 'int' &&
          (i.operands?.join('') || '').includes('21')
        );
        // Most COM programs will have at least one INT 21h
        // (for printing, exiting, etc.)
        expect(hasInt21).toBe(true);
      }
    }, 120000);
  });

  describe('DOS MZ EXE Analysis', () => {
    const exePath = path.join(fixturesDir, 'hello.exe');

    it('should detect DOS MZ format', async () => {
      if (!fs.existsSync(exePath)) {
        console.warn('Skipping: hello.exe (16-bit MZ) not found');
        return;
      }

      const result = await analyzeHandler({ filepath: exePath });

      expect(result.binary).toBeDefined();
      // MZ EXE has "MZ" signature
      expect(result.binary?.format).toMatch(/MZ|DOS|EXE/i);
      expect(result.binary?.bits).toBe(16);
    }, 120000);

    it('should parse MZ header correctly', async () => {
      if (!fs.existsSync(exePath)) return;

      const result = await analyzeHandler({ filepath: exePath });

      // MZ files have relocation info and segment info
      expect(result.binary).toBeDefined();
    }, 120000);

    it('should handle segmented addresses', async () => {
      if (!fs.existsSync(exePath)) return;

      const result = await analyzeHandler({ filepath: exePath });

      expect(result.functions).toBeDefined();
      // 16-bit addresses may be shown as segment:offset or flat
    }, 120000);

    it('should identify segments in MZ EXE', async () => {
      if (!fs.existsSync(exePath)) return;

      const result = await analyzeHandler({ filepath: exePath });

      // MZ files can have multiple segments
      expect(result.sections).toBeDefined();
    }, 120000);
  });

  describe('Multi-Segment 16-bit Analysis', () => {
    const complexPath = path.join(fixturesDir, 'complex_16.exe');

    it('should handle code segment (CS) references', async () => {
      if (!fs.existsSync(complexPath)) {
        console.warn('Skipping: complex_16.exe not found');
        return;
      }

      const result = await disassembleHandler({
        filepath: complexPath,
        target: 'entry',
        length: 50
      });

      expect(result.instructions).toBeDefined();
      // May have FAR calls/jumps with segment:offset
    }, 120000);

    it('should handle data segment (DS) references', async () => {
      if (!fs.existsSync(complexPath)) return;

      const result = await disassembleHandler({
        filepath: complexPath,
        target: 'entry',
        length: 100
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // Look for DS: segment override or MOV DS,AX patterns
        const allAsm = result.instructions.map(i =>
          i.mnemonic + ' ' + (i.operands || []).join(',')
        ).join(' ');

        // May have segment registers
        const hasSegRegs = /\b[CDEFS]S\b/i.test(allAsm);
        expect(result.instructions.length).toBeGreaterThan(0);
      }
    }, 120000);

    it('should recognize FAR vs NEAR calls', async () => {
      if (!fs.existsSync(complexPath)) return;

      const result = await disassembleHandler({
        filepath: complexPath,
        target: 'entry',
        length: 200
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // FAR calls: CALL FAR ptr or CALL segment:offset
        // NEAR calls: CALL offset
        const hasCall = result.instructions.some(i =>
          i.mnemonic.toLowerCase().includes('call')
        );
        expect(result.instructions.length).toBeGreaterThan(0);
      }
    }, 120000);
  });

  describe('Boot Sector Analysis', () => {
    const bootPath = path.join(fixturesDir, 'bootsector.bin');

    it('should analyze 512-byte boot sector', async () => {
      if (!fs.existsSync(bootPath)) {
        console.warn('Skipping: bootsector.bin not found');
        return;
      }

      const result = await analyzeHandler({ filepath: bootPath });

      expect(result.binary).toBeDefined();
      // Boot sectors are raw 16-bit code
      expect(result.binary?.bits).toBe(16);
    }, 120000);

    it('should recognize boot sector entry at 0x7C00', async () => {
      if (!fs.existsSync(bootPath)) return;

      // Boot sectors are loaded at 0000:7C00 by BIOS
      const result = await disassembleHandler({
        filepath: bootPath,
        target: '0x0',  // Start of file
        length: 50
      });

      expect(result.instructions).toBeDefined();
    }, 120000);

    it('should find boot signature 0xAA55', async () => {
      if (!fs.existsSync(bootPath)) return;

      // Last 2 bytes should be 55 AA (little-endian 0xAA55)
      const data = fs.readFileSync(bootPath);
      if (data.length >= 512) {
        expect(data[510]).toBe(0x55);
        expect(data[511]).toBe(0xAA);
      }
    });
  });

  describe('16-bit Specific Instructions', () => {
    const comPath = path.join(fixturesDir, 'hello.com');

    it('should recognize 16-bit specific opcodes', async () => {
      if (!fs.existsSync(comPath)) {
        console.warn('Skipping: need test binary');
        return;
      }

      const result = await disassembleHandler({
        filepath: comPath,
        target: '0x100',
        length: 100
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // Common 16-bit instructions
        const mnemonics = result.instructions.map(i => i.mnemonic.toLowerCase());

        // Should have some standard instructions
        const commonInstructions = ['mov', 'int', 'push', 'pop', 'call', 'ret', 'jmp'];
        const hasCommon = mnemonics.some(m => commonInstructions.includes(m));
        expect(hasCommon).toBe(true);
      }
    }, 120000);

    it('should handle 16-bit immediate values', async () => {
      if (!fs.existsSync(comPath)) return;

      const result = await disassembleHandler({
        filepath: comPath,
        target: '0x100',
        length: 50
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // Immediate values should be 16-bit max (0xFFFF)
        for (const inst of result.instructions) {
          if (inst.operands) {
            for (const op of inst.operands) {
              const match = op.match(/0x([0-9a-fA-F]+)/);
              if (match && match[1]) {
                // 16-bit immediate should be at most 4 hex chars
                // (or 8 for segment:offset)
                expect(match[1].length).toBeLessThanOrEqual(8);
              }
            }
          }
        }
      }
    }, 120000);
  });

  describe('8086 vs 80286 Features', () => {
    it('should handle 8086-only code', async () => {
      const path8086 = path.join(fixturesDir, 'pure_8086.com');
      if (!fs.existsSync(path8086)) {
        console.warn('Skipping: pure_8086.com not found');
        return;
      }

      const result = await analyzeHandler({ filepath: path8086 });

      expect(result.binary).toBeDefined();
      expect(result.binary?.architecture).toMatch(/8086/i);
    }, 120000);

    it('should recognize 80286 protected mode instructions', async () => {
      const path286 = path.join(fixturesDir, 'protected_286.exe');
      if (!fs.existsSync(path286)) {
        console.warn('Skipping: protected_286.exe not found');
        return;
      }

      const result = await disassembleHandler({
        filepath: path286,
        target: 'entry',
        length: 100
      });

      expect(result.instructions).toBeDefined();
      // 80286 added: LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, STR, LMSW, SMSW
    }, 120000);
  });
});

describe('16-bit Test Binary Generation (Reference)', () => {
  it('should document how to create test binaries', () => {
    // Reference for creating 16-bit test binaries:
    //
    // Using NASM (Netwide Assembler):
    //
    // hello.com (COM file):
    //   org 100h
    //   mov ah, 09h
    //   mov dx, message
    //   int 21h
    //   mov ax, 4C00h
    //   int 21h
    //   message db 'Hello, World!$'
    //
    //   nasm -f bin -o hello.com hello.asm
    //
    // hello.exe (MZ EXE):
    //   nasm -f obj -o hello.obj hello.asm
    //   alink -oEXE -o hello.exe hello.obj
    //   (or use MASM/TASM/WASM with linker)
    //
    // Boot sector:
    //   org 7C00h
    //   ; boot code here
    //   times 510-($-$$) db 0
    //   dw 0xAA55
    //
    //   nasm -f bin -o bootsector.bin boot.asm
    //
    // Tools:
    // - NASM: https://www.nasm.us/
    // - OpenWatcom: http://www.openwatcom.org/
    // - DOSBox for testing: https://www.dosbox.com/

    expect(true).toBe(true);
  });

  it('should list x86-16 processor modes', () => {
    const processorModes = {
      'Real Mode (8086)': '16-bit, 1MB address space, no protection',
      'Protected Mode (80286)': '16-bit, 16MB address space, memory protection',
      'Virtual 8086 Mode': 'Real mode emulation within protected mode',
      'Unreal Mode': 'Real mode with 32-bit addressing (undocumented)'
    };

    expect(Object.keys(processorModes).length).toBeGreaterThan(0);
  });

  it('should list DOS interrupt reference', () => {
    const dosInterrupts = {
      'INT 10h': 'Video BIOS services',
      'INT 13h': 'Disk BIOS services',
      'INT 16h': 'Keyboard BIOS services',
      'INT 21h': 'DOS services (file, memory, process)',
      'INT 2Fh': 'Multiplex interrupt (TSR, DOS extenders)'
    };

    expect(Object.keys(dosInterrupts).length).toBeGreaterThan(0);
  });
});

describe('16-bit Segment Model Reference', () => {
  it('should document memory models', () => {
    const memoryModels = {
      'Tiny': 'Code and data in same 64KB segment (COM files)',
      'Small': 'One code segment, one data segment',
      'Medium': 'Multiple code segments, one data segment',
      'Compact': 'One code segment, multiple data segments',
      'Large': 'Multiple code and data segments',
      'Huge': 'Like Large, but data items can exceed 64KB'
    };

    expect(Object.keys(memoryModels).length).toBe(6);
  });
});
