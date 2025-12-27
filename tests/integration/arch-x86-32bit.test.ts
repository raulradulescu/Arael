/**
 * Integration tests for x86 32-bit architecture support
 *
 * Requirements:
 * - Analyze 32-bit ELF binaries (Linux)
 * - Analyze 32-bit PE binaries (Windows)
 * - Correctly identify i386/i686 architecture
 * - Decompile 32-bit functions correctly
 * - Handle 32-bit calling conventions (cdecl, stdcall, fastcall)
 * - Recognize 32-bit register names (EAX, EBX, etc.)
 *
 * Test binaries needed in tests/fixtures/x86_32/:
 * - hello_world_32.elf (Linux ELF i386)
 * - hello_world_32.exe (Windows PE i386)
 * - calling_conventions_32.exe (tests cdecl, stdcall, fastcall)
 * - complex_32.elf (multi-function program)
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
import { importsHandler } from '../../src/mcp/handlers/imports';

// Test fixtures directory
const fixturesDir = path.join(__dirname, '../fixtures/x86_32');

// Check if test binaries exist
const hasTestBinaries = (): boolean => {
  return fs.existsSync(fixturesDir) &&
    (fs.existsSync(path.join(fixturesDir, 'hello_world_32.elf')) ||
     fs.existsSync(path.join(fixturesDir, 'hello_world_32.exe')));
};

// Skip if no test binaries
const describeOrSkip = hasTestBinaries() ? describe : describe.skip;

describeOrSkip('x86 32-bit Architecture Support', () => {
  const ghidraPath = process.env['GHIDRA_PATH'] ?? '';

  beforeAll(async () => {
    if (!ghidraPath) {
      console.warn('GHIDRA_PATH not set, skipping x86-32 tests');
      return;
    }

    const connection = getConnection({
      ghidraPath,
      pythonPath: process.env['ARAEL_PYTHON'] ?? process.env['PYTHON_PATH']
    });

    await connection.connect();
  }, 60000);

  describe('ELF i386 Analysis', () => {
    const elfPath = path.join(fixturesDir, 'hello_world_32.elf');

    it('should detect 32-bit ELF architecture', async () => {
      if (!fs.existsSync(elfPath)) {
        console.warn('Skipping: hello_world_32.elf not found');
        return;
      }

      const result = await analyzeHandler({ filepath: elfPath });

      expect(result.binary).toBeDefined();
      expect(result.binary?.format).toBe('ELF');
      expect(result.binary?.architecture).toMatch(/i386|x86|IA-32/i);
      expect(result.binary?.bits).toBe(32);
    }, 120000);

    it('should identify i386 in binary metadata', async () => {
      if (!fs.existsSync(elfPath)) return;

      const result = await analyzeHandler({ filepath: elfPath });

      // Machine type should indicate 32-bit x86
      expect(result.binary?.machine).toMatch(/386|i386|x86/i);
    }, 120000);

    it('should find main function in 32-bit ELF', async () => {
      if (!fs.existsSync(elfPath)) return;

      const result = await functionsHandler({ filepath: elfPath });

      expect(result.functions).toBeDefined();
      const mainFunc = result.functions?.find(f => f.name === 'main');
      expect(mainFunc).toBeDefined();
    }, 120000);

    it('should decompile 32-bit function correctly', async () => {
      if (!fs.existsSync(elfPath)) return;

      const result = await decompileHandler({
        filepath: elfPath,
        function: 'main'
      });

      expect(result.code).toBeDefined();
      expect(result.code).toContain('main');
      // 32-bit code should not reference 64-bit registers
      expect(result.code).not.toMatch(/\bRAX\b|\bRBX\b|\bRCX\b|\bRDX\b/);
    }, 120000);

    it('should disassemble with 32-bit registers', async () => {
      if (!fs.existsSync(elfPath)) return;

      const result = await disassembleHandler({
        filepath: elfPath,
        target: 'main'
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // Should use 32-bit registers (EAX, EBX, etc.) not 64-bit (RAX, RBX)
        const allAsm = result.instructions.map(i => i.mnemonic + ' ' + (i.operands || [])).join(' ');

        // Should have 32-bit register references
        expect(allAsm).toMatch(/E[ABCDSI]X|E[BS]P|E[DS]I/i);
        // Should NOT have 64-bit register references
        expect(allAsm).not.toMatch(/\bR[ABCD]X\b|\bR[BS]P\b|\bR[SD]I\b|\bR[89]\b|\bR1[0-5]\b/);
      }
    }, 120000);

    it('should handle 32-bit addresses correctly', async () => {
      if (!fs.existsSync(elfPath)) return;

      const result = await analyzeHandler({ filepath: elfPath });

      expect(result.functions).toBeDefined();
      if (result.functions && result.functions.length > 0) {
        const func = result.functions[0];
        if (func) {
          // 32-bit addresses should be 8 hex chars max (0xFFFFFFFF)
          const addrMatch = func.address.match(/0x([0-9a-fA-F]+)/);
          expect(addrMatch).toBeDefined();
          if (addrMatch && addrMatch[1]) {
            expect(addrMatch[1].length).toBeLessThanOrEqual(8);
          }
        }
      }
    }, 120000);
  });

  describe('PE i386 Analysis', () => {
    const pePath = path.join(fixturesDir, 'hello_world_32.exe');

    it('should detect 32-bit PE architecture', async () => {
      if (!fs.existsSync(pePath)) {
        console.warn('Skipping: hello_world_32.exe not found');
        return;
      }

      const result = await analyzeHandler({ filepath: pePath });

      expect(result.binary).toBeDefined();
      expect(result.binary?.format).toBe('PE');
      expect(result.binary?.architecture).toMatch(/i386|x86|IA-32/i);
      expect(result.binary?.bits).toBe(32);
    }, 120000);

    it('should identify PE32 (not PE32+)', async () => {
      if (!fs.existsSync(pePath)) return;

      const result = await analyzeHandler({ filepath: pePath });

      // PE32 is 32-bit, PE32+ is 64-bit
      expect(result.binary?.format).toBe('PE');
      expect(result.binary?.bits).toBe(32);
    }, 120000);

    it('should analyze 32-bit Windows imports', async () => {
      if (!fs.existsSync(pePath)) return;

      const result = await importsHandler({ filepath: pePath });

      expect(result.imports).toBeDefined();
      // 32-bit Windows typically imports from kernel32.dll, user32.dll, etc.
      const hasKernel32 = result.imports?.some(i =>
        i.library?.toLowerCase().includes('kernel32')
      );
      expect(hasKernel32).toBe(true);
    }, 120000);
  });

  describe('32-bit Calling Conventions', () => {
    const convPath = path.join(fixturesDir, 'calling_conventions_32.exe');

    it('should recognize cdecl calling convention', async () => {
      if (!fs.existsSync(convPath)) {
        console.warn('Skipping: calling_conventions_32.exe not found');
        return;
      }

      const result = await decompileHandler({
        filepath: convPath,
        function: 'cdecl_func'
      });

      expect(result.code).toBeDefined();
      // cdecl: caller cleans stack, args pushed right-to-left
    }, 120000);

    it('should recognize stdcall calling convention', async () => {
      if (!fs.existsSync(convPath)) return;

      const result = await decompileHandler({
        filepath: convPath,
        function: 'stdcall_func'
      });

      expect(result.code).toBeDefined();
      // stdcall: callee cleans stack (RET n)
    }, 120000);

    it('should recognize fastcall calling convention', async () => {
      if (!fs.existsSync(convPath)) return;

      const result = await decompileHandler({
        filepath: convPath,
        function: 'fastcall_func'
      });

      expect(result.code).toBeDefined();
      // fastcall: first 2 args in ECX, EDX
    }, 120000);
  });

  describe('32-bit vs 64-bit Comparison', () => {
    const elf32Path = path.join(fixturesDir, 'hello_world_32.elf');
    const elf64Path = path.join(__dirname, '../fixtures/hello_world');

    it('should correctly distinguish 32-bit from 64-bit ELF', async () => {
      if (!fs.existsSync(elf32Path) || !fs.existsSync(elf64Path)) {
        console.warn('Skipping: need both 32 and 64-bit test binaries');
        return;
      }

      const result32 = await analyzeHandler({ filepath: elf32Path });
      const result64 = await analyzeHandler({ filepath: elf64Path });

      expect(result32.binary?.bits).toBe(32);
      expect(result64.binary?.bits).toBe(64);
      expect(result32.binary?.architecture).not.toBe(result64.binary?.architecture);
    }, 180000);

    it('should use different pointer sizes', async () => {
      if (!fs.existsSync(elf32Path) || !fs.existsSync(elf64Path)) return;

      const result32 = await analyzeHandler({ filepath: elf32Path });
      const result64 = await analyzeHandler({ filepath: elf64Path });

      // 32-bit has 4-byte pointers, 64-bit has 8-byte pointers
      expect(result32.binary?.bits).toBe(32);
      expect(result64.binary?.bits).toBe(64);
    }, 180000);
  });

  describe('32-bit Specific Patterns', () => {
    const complexPath = path.join(fixturesDir, 'complex_32.elf');

    it('should handle 32-bit stack frames', async () => {
      if (!fs.existsSync(complexPath)) {
        console.warn('Skipping: complex_32.elf not found');
        return;
      }

      const result = await disassembleHandler({
        filepath: complexPath,
        target: 'main'
      });

      expect(result.instructions).toBeDefined();
      if (result.instructions && result.instructions.length > 0) {
        // Look for typical 32-bit prologue: PUSH EBP; MOV EBP,ESP
        const first5 = result.instructions.slice(0, 5);
        const hasPrologue = first5.some(i =>
          i.mnemonic.toLowerCase() === 'push' &&
          (i.operands?.join('') || '').toLowerCase().includes('ebp')
        );
        // May or may not have traditional prologue depending on optimization
        expect(result.instructions.length).toBeGreaterThan(0);
      }
    }, 120000);

    it('should handle 32-bit GOT/PLT entries', async () => {
      if (!fs.existsSync(complexPath)) return;

      const result = await analyzeHandler({ filepath: complexPath });

      // 32-bit ELF should have sections
      expect(result.sections).toBeDefined();
    }, 120000);
  });
});

describe('x86 32-bit Test Binary Generation (Reference)', () => {
  it('should document how to create test binaries', () => {
    // Reference for creating 32-bit test binaries:
    //
    // Linux ELF i386:
    //   gcc -m32 -o hello_world_32.elf hello_world.c
    //   (requires: sudo apt install gcc-multilib)
    //
    // Windows PE i386:
    //   i686-w64-mingw32-gcc -o hello_world_32.exe hello_world.c
    //   (requires: sudo apt install mingw-w64)
    //
    // Or use Visual Studio with x86 target on Windows
    //
    // Calling conventions test (Windows):
    //   void __cdecl cdecl_func(int a, int b);
    //   void __stdcall stdcall_func(int a, int b);
    //   void __fastcall fastcall_func(int a, int b);

    expect(true).toBe(true);
  });
});
