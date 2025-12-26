/**
 * Mock responses for Ghidra bridge/headless testing
 */

import { AnalysisResult, FunctionInfo, StringInfo, ImportInfo } from '../../src/output/schema';

export const mockFunctions: FunctionInfo[] = [
  {
    name: 'main',
    address: '0x401150',
    size: 50,
    signature: 'int main(int argc, char **argv)',
    isThunk: false,
    isExternal: false,
    callers: ['0x401000'],
    callees: ['printf'],
    pseudocode: `int main(int argc, char **argv) {
    printf("Hello, World!\\n");
    return 0;
}`
  },
  {
    name: '_start',
    address: '0x401000',
    size: 30,
    signature: 'void _start(void)',
    isThunk: false,
    isExternal: false,
    callers: [],
    callees: ['__libc_start_main', 'main'],
    pseudocode: null
  },
  {
    name: 'printf',
    address: '0x401030',
    size: 16,
    signature: 'int printf(const char *format, ...)',
    isThunk: true,
    isExternal: true,
    callers: ['0x401150'],
    callees: [],
    pseudocode: null
  }
];

export const mockStrings: StringInfo[] = [
  {
    address: '0x402000',
    value: 'Hello, World!',
    length: 13,
    encoding: 'ascii',
    xrefs: [
      {
        address: '0x401160',
        function: 'main',
        type: 'data'
      }
    ]
  },
  {
    address: '0x402010',
    value: '/lib64/ld-linux-x86-64.so.2',
    length: 27,
    encoding: 'ascii',
    xrefs: []
  }
];

export const mockImports: ImportInfo[] = [
  {
    name: 'printf',
    library: 'libc.so.6',
    address: '0x401030',
    type: 'function'
  },
  {
    name: '__libc_start_main',
    library: 'libc.so.6',
    address: '0x401040',
    type: 'function'
  }
];

export const mockAnalysisResult: AnalysisResult = {
  version: '1.0.0',
  metadata: {
    analysisId: 'mock-analysis-id',
    timestamp: '2024-01-01T00:00:00Z',
    araelVersion: '1.0.0',
    ghidraVersion: '11.0',
    analysisDurationMs: 1500,
    connectionMode: 'headless',
    cached: false
  },
  binary: {
    filename: 'hello_world',
    filepath: '/test/hello_world',
    size: 16384,
    hashes: {
      md5: 'd41d8cd98f00b204e9800998ecf8427e',
      sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    },
    format: 'ELF',
    architecture: 'x86_64',
    endianness: 'little',
    entryPoint: '0x401000',
    imageBase: '0x400000'
  },
  functions: mockFunctions,
  strings: mockStrings,
  imports: mockImports
};
