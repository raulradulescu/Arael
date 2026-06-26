import { renderAnalysisHtml } from '../../src/output/html';
import type { AnalysisResult } from '../../src/output/schema';

describe('analysis HTML report', () => {
  it('renders a standalone escaped document with interactive table hooks', () => {
    const html = renderAnalysisHtml(makeAnalysisResult(), {
      title: 'Custom <Report>',
      generatedAt: '2026-01-01T00:00:00.000Z',
      sourceLabel: 'SQLite cache row 1'
    });

    expect(html.match(/<!DOCTYPE html>/g)).toHaveLength(1);
    expect(html).toContain('<title>Custom &lt;Report&gt;</title>');
    expect(html).toContain('Source: SQLite cache row 1');
    expect(html).toContain('data-search-target="functions-table"');
    expect(html).toContain('data-search-target="strings-table"');
    expect(html).toContain('data-sortable="true"');
    expect(html).toContain('flag{&lt;script&gt;}');
    expect(html).toContain('data-copy="flag{&lt;script&gt;}"');
  });
});

function makeAnalysisResult(): AnalysisResult {
  return {
    version: '1.0.0',
    metadata: {
      analysisId: 'analysis-1',
      timestamp: '2026-01-01T00:00:00.000Z',
      araelVersion: 'test',
      ghidraVersion: 'test',
      analysisDurationMs: 10,
      connectionMode: 'headless',
      cached: false
    },
    binary: {
      filename: 'sample<bad>.bin',
      filepath: '/tmp/sample<bad>.bin',
      size: 4096,
      hashes: {
        md5: 'md5',
        sha1: 'sha1',
        sha256: 'sha256'
      },
      format: 'ELF',
      architecture: 'x86_64',
      bits: 64,
      endianness: 'little',
      entryPoint: '0x401000',
      imageBase: '0x400000',
      packing: {
        isPacked: false,
        packers: [],
        entropy: {
          overall: 5.5,
          sections: []
        },
        suspiciousIndicators: []
      }
    },
    sections: [{
      name: '.text',
      start: '0x401000',
      end: '0x402000',
      size: 4096,
      permissions: { read: true, write: false, execute: true },
      entropy: 5.1,
      anomalies: []
    }],
    functions: [{
      name: 'main<script>',
      address: '0x401000',
      size: 42,
      signature: 'int main()',
      isThunk: false,
      isExternal: false,
      callers: [],
      callees: [],
      pseudocode: null
    }],
    strings: [{
      address: '0x402000',
      value: 'flag{<script>}',
      length: 14,
      encoding: 'ascii',
      section: '.rodata',
      xrefs: []
    }],
    imports: [{
      name: 'connect',
      library: 'libc.so.6',
      address: '0x403000',
      type: 'function',
      capabilities: ['Network'],
      riskLevel: 'medium'
    }],
    exports: []
  };
}
