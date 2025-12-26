import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { AnalysisCache } from '../../src/cache/store';
import { generateCacheKey, cacheKeyToString } from '../../src/cache/keys';
import { AnalysisResult } from '../../src/output/schema';

describe('Cache', () => {
  const tempDir = os.tmpdir();
  let testDbPath: string;
  let cache: AnalysisCache;

  beforeEach(() => {
    testDbPath = path.join(tempDir, `arael_test_cache_${Date.now()}.db`);
    cache = new AnalysisCache(testDbPath);
  });

  afterEach(() => {
    cache.close();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe('generateCacheKey', () => {
    it('should generate consistent hash for same file', () => {
      const testFile = path.join(tempDir, 'arael_test_key.bin');
      fs.writeFileSync(testFile, 'test content');

      try {
        const key1 = generateCacheKey(testFile);
        const key2 = generateCacheKey(testFile);

        expect(key1.fileHash).toBe(key2.fileHash);
      } finally {
        fs.unlinkSync(testFile);
      }
    });

    it('should generate different hash for different content', () => {
      const file1 = path.join(tempDir, 'arael_test_key1.bin');
      const file2 = path.join(tempDir, 'arael_test_key2.bin');
      fs.writeFileSync(file1, 'content 1');
      fs.writeFileSync(file2, 'content 2');

      try {
        const key1 = generateCacheKey(file1);
        const key2 = generateCacheKey(file2);

        expect(key1.fileHash).not.toBe(key2.fileHash);
      } finally {
        fs.unlinkSync(file1);
        fs.unlinkSync(file2);
      }
    });
  });

  describe('cacheKeyToString', () => {
    it('should create composite key string', () => {
      const key = {
        fileHash: 'abc123',
        ghidraVersion: '11.0',
        araelVersion: '1.0.0'
      };

      const str = cacheKeyToString(key);
      expect(str).toBe('abc123_ghidra11.0_arael1.0.0');
    });
  });

  describe('AnalysisCache', () => {
    const mockResult: AnalysisResult = {
      version: '1.0.0',
      metadata: {
        analysisId: 'test-id',
        timestamp: '2024-01-01T00:00:00Z',
        araelVersion: '1.0.0',
        ghidraVersion: 'test',
        analysisDurationMs: 1000,
        connectionMode: 'headless',
        cached: false
      },
      binary: {
        filename: 'test.bin',
        filepath: '/test/path',
        size: 1024,
        hashes: { md5: 'a', sha1: 'b', sha256: 'c' },
        format: 'ELF',
        architecture: 'x86_64',
        endianness: 'little',
        entryPoint: '0x1000',
        imageBase: '0x400000'
      },
      functions: [],
      strings: [],
      imports: []
    };

    it('should return null for non-cached file', () => {
      const result = cache.get('/nonexistent/file');
      expect(result).toBeNull();
    });

    it('should store and retrieve analysis result', () => {
      const testFile = path.join(tempDir, 'arael_test_cache.bin');
      fs.writeFileSync(testFile, 'test content');

      try {
        cache.set(testFile, mockResult);
        const retrieved = cache.get(testFile);

        expect(retrieved).not.toBeNull();
        expect(retrieved?.metadata.analysisId).toBe('test-id');
        expect(retrieved?.binary.filename).toBe('test.bin');
      } finally {
        fs.unlinkSync(testFile);
      }
    });

    it('should report correct stats', () => {
      const testFile = path.join(tempDir, 'arael_test_stats.bin');
      fs.writeFileSync(testFile, 'test content');

      try {
        const statsBefore = cache.getStats();
        expect(statsBefore.count).toBe(0);

        cache.set(testFile, mockResult);

        const statsAfter = cache.getStats();
        expect(statsAfter.count).toBe(1);
        expect(statsAfter.sizeBytes).toBeGreaterThan(0);
      } finally {
        fs.unlinkSync(testFile);
      }
    });

    it('should invalidate all entries', () => {
      const testFile = path.join(tempDir, 'arael_test_invalidate.bin');
      fs.writeFileSync(testFile, 'test content');

      try {
        cache.set(testFile, mockResult);
        expect(cache.getStats().count).toBe(1);

        const cleared = cache.invalidateAll();
        expect(cleared).toBe(1);
        expect(cache.getStats().count).toBe(0);
      } finally {
        fs.unlinkSync(testFile);
      }
    });
  });
});
