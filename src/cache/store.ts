import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { generateCacheKey, cacheKeyToString } from './keys';
import { AnalysisResult } from '../output/schema';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS analysis_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cache_key TEXT UNIQUE NOT NULL,
  file_hash TEXT NOT NULL,
  filepath TEXT NOT NULL,
  ghidra_version TEXT NOT NULL,
  arael_version TEXT NOT NULL,
  analysis_json TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_file_hash ON analysis_cache(file_hash);
CREATE INDEX IF NOT EXISTS idx_created_at ON analysis_cache(created_at);
`;

export class AnalysisCache {
  private db: Database.Database;
  private dbPath: string;

  constructor(dbPath?: string) {
    this.dbPath = dbPath ?? this.getDefaultDbPath();
    this.ensureDirectoryExists();
    this.db = new Database(this.dbPath);
    this.initialize();
  }

  private getDefaultDbPath(): string {
    const araelDir = path.join(os.homedir(), '.arael', 'cache');
    return path.join(araelDir, 'analysis.db');
  }

  private ensureDirectoryExists(): void {
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  private initialize(): void {
    this.db.exec(SCHEMA);
  }

  /**
   * Return the SQLite database path used by this cache.
   */
  getDbPath(): string {
    return this.dbPath;
  }

  /**
   * Get cached analysis result for a file.
   * Returns null if not found, file doesn't exist, or cache key doesn't match.
   */
  get(filepath: string): AnalysisResult | null {
    let keyString: string;
    try {
      const cacheKey = generateCacheKey(filepath);
      keyString = cacheKeyToString(cacheKey);
    } catch {
      // File doesn't exist or can't be read
      return null;
    }

    const row = this.db.prepare(
      'SELECT analysis_json FROM analysis_cache WHERE cache_key = ?'
    ).get(keyString) as { analysis_json: string } | undefined;

    if (row) {
      // Update access time for LRU tracking
      this.db.prepare(
        'UPDATE analysis_cache SET accessed_at = CURRENT_TIMESTAMP WHERE cache_key = ?'
      ).run(keyString);

      return JSON.parse(row.analysis_json) as AnalysisResult;
    }

    return null;
  }

  /**
   * List cached analyses without returning the full stored JSON payload.
   */
  listEntries(limit = 20): AnalysisCacheEntrySummary[] {
    const safeLimit = Math.max(1, Math.min(1000, Math.floor(limit)));
    const rows = this.db.prepare(`
      SELECT
        id,
        cache_key as cacheKey,
        file_hash as fileHash,
        filepath,
        ghidra_version as ghidraVersion,
        arael_version as araelVersion,
        created_at as createdAt,
        accessed_at as accessedAt,
        analysis_json as analysisJson
      FROM analysis_cache
      ORDER BY accessed_at DESC, created_at DESC, id DESC
      LIMIT ?
    `).all(safeLimit) as AnalysisCacheRow[];

    return rows.map(row => this.rowToSummary(row));
  }

  /**
   * Resolve a cached analysis by path, row id, cache key, SHA-256 file hash, or stored filepath.
   */
  getEntry(identifier: string): AnalysisCacheEntry | null {
    const row = this.resolveEntryRow(identifier);
    if (!row) {
      return null;
    }

    this.db.prepare(
      'UPDATE analysis_cache SET accessed_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).run(row.id);

    return this.rowToEntry(row);
  }

  /**
   * Check if a file has a valid cache entry.
   */
  has(filepath: string): boolean {
    const cacheKey = generateCacheKey(filepath);
    const keyString = cacheKeyToString(cacheKey);

    const row = this.db.prepare(
      'SELECT 1 FROM analysis_cache WHERE cache_key = ?'
    ).get(keyString);

    return row !== undefined;
  }

  /**
   * Store analysis result in cache.
   */
  set(filepath: string, result: AnalysisResult): void {
    const cacheKey = generateCacheKey(filepath);
    const keyString = cacheKeyToString(cacheKey);

    this.db.prepare(`
      INSERT OR REPLACE INTO analysis_cache
      (cache_key, file_hash, filepath, ghidra_version, arael_version, analysis_json)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      keyString,
      cacheKey.fileHash,
      filepath,
      cacheKey.ghidraVersion,
      cacheKey.araelVersion,
      JSON.stringify(result)
    );
  }

  /**
   * Remove a specific cache entry.
   */
  delete(filepath: string): boolean {
    const cacheKey = generateCacheKey(filepath);
    const keyString = cacheKeyToString(cacheKey);

    const result = this.db.prepare(
      'DELETE FROM analysis_cache WHERE cache_key = ?'
    ).run(keyString);

    return result.changes > 0;
  }

  /**
   * Invalidate all cache entries.
   */
  invalidateAll(): number {
    const result = this.db.prepare('DELETE FROM analysis_cache').run();
    return result.changes;
  }

  /**
   * Prune cache entries older than specified days.
   */
  pruneOldEntries(maxAgeDays = 30): number {
    const result = this.db.prepare(
      `DELETE FROM analysis_cache WHERE created_at < datetime('now', '-${maxAgeDays} days')`
    ).run();
    return result.changes;
  }

  /**
   * Get cache statistics.
   */
  getStats(): { count: number; sizeBytes: number } {
    const count = this.db.prepare(
      'SELECT COUNT(*) as count FROM analysis_cache'
    ).get() as { count: number };

    const stats = fs.statSync(this.dbPath);

    return {
      count: count.count,
      sizeBytes: stats.size
    };
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db.close();
  }

  private resolveEntryRow(identifier: string): AnalysisCacheRow | null {
    if (fs.existsSync(identifier)) {
      try {
        const cacheKey = cacheKeyToString(generateCacheKey(identifier));
        return this.findRow('cache_key = ?', cacheKey);
      } catch {
        return null;
      }
    }

    if (/^\d+$/.test(identifier)) {
      const byId = this.findRow('id = ?', Number(identifier));
      if (byId) {
        return byId;
      }
    }

    const byCacheKey = this.findRow('cache_key = ?', identifier);
    if (byCacheKey) {
      return byCacheKey;
    }

    if (/^[a-fA-F0-9]{64}$/.test(identifier)) {
      const byFileHash = this.findRow('file_hash = ?', identifier.toLowerCase(), 'created_at DESC, id DESC');
      if (byFileHash) {
        return byFileHash;
      }
    }

    return this.findRow('filepath = ?', identifier, 'created_at DESC, id DESC');
  }

  private findRow(whereSql: string, value: string | number, orderBy = 'id DESC'): AnalysisCacheRow | null {
    const row = this.db.prepare(`
      SELECT
        id,
        cache_key as cacheKey,
        file_hash as fileHash,
        filepath,
        ghidra_version as ghidraVersion,
        arael_version as araelVersion,
        created_at as createdAt,
        accessed_at as accessedAt,
        analysis_json as analysisJson
      FROM analysis_cache
      WHERE ${whereSql}
      ORDER BY ${orderBy}
      LIMIT 1
    `).get(value) as AnalysisCacheRow | undefined;

    return row ?? null;
  }

  private rowToSummary(row: AnalysisCacheRow): AnalysisCacheEntrySummary {
    const analysis = this.parseAnalysis(row.analysisJson);
    return {
      id: row.id,
      cacheKey: row.cacheKey,
      fileHash: row.fileHash,
      filepath: row.filepath,
      ghidraVersion: row.ghidraVersion,
      araelVersion: row.araelVersion,
      createdAt: row.createdAt,
      accessedAt: row.accessedAt,
      analysisId: analysis?.metadata.analysisId ?? null,
      timestamp: analysis?.metadata.timestamp ?? null,
      binaryFilename: analysis?.binary.filename ?? null,
      format: analysis?.binary.format ?? null,
      architecture: analysis?.binary.architecture ?? null,
      functionCount: analysis?.functions.length ?? null,
      stringCount: analysis?.strings.length ?? null,
      importCount: analysis?.imports.length ?? null
    };
  }

  private rowToEntry(row: AnalysisCacheRow): AnalysisCacheEntry {
    return {
      ...this.rowToSummary(row),
      analysis: this.parseAnalysis(row.analysisJson) ?? JSON.parse(row.analysisJson) as AnalysisResult
    };
  }

  private parseAnalysis(value: string): AnalysisResult | null {
    try {
      return JSON.parse(value) as AnalysisResult;
    } catch {
      return null;
    }
  }
}

interface AnalysisCacheRow {
  id: number;
  cacheKey: string;
  fileHash: string;
  filepath: string;
  ghidraVersion: string;
  araelVersion: string;
  createdAt: string;
  accessedAt: string;
  analysisJson: string;
}

export interface AnalysisCacheEntrySummary {
  id: number;
  cacheKey: string;
  fileHash: string;
  filepath: string;
  ghidraVersion: string;
  araelVersion: string;
  createdAt: string;
  accessedAt: string;
  analysisId: string | null;
  timestamp: string | null;
  binaryFilename: string | null;
  format: string | null;
  architecture: string | null;
  functionCount: number | null;
  stringCount: number | null;
  importCount: number | null;
}

export interface AnalysisCacheEntry extends AnalysisCacheEntrySummary {
  analysis: AnalysisResult;
}

// Singleton instance
let cacheInstance: AnalysisCache | null = null;

export function getCache(): AnalysisCache {
  if (!cacheInstance) {
    cacheInstance = new AnalysisCache();
  }
  return cacheInstance;
}
