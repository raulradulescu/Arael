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
}

// Singleton instance
let cacheInstance: AnalysisCache | null = null;

export function getCache(): AnalysisCache {
  if (!cacheInstance) {
    cacheInstance = new AnalysisCache();
  }
  return cacheInstance;
}
