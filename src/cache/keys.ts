import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface CacheKey {
  fileHash: string;
  ghidraVersion: string;
  araelVersion: string;
}

/**
 * Generate a cache key for a binary file.
 * The key is a composite of file hash, Ghidra version, and Arael version.
 */
export function generateCacheKey(filepath: string): CacheKey {
  const absolutePath = path.resolve(filepath);
  const fileBuffer = fs.readFileSync(absolutePath);
  const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  // Get Arael version from package.json
  let araelVersion = '1.0.0';
  try {
    const packagePath = path.join(__dirname, '../../package.json');
    if (fs.existsSync(packagePath)) {
      const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8')) as { version?: string };
      araelVersion = pkg.version ?? '1.0.0';
    }
  } catch {
    // Use default version
  }

  return {
    fileHash,
    ghidraVersion: process.env['GHIDRA_VERSION'] ?? 'unknown',
    araelVersion
  };
}

/**
 * Convert a CacheKey to a string for storage.
 */
export function cacheKeyToString(key: CacheKey): string {
  return `${key.fileHash}_ghidra${key.ghidraVersion}_arael${key.araelVersion}`;
}

/**
 * Generate file hashes (MD5, SHA1, SHA256) for a binary.
 */
export function generateFileHashes(filepath: string): {
  md5: string;
  sha1: string;
  sha256: string;
} {
  const absolutePath = path.resolve(filepath);
  const fileBuffer = fs.readFileSync(absolutePath);

  return {
    md5: crypto.createHash('md5').update(fileBuffer).digest('hex'),
    sha1: crypto.createHash('sha1').update(fileBuffer).digest('hex'),
    sha256: crypto.createHash('sha256').update(fileBuffer).digest('hex')
  };
}
