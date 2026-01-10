import * as fs from 'fs';
import * as path from 'path';

/**
 * Simple glob implementation for matching file patterns
 * Supports: * (any chars), ? (single char), ** (recursive)
 */
export function glob(pattern: string, cwd: string = process.cwd()): string[] {
  const results: string[] = [];

  // Normalize pattern
  const normalizedPattern = pattern.replace(/\\/g, '/');

  // Check if pattern has wildcards
  if (!normalizedPattern.includes('*') && !normalizedPattern.includes('?')) {
    // No wildcards, check if file exists
    const fullPath = path.isAbsolute(pattern) ? pattern : path.join(cwd, pattern);
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      return [fullPath];
    }
    return [];
  }

  // Split pattern into directory and file parts
  const parts = normalizedPattern.split('/');

  // Find the base directory (up to first wildcard)
  let baseDir = cwd;
  let patternParts: string[] = [];
  let foundWildcard = false;

  for (const part of parts) {
    if (!foundWildcard && !part.includes('*') && !part.includes('?')) {
      baseDir = path.join(baseDir, part);
    } else {
      foundWildcard = true;
      patternParts.push(part);
    }
  }

  // Recursive search function
  function search(dir: string, remainingParts: string[]): void {
    if (!fs.existsSync(dir)) return;

    const [current, ...rest] = remainingParts;

    if (!current) {
      // No more pattern parts, this directory matches
      return;
    }

    // Handle ** (recursive)
    if (current === '**') {
      // Match zero or more directories
      if (rest.length > 0) {
        // Try matching rest in current directory
        search(dir, rest);

        // Recurse into subdirectories
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isDirectory()) {
              search(path.join(dir, entry.name), remainingParts);
            }
          }
        } catch {
          // Permission denied or other error
        }
      }
      return;
    }

    // Convert glob pattern to regex
    const regexPattern = current
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    const regex = new RegExp(`^${regexPattern}$`);

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (regex.test(entry.name)) {
          const fullPath = path.join(dir, entry.name);

          if (rest.length === 0) {
            // Last pattern part, add if it's a file
            if (entry.isFile()) {
              results.push(fullPath);
            }
          } else {
            // More pattern parts, recurse if directory
            if (entry.isDirectory()) {
              search(fullPath, rest);
            }
          }
        }
      }
    } catch {
      // Permission denied or other error
    }
  }

  search(baseDir, patternParts);
  return results.sort();
}

/**
 * Expand multiple patterns
 */
export function expandPatterns(patterns: string[], cwd: string = process.cwd()): string[] {
  const results = new Set<string>();

  for (const pattern of patterns) {
    const matches = glob(pattern, cwd);
    for (const match of matches) {
      results.add(match);
    }
  }

  return Array.from(results).sort();
}
