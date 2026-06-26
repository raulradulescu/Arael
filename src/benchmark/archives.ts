import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.7z']);

export interface ArchiveExtractionResult {
  outputRoot: string;
  extractedArchives: string[];
}

export function isArchivePath(filepath: string): boolean {
  return ARCHIVE_EXTENSIONS.has(path.extname(filepath).toLowerCase());
}

export function expandArchives(options: {
  target: string;
  password?: string;
  outputDir?: string;
  maxNestedArchives?: number;
}): ArchiveExtractionResult {
  const target = path.resolve(options.target);
  const outputRoot = path.resolve(
    options.outputDir ?? path.join(path.dirname(target), 'extracted')
  );
  fs.mkdirSync(outputRoot, { recursive: true });

  const extractedArchives: string[] = [];
  const archives = fs.existsSync(target) && fs.statSync(target).isFile()
    ? [target]
    : findArchives(target);

  for (const archive of archives) {
    extractArchive(archive, outputRoot, options.password);
    extractedArchives.push(archive);
  }

  let nested = limitArchives(
    findArchives(outputRoot).filter(archive => !extractedArchives.includes(archive)),
    options.maxNestedArchives
  );
  while (nested.length > 0) {
    for (const archive of nested) {
      const destination = archiveDestination(outputRoot, archive);
      extractArchive(archive, destination, options.password);
      extractedArchives.push(archive);
    }
    nested = limitArchives(
      findArchives(outputRoot).filter(archive => !extractedArchives.includes(archive)),
      options.maxNestedArchives === undefined
        ? undefined
        : Math.max(0, options.maxNestedArchives - extractedArchives.length)
    );
  }

  return { outputRoot, extractedArchives };
}

function limitArchives(archives: string[], limit?: number): string[] {
  return limit === undefined ? archives : archives.slice(0, limit);
}

function findArchives(root: string): string[] {
  if (!fs.existsSync(root)) {
    return [];
  }

  const stats = fs.statSync(root);
  if (stats.isFile()) {
    return isArchivePath(root) ? [root] : [];
  }

  const results: string[] = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'extracted' || entry.name.startsWith('.')) {
        continue;
      }
      results.push(...findArchives(fullPath));
    } else if (entry.isFile() && isArchivePath(fullPath)) {
      results.push(fullPath);
    }
  }

  return results.sort();
}

function extractArchive(archive: string, outputRoot: string, password?: string): void {
  const destination = archiveDestination(outputRoot, archive);
  fs.mkdirSync(destination, { recursive: true });

  const existing = fs.readdirSync(destination);
  if (existing.length > 0) {
    return;
  }

  const extension = path.extname(archive).toLowerCase();
  if (extension === '.zip') {
    const args = ['-q'];
    if (password) {
      args.push('-P', password);
    }
    args.push(archive, '-d', destination);
    execFileSync('unzip', args, { stdio: 'pipe' });
    return;
  }

  if (extension === '.7z') {
    const args = ['x', '-y', `-o${destination}`];
    if (password) {
      args.push(`-p${password}`);
    }
    args.push(archive);
    execFileSync('7z', args, { stdio: 'pipe' });
    return;
  }

  throw new Error(`Unsupported archive format: ${archive}`);
}

function archiveDestination(outputRoot: string, archive: string): string {
  const basename = path.basename(archive, path.extname(archive));
  return path.join(outputRoot, sanitizeName(basename));
}

function sanitizeName(value: string): string {
  return value.replace(/[^\w .()-]+/g, '_').trim() || 'archive';
}
