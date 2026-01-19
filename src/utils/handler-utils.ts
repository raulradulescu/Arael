/**
 * Handler utilities for reducing code duplication across MCP handlers.
 */

import { getCache } from '../cache/store';
import type { AnalysisResult } from '../output/schema';
import { validateBinary } from './preflight';
import { logger } from './logger';

/**
 * Get cached analysis result or run analysis if not cached.
 * Centralizes the common cache-check-or-analyze pattern used across handlers.
 */
export async function getCachedOrAnalyze(filepath: string): Promise<AnalysisResult | null> {
  const cache = getCache();
  const cached = cache.get(filepath);

  if (cached) {
    return cached;
  }

  // Import dynamically to avoid circular dependency
  const { analyzeHandler } = await import('../mcp/handlers/analyze');

  logger.info('No cache found, running analysis', { filepath });
  return analyzeHandler({ filepath });
}

/**
 * Get cached analysis result only (no fallback to analysis).
 * Use when you don't want to trigger a full analysis.
 */
export function getCached(filepath: string): AnalysisResult | null {
  const cache = getCache();
  return cache.get(filepath);
}

/**
 * Handler factory for creating data extraction handlers.
 * Reduces boilerplate for simple handlers that extract and filter data from analysis.
 */
export function createDataHandler<T, A extends { filepath: string }>(
  extractor: (result: AnalysisResult) => T[],
  filterFn?: (items: T[], args: A) => T[]
): (args: A) => Promise<T[]> {
  return async (args: A): Promise<T[]> => {
    await validateBinary(args.filepath);

    const result = await getCachedOrAnalyze(args.filepath);
    if (!result) return [];

    let data = extractor(result);

    if (filterFn) {
      data = filterFn(data, args);
    }

    return data;
  };
}
