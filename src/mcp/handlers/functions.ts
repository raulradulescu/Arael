import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { FunctionInfo } from '../../output/schema';
import { analyzeHandler } from './analyze';
import { logger } from '../../utils/logger';

export interface FunctionsFilter {
  namePattern?: string;
  minSize?: number;
  maxSize?: number;
  excludeThunks?: boolean;
  excludeExternal?: boolean;
}

export interface FunctionsArgs {
  filepath: string;
  filter?: FunctionsFilter;
}

export interface FunctionSummary {
  name: string;
  address: string;
  size: number;
  signature: string;
  isThunk: boolean;
  isExternal: boolean;
}

export async function functionsHandler(args: FunctionsArgs): Promise<FunctionSummary[]> {
  const { filepath, filter } = args;

  // Validate binary
  await validateBinary(filepath);

  // Get or create analysis
  const cache = getCache();
  let functions: FunctionInfo[];

  const cached = cache.get(filepath);
  if (cached) {
    functions = cached.functions;
  } else {
    logger.info('No cache found, running analysis', { filepath });
    const result = await analyzeHandler({ filepath });
    functions = result.functions;
  }

  // Apply filters
  let filtered = functions;

  if (filter) {
    if (filter.namePattern) {
      const regex = new RegExp(filter.namePattern);
      filtered = filtered.filter((f) => regex.test(f.name));
    }

    if (filter.minSize !== undefined) {
      filtered = filtered.filter((f) => f.size >= filter.minSize!);
    }

    if (filter.maxSize !== undefined) {
      filtered = filtered.filter((f) => f.size <= filter.maxSize!);
    }

    if (filter.excludeThunks) {
      filtered = filtered.filter((f) => !f.isThunk);
    }

    if (filter.excludeExternal) {
      filtered = filtered.filter((f) => !f.isExternal);
    }
  }

  // Return summary (without pseudocode to reduce size)
  return filtered.map((f) => ({
    name: f.name,
    address: f.address,
    size: f.size,
    signature: f.signature,
    isThunk: f.isThunk,
    isExternal: f.isExternal
  }));
}
