import { getConnection } from '../../ghidra/connection';
import { validateBinary } from '../../utils/preflight';
import { logger } from '../../utils/logger';

export interface ExportsArgs {
  filepath: string;
  filter?: {
    namePattern?: string;
    type?: 'function' | 'data' | 'all';
  };
}

export interface ExportInfo {
  name: string;
  address: string;
  size: number;
  type: 'function' | 'data';
}

export interface ExportsResult {
  exports: ExportInfo[];
  totalCount: number;
  error?: string;
}

export async function exportsHandler(args: ExportsArgs): Promise<ExportsResult> {
  const { filepath, filter } = args;

  // Validate binary
  await validateBinary(filepath);

  logger.info('Listing exported symbols', { filepath, filter });

  const connection = getConnection();

  try {
    const exports = await connection.getExports(filepath, filter);

    if (exports === null) {
      return {
        exports: [],
        totalCount: 0,
        error: 'Failed to retrieve exports'
      };
    }

    return {
      exports,
      totalCount: exports.length
    };
  } catch (error) {
    logger.error('Failed to get exports', { error: String(error) });
    return {
      exports: [],
      totalCount: 0,
      error: String(error)
    };
  }
}
