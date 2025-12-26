import { getConnection } from '../../ghidra/connection';
import { validateBinary } from '../../utils/preflight';
import { logger } from '../../utils/logger';

export interface XrefsArgs {
  filepath: string;
  address: string;
  direction?: 'to' | 'from' | 'both';
  maxResults?: number;
}

export interface XrefInfo {
  from?: string;
  to?: string;
  type: string;
  functionName?: string;
}

export interface XrefsResult {
  address: string;
  direction: 'to' | 'from' | 'both';
  references: XrefInfo[];
  error?: string;
}

export async function xrefsHandler(args: XrefsArgs): Promise<XrefsResult> {
  const {
    filepath,
    address,
    direction = 'both',
    maxResults = 100
  } = args;

  // Validate binary
  await validateBinary(filepath);

  logger.info('Finding cross-references', { filepath, address, direction, maxResults });

  const connection = getConnection();

  try {
    const references = await connection.getXrefs(
      filepath,
      address,
      direction,
      maxResults
    );

    if (references === null) {
      return {
        address,
        direction,
        references: [],
        error: `Address not found or invalid: ${address}`
      };
    }

    return {
      address,
      direction,
      references
    };
  } catch (error) {
    logger.error('Failed to get cross-references', { error: String(error) });
    return {
      address,
      direction,
      references: [],
      error: String(error)
    };
  }
}
