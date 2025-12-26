import { getConnection } from '../../ghidra/connection';
import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { AnalysisResult } from '../../output/schema';
import { logger } from '../../utils/logger';

export interface AnalyzeArgs {
  filepath: string;
  force?: boolean;
}

export async function analyzeHandler(args: AnalyzeArgs): Promise<AnalysisResult> {
  const { filepath, force = false } = args;

  // Validate binary
  await validateBinary(filepath);

  // Check cache unless force is set
  const cache = getCache();
  if (!force) {
    const cached = cache.get(filepath);
    if (cached) {
      logger.info('Returning cached analysis', { filepath });
      return {
        ...cached,
        metadata: {
          ...cached.metadata,
          cached: true
        }
      };
    }
  }

  // Perform analysis
  logger.info('Starting analysis', { filepath, force });
  const connection = getConnection();
  const result = await connection.analyze(filepath);

  // Cache result
  cache.set(filepath, result);
  logger.info('Analysis complete and cached', { filepath });

  return result;
}
