import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { StringInfo } from '../../output/schema';
import { analyzeHandler } from './analyze';
import { logger } from '../../utils/logger';
import { extractStringsWithSystemTool } from '../../utils/system_strings';

export interface StringsArgs {
  filepath: string;
  minLength?: number;
  encoding?: 'ascii' | 'utf8' | 'utf16le' | 'all';
}

export async function stringsHandler(args: StringsArgs): Promise<StringInfo[]> {
  const { filepath, minLength = 4, encoding = 'all' } = args;

  // Validate binary
  const preflight = await validateBinary(filepath);

  // Get or create analysis
  const cache = getCache();
  let strings: StringInfo[];

  const cached = cache.get(filepath);
  if (cached) {
    strings = cached.strings;
  } else {
    const preferSystem = process.env['ARAEL_USE_SYSTEM_STRINGS'] === '1';
    const grepPattern = process.env['ARAEL_STRINGS_GREP'];

    if (preferSystem) {
      logger.info('Using system strings tool', { filepath });
      strings = await extractStringsWithSystemTool(preflight.absolutePath, {
        minLength,
        encoding,
        pattern: grepPattern
      });
    } else {
      try {
        logger.info('No cache found, running analysis', { filepath });
        const result = await analyzeHandler({ filepath });
        strings = result.strings;
      } catch (error) {
        logger.warn('Ghidra analysis failed, falling back to system strings', {
          error: error instanceof Error ? error.message : String(error)
        });
        strings = await extractStringsWithSystemTool(preflight.absolutePath, {
          minLength,
          encoding,
          pattern: grepPattern
        });
      }
    }
  }

  // Apply filters
  let filtered = strings;

  // Filter by length
  filtered = filtered.filter((s) => s.length >= minLength);

  // Filter by encoding
  if (encoding !== 'all') {
    filtered = filtered.filter((s) => s.encoding === encoding);
  }

  const grepPattern = process.env['ARAEL_STRINGS_GREP'];
  if (grepPattern) {
    const regex = new RegExp(grepPattern);
    filtered = filtered.filter((s) => regex.test(s.value));
  }

  return filtered;
}
