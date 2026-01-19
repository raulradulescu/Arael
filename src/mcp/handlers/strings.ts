import { validateBinary } from '../../utils/preflight';
import { getCachedOrAnalyze } from '../../utils/handler-utils';
import { StringInfo } from '../../output/schema';
import { logger } from '../../utils/logger';
import { extractStringsWithSystemTool } from '../../utils/system_strings';

export interface StringsArgs {
  filepath: string;
  minLength?: number;
  encoding?: 'ascii' | 'utf8' | 'utf16le' | 'all';
}

export async function stringsHandler(args: StringsArgs): Promise<StringInfo[]> {
  const { filepath, minLength = 4, encoding = 'all' } = args;
  const preflight = await validateBinary(filepath);

  const preferSystem = process.env['ARAEL_USE_SYSTEM_STRINGS'] === '1';
  const grepPattern = process.env['ARAEL_STRINGS_GREP'];

  let strings: StringInfo[];

  if (preferSystem) {
    logger.info('Using system strings tool', { filepath });
    strings = await extractStringsWithSystemTool(preflight.absolutePath, {
      minLength, encoding, pattern: grepPattern
    });
  } else {
    try {
      const result = await getCachedOrAnalyze(filepath);
      strings = result?.strings ?? [];
    } catch (error) {
      logger.warn('Ghidra analysis failed, falling back to system strings', {
        error: error instanceof Error ? error.message : String(error)
      });
      strings = await extractStringsWithSystemTool(preflight.absolutePath, {
        minLength, encoding, pattern: grepPattern
      });
    }
  }

  const regex = grepPattern ? new RegExp(grepPattern) : null;

  return strings.filter((s) =>
    s.length >= minLength &&
    (encoding === 'all' || s.encoding === encoding) &&
    (!regex || regex.test(s.value))
  );
}
