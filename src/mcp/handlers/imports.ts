import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { ImportInfo } from '../../output/schema';
import { analyzeHandler } from './analyze';
import { logger } from '../../utils/logger';

export interface ImportsArgs {
  filepath: string;
}

export interface GroupedImports {
  library: string;
  functions: Array<{
    name: string;
    address: string;
  }>;
}

export async function importsHandler(args: ImportsArgs): Promise<{
  imports: ImportInfo[];
  grouped: GroupedImports[];
}> {
  const { filepath } = args;

  // Validate binary
  await validateBinary(filepath);

  // Get or create analysis
  const cache = getCache();
  let imports: ImportInfo[];

  const cached = cache.get(filepath);
  if (cached) {
    imports = cached.imports;
  } else {
    logger.info('No cache found, running analysis', { filepath });
    const result = await analyzeHandler({ filepath });
    imports = result.imports;
  }

  // Group by library
  const byLibrary = new Map<string, Array<{ name: string; address: string }>>();

  for (const imp of imports) {
    const lib = imp.library;
    if (!byLibrary.has(lib)) {
      byLibrary.set(lib, []);
    }
    byLibrary.get(lib)!.push({
      name: imp.name,
      address: imp.address
    });
  }

  const grouped: GroupedImports[] = Array.from(byLibrary.entries()).map(
    ([library, functions]) => ({
      library,
      functions
    })
  );

  return {
    imports,
    grouped
  };
}
