import { validateBinary } from '../../utils/preflight';
import { getCachedOrAnalyze } from '../../utils/handler-utils';
import { ImportInfo } from '../../output/schema';

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

  await validateBinary(filepath);

  const result = await getCachedOrAnalyze(filepath);
  const imports = result?.imports ?? [];

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
    ([library, functions]) => ({ library, functions })
  );

  return { imports, grouped };
}
