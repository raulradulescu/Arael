import { getConnection } from '../../ghidra/connection';
import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { logger } from '../../utils/logger';

export interface DecompileArgs {
  filepath: string;
  function: string;
}

export interface DecompileResult {
  function: string;
  address?: string;
  signature?: string;
  pseudocode: string | null;
  error?: string;
}

export async function decompileHandler(args: DecompileArgs): Promise<DecompileResult> {
  const { filepath, function: funcTarget } = args;

  // Validate binary
  await validateBinary(filepath);

  // Try to get from cache first
  const cache = getCache();
  const cached = cache.get(filepath);

  if (cached) {
    // Find function in cached result
    const func = cached.functions.find(
      (f) => f.name === funcTarget || f.address === funcTarget
    );

    if (func) {
      logger.info('Returning cached decompilation', { filepath, function: funcTarget });
      return {
        function: func.name,
        address: func.address,
        signature: func.signature,
        pseudocode: func.pseudocode
      };
    }
  }

  // Decompile via Ghidra
  logger.info('Decompiling function', { filepath, function: funcTarget });
  const connection = getConnection();
  const pseudocode = await connection.decompile(filepath, funcTarget);

  if (pseudocode === null) {
    return {
      function: funcTarget,
      pseudocode: null,
      error: `Function not found: ${funcTarget}`
    };
  }

  return {
    function: funcTarget,
    pseudocode
  };
}
