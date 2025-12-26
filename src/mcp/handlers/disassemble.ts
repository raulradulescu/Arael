import { getConnection } from '../../ghidra/connection';
import { getCache } from '../../cache/store';
import { validateBinary } from '../../utils/preflight';
import { logger } from '../../utils/logger';

export interface DisassembleArgs {
  filepath: string;
  function?: string;
  startAddress?: string;
  length?: number;
  includeBytes?: boolean;
  includeReferences?: boolean;
}

export interface Instruction {
  address: string;
  mnemonic: string;
  operands: string;
  bytes?: string;
  references?: Array<{
    address: string;
    type: string;
  }>;
}

export interface DisassembleResult {
  function?: string;
  address?: string;
  instructions: Instruction[] | null;
  error?: string;
}

export async function disassembleHandler(args: DisassembleArgs): Promise<DisassembleResult> {
  const {
    filepath,
    function: funcTarget,
    startAddress,
    length,
    includeBytes = true,
    includeReferences = true
  } = args;

  // Validate binary
  await validateBinary(filepath);

  // Determine mode: function or address range
  if (!funcTarget && !startAddress) {
    return {
      instructions: null,
      error: 'Must provide either function name/address or startAddress'
    };
  }

  logger.info('Disassembling', { filepath, function: funcTarget, startAddress, length });

  const connection = getConnection();

  if (funcTarget) {
    // Disassemble by function name or address
    // Try cache first
    const cache = getCache();
    const cached = cache.get(filepath);

    let targetAddress = funcTarget;

    if (cached) {
      const func = cached.functions.find(
        (f) => f.name === funcTarget || f.address === funcTarget
      );

      if (func) {
        targetAddress = func.address;
        logger.info('Found function in cache', { name: func.name, address: func.address });
      }
    }

    // Call Ghidra to disassemble function
    const instructions = await connection.disassemble(
      filepath,
      targetAddress,
      undefined,
      includeBytes,
      includeReferences
    );

    if (instructions === null) {
      return {
        function: funcTarget,
        instructions: null,
        error: `Function not found: ${funcTarget}`
      };
    }

    return {
      function: funcTarget,
      address: targetAddress,
      instructions
    };
  } else if (startAddress) {
    // Disassemble address range
    const instructions = await connection.disassemble(
      filepath,
      startAddress,
      length,
      includeBytes,
      includeReferences
    );

    if (instructions === null) {
      return {
        instructions: null,
        error: `Failed to disassemble at address: ${startAddress}`
      };
    }

    return {
      address: startAddress,
      instructions
    };
  }

  return {
    instructions: null,
    error: 'Invalid arguments'
  };
}
