import { createDataHandler } from '../../utils/handler-utils';
import { FunctionInfo } from '../../output/schema';

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

// Create handler using factory
const baseFunctionsHandler = createDataHandler<FunctionInfo, FunctionsArgs>(
  (result) => result.functions,
  (functions, args) => {
    const filter = args.filter;
    if (!filter) return functions;

    const regex = filter.namePattern ? new RegExp(filter.namePattern) : null;

    return functions.filter((f) =>
      (!regex || regex.test(f.name)) &&
      (filter.minSize === undefined || f.size >= filter.minSize) &&
      (filter.maxSize === undefined || f.size <= filter.maxSize) &&
      (!filter.excludeThunks || !f.isThunk) &&
      (!filter.excludeExternal || !f.isExternal)
    );
  }
);

export async function functionsHandler(args: FunctionsArgs): Promise<FunctionSummary[]> {
  const functions = await baseFunctionsHandler(args);

  return functions.map((f) => ({
    name: f.name,
    address: f.address,
    size: f.size,
    signature: f.signature,
    isThunk: f.isThunk,
    isExternal: f.isExternal
  }));
}
