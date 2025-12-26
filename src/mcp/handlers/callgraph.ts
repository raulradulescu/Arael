import { getConnection } from '../../ghidra/connection';
import { validateBinary } from '../../utils/preflight';
import { logger } from '../../utils/logger';

export interface CallgraphArgs {
  filepath: string;
  format?: 'json' | 'dot' | 'mermaid';
  rootFunction?: string;
  maxDepth?: number;
  includeExternal?: boolean;
  excludeExternal?: boolean;
  includeThunks?: boolean;
}

export interface CallgraphEdge {
  from: string;
  to: string;
  type: 'call' | 'jump' | 'conditional';
}

export interface CallgraphNode {
  id?: string;
  name: string;
  address: string;
  size?: number;
  isExternal?: boolean;
  isThunk?: boolean;
}

export interface CallgraphResult {
  format: 'json' | 'dot' | 'mermaid';
  nodes: CallgraphNode[];
  edges: CallgraphEdge[];
  output?: string;
  graphData?: string;
  error?: string;
}

export async function callgraphHandler(args: CallgraphArgs): Promise<CallgraphResult> {
  const {
    filepath,
    format = 'json',
    rootFunction,
    maxDepth = 5,
    includeExternal,
    excludeExternal,
    includeThunks = false
  } = args;

  const includeExternalResolved =
    includeExternal ?? (excludeExternal !== undefined ? !excludeExternal : false);
  const excludeExternalResolved = !includeExternalResolved;

  // Validate binary
  await validateBinary(filepath);

  logger.info('Generating call graph', {
    filepath,
    format,
    rootFunction,
    maxDepth,
    includeExternal: includeExternalResolved,
    includeThunks
  });

  const connection = getConnection();

  try {
    const result = await connection.getCallgraph(filepath, {
      format,
      rootFunction,
      maxDepth,
      excludeExternal: excludeExternalResolved,
      includeThunks
    });

    if (result === null) {
      return {
        format,
        nodes: [],
        edges: [],
        error: 'Failed to generate call graph'
      };
    }

    const nodes = (result.nodes || []).map((node: CallgraphNode) => ({
      ...node,
      id: node.id ?? node.address ?? node.name
    }));

    return {
      format,
      nodes,
      edges: result.edges || [],
      output: result.graphData,
      graphData: result.graphData,
      error: result.error
    };
  } catch (error) {
    logger.error('Failed to generate call graph', { error: String(error) });
    return {
      format,
      nodes: [],
      edges: [],
      error: String(error)
    };
  }
}
