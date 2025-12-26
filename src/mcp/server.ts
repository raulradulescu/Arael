#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';
import { logger } from '../utils/logger';
import { loadEnvFromFile } from '../utils/env';
import { getConnection } from '../ghidra/connection';
import { analyzeHandler } from './handlers/analyze';
import { decompileHandler } from './handlers/decompile';
import { disassembleHandler } from './handlers/disassemble';
import { xrefsHandler } from './handlers/xrefs';
import { functionsHandler } from './handlers/functions';
import { stringsHandler } from './handlers/strings';
import { importsHandler } from './handlers/imports';
import { exportsHandler } from './handlers/exports';
import { callgraphHandler } from './handlers/callgraph';
import { hexdumpHandler } from './handlers/hexdump';

loadEnvFromFile();

// Tool definitions
const TOOLS: Tool[] = [
  {
    name: 'arael_analyze',
    description: 'Perform full analysis of an ELF x86_64 binary using Ghidra',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Absolute path to the binary file'
        },
        force: {
          type: 'boolean',
          description: 'Bypass cache and re-analyze',
          default: false
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_decompile',
    description: 'Decompile a specific function to C pseudocode',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        function: {
          type: 'string',
          description: 'Function name or address (0x...)'
        }
      },
      required: ['filepath', 'function']
    }
  },
  {
    name: 'arael_disassemble',
    description: 'Get assembly instructions for a function or address range',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        function: {
          type: 'string',
          description: 'Function name or address (0x...)'
        },
        startAddress: {
          type: 'string',
          description: 'Start address for range disassembly (0x...)'
        },
        length: {
          type: 'number',
          description: 'Number of bytes to disassemble (for range mode)'
        },
        includeBytes: {
          type: 'boolean',
          description: 'Include raw instruction bytes',
          default: true
        },
        includeReferences: {
          type: 'boolean',
          description: 'Include cross-references',
          default: true
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_xrefs',
    description: 'Find cross-references to/from an address',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        address: {
          type: 'string',
          description: 'Address to analyze (0x...)'
        },
        direction: {
          type: 'string',
          enum: ['to', 'from', 'both'],
          description: 'Direction of references (to=callers, from=callees)',
          default: 'both'
        },
        maxResults: {
          type: 'number',
          description: 'Maximum number of results',
          default: 100
        }
      },
      required: ['filepath', 'address']
    }
  },
  {
    name: 'arael_functions',
    description: 'List all functions in an analyzed binary',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        filter: {
          type: 'object',
          properties: {
            namePattern: {
              type: 'string',
              description: 'Regex to filter by name'
            },
            minSize: { type: 'number' },
            maxSize: { type: 'number' },
            excludeThunks: { type: 'boolean', default: false },
            excludeExternal: { type: 'boolean', default: false }
          }
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_strings',
    description: 'Extract strings from binary with their cross-references',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        minLength: {
          type: 'number',
          description: 'Minimum string length',
          default: 4
        },
        encoding: {
          type: 'string',
          enum: ['ascii', 'utf8', 'utf16le', 'all'],
          default: 'all'
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_imports',
    description: 'List imported functions and their libraries',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_exports',
    description: 'List exported symbols (functions and data)',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        filter: {
          type: 'object',
          properties: {
            namePattern: {
              type: 'string',
              description: 'Regex pattern to filter export names'
            },
            type: {
              type: 'string',
              enum: ['function', 'data', 'all'],
              description: 'Type of exports to retrieve',
              default: 'all'
            }
          }
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_callgraph',
    description: 'Generate call graph visualization in JSON, DOT, or Mermaid format',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        format: {
          type: 'string',
          enum: ['json', 'dot', 'mermaid'],
          description: 'Output format',
          default: 'json'
        },
        rootFunction: {
          type: 'string',
          description: 'Root function name or address for BFS traversal (omit for full graph)'
        },
        maxDepth: {
          type: 'number',
          description: 'Maximum depth for BFS traversal',
          default: 5
        },
        includeExternal: {
          type: 'boolean',
          description: 'Include external functions',
          default: false
        },
        includeThunks: {
          type: 'boolean',
          description: 'Include thunk functions',
          default: false
        }
      },
      required: ['filepath']
    }
  },
  {
    name: 'arael_hexdump',
    description: 'Get formatted hexdump for address range',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Path to the binary file'
        },
        start: {
          type: 'string',
          description: 'Start address (0x...)'
        },
        length: {
          type: 'number',
          description: 'Number of bytes',
          default: 256
        },
        width: {
          type: 'number',
          enum: [8, 16, 32],
          default: 16
        }
      },
      required: ['filepath', 'start']
    }
  }
];

async function main(): Promise<void> {
  logger.info('Starting Arael MCP server...');

  // Initialize Ghidra connection
  const ghidraPath = process.env['GHIDRA_PATH'];
  if (!ghidraPath) {
    logger.warn('GHIDRA_PATH not set. Headless mode may not work.');
  }

  const connection = getConnection({
    ghidraPath: ghidraPath ?? '',
    bridgeHost: process.env['GHIDRA_BRIDGE_HOST'] ?? '127.0.0.1',
    bridgePort: parseInt(process.env['GHIDRA_BRIDGE_PORT'] ?? '4768', 10)
  });

  // Try to connect
  try {
    const mode = await connection.connect();
    logger.info(`Connected to Ghidra via ${mode}`);
  } catch (e) {
    logger.warn('Could not establish Ghidra connection at startup. Will retry on first request.');
  }

  // Create MCP server
  const server = new Server(
    {
      name: 'arael',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Handle list tools request
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    logger.info(`Tool call: ${name}`, { args });

    try {
      let result: unknown;

      switch (name) {
        case 'arael_analyze':
          result = await analyzeHandler(args as { filepath: string; force?: boolean });
          break;
        case 'arael_decompile':
          result = await decompileHandler(args as { filepath: string; function: string });
          break;
        case 'arael_disassemble':
          result = await disassembleHandler(args as {
            filepath: string;
            function?: string;
            startAddress?: string;
            length?: number;
            includeBytes?: boolean;
            includeReferences?: boolean;
          });
          break;
        case 'arael_xrefs':
          result = await xrefsHandler(args as {
            filepath: string;
            address: string;
            direction?: 'to' | 'from' | 'both';
            maxResults?: number;
          });
          break;
        case 'arael_functions':
          result = await functionsHandler(args as { filepath: string; filter?: Record<string, unknown> });
          break;
        case 'arael_strings': {
          const stringsArgs = args as { filepath: string; minLength?: number; encoding?: string };
          result = await stringsHandler({
            filepath: stringsArgs.filepath,
            minLength: stringsArgs.minLength,
            encoding: stringsArgs.encoding as 'ascii' | 'utf8' | 'utf16le' | 'all' | undefined
          });
          break;
        }
        case 'arael_imports':
          result = await importsHandler(args as { filepath: string });
          break;
        case 'arael_exports':
          result = await exportsHandler(args as { filepath: string; filter?: Record<string, unknown> });
          break;
        case 'arael_callgraph': {
          const callgraphArgs = args as {
            filepath: string;
            format?: 'json' | 'dot' | 'mermaid';
            rootFunction?: string;
            maxDepth?: number;
            includeExternal?: boolean;
            excludeExternal?: boolean;
            includeThunks?: boolean;
          };
          result = await callgraphHandler(callgraphArgs);
          break;
        }
        case 'arael_hexdump': {
          const hexdumpArgs = args as { filepath: string; start: string; length?: number; width?: number };
          result = await hexdumpHandler({
            filepath: hexdumpArgs.filepath,
            start: hexdumpArgs.start,
            length: hexdumpArgs.length,
            width: hexdumpArgs.width as 8 | 16 | 32 | undefined
          });
          break;
        }
        default:
          throw new Error(`Unknown tool: ${name}`);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    } catch (error) {
      logger.error(`Tool ${name} failed`, { error: String(error) });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: error instanceof Error ? error.message : String(error),
              code: 'TOOL_ERROR'
            })
          }
        ],
        isError: true
      };
    }
  });

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info('Arael MCP server running');
}

main().catch((error) => {
  logger.error('Fatal error', { error: String(error) });
  process.exit(1);
});
