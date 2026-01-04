import { GhidraBridge } from './bridge';
import { GhidraHeadless } from './headless';
import { AnalysisResult, FunctionInfo, StringInfo, ImportInfo } from '../output/schema';
import { AnalysisBuilder } from '../output/builder';
import { logger } from '../utils/logger';

export type ConnectionMode = 'bridge' | 'headless' | 'none';

export interface ConnectionConfig {
  ghidraPath: string;
  bridgeHost?: string;
  bridgePort?: number;
  pythonPath?: string;
  preferBridge?: boolean;
}

/**
 * GhidraConnection manages the connection to Ghidra, automatically selecting
 * between bridge mode and headless mode based on availability.
 */
export class GhidraConnection {
  private bridge: GhidraBridge;
  private headless: GhidraHeadless;
  private mode: ConnectionMode = 'none';
  private config: ConnectionConfig;
  private _loadedBinaryPath: string | null = null;

  /**
   * Get the path of the currently loaded binary (bridge mode only).
   */
  get loadedBinaryPath(): string | null {
    return this._loadedBinaryPath;
  }

  constructor(config: ConnectionConfig) {
    this.config = config;
    this.bridge = new GhidraBridge({
      host: config.bridgeHost,
      port: config.bridgePort,
      pythonPath: config.pythonPath
    });
    this.headless = new GhidraHeadless({ ghidraPath: config.ghidraPath });
  }

  /**
   * Attempt to establish a connection, preferring bridge mode.
   */
  async connect(): Promise<ConnectionMode> {
    // Try bridge first if preferred (default)
    if (this.config.preferBridge !== false) {
      logger.info('Attempting to connect via ghidra-bridge...');
      const bridgeAvailable = await this.bridge.isAvailable();

      if (bridgeAvailable) {
        this.mode = 'bridge';
        logger.info('Connected via ghidra-bridge');
        return this.mode;
      }

      logger.warn('ghidra-bridge not available, checking headless mode...');
    }

    // Fall back to headless
    if (this.headless.isAvailable()) {
      this.mode = 'headless';
      logger.info('Using Ghidra headless mode');
      return this.mode;
    }

    logger.error('No Ghidra connection method available');
    this.mode = 'none';
    throw new Error(
      'No Ghidra connection available. Ensure either:\n' +
      '1. Ghidra is running with ghidra-bridge server, or\n' +
      '2. GHIDRA_PATH environment variable points to Ghidra installation.\n' +
      'See TROUBLESHOOTING.md for help.'
    );
  }

  /**
   * Get the current connection mode.
   */
  getMode(): ConnectionMode {
    return this.mode;
  }

  /**
   * Check if connected.
   */
  isConnected(): boolean {
    return this.mode !== 'none';
  }

  /**
   * Perform full analysis of a binary.
   */
  async analyze(binaryPath: string): Promise<AnalysisResult> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.mode === 'bridge') {
      return this.analyzeViaBridge(binaryPath);
    } else if (this.mode === 'headless') {
      return this.analyzeViaHeadless(binaryPath);
    } else {
      throw new Error('Not connected to Ghidra');
    }
  }

  private async analyzeViaBridge(binaryPath: string): Promise<AnalysisResult> {
    const builder = new AnalysisBuilder();
    await builder.setBinaryFromPath(binaryPath);

    // Resolve to absolute path for comparison
    const path = await import('path');
    const absolutePath = path.resolve(binaryPath);

    // Check if we need to load a different binary
    const currentProgram = await this.bridge.getCurrentProgramName();
    const expectedName = path.basename(absolutePath);

    if (!currentProgram || currentProgram !== expectedName) {
      logger.info('Loading binary into Ghidra', { path: absolutePath });

      // Close current program if different
      if (currentProgram) {
        await this.bridge.closeCurrentProgram();
      }

      // Load the new binary
      const loadResult = await this.bridge.loadBinary(absolutePath);
      if (!loadResult.success) {
        logger.warn('Failed to load binary via bridge, falling back to headless', {
          error: loadResult.error
        });
        // Fall back to headless for this analysis
        return this.analyzeViaHeadless(binaryPath);
      }

      this._loadedBinaryPath = absolutePath;
      logger.info('Binary loaded successfully', { programName: loadResult.programName });
    }

    // Get program info
    try {
      const programInfo = await this.bridge.getProgramInfo();
      builder.setAddresses(programInfo.entryPoint, programInfo.imageBase);
    } catch (e) {
      logger.warn('Failed to get program info', { error: String(e) });
    }

    // Get functions
    const ghidraFunctions = await this.bridge.getFunctions();
    const functions: FunctionInfo[] = [];

    for (const gf of ghidraFunctions) {
      const pseudocode = await this.bridge.decompile(gf.address).catch(() => null);

      functions.push({
        name: gf.name,
        address: gf.address,
        size: gf.size,
        signature: gf.signature ?? '',
        isThunk: gf.isThunk ?? false,
        isExternal: gf.isExternal ?? false,
        callers: [],
        callees: [],
        pseudocode
      });
    }
    builder.setFunctions(functions);

    // Get strings
    const ghidraStrings = await this.bridge.getStrings();
    const strings: StringInfo[] = ghidraStrings.map((s) => ({
      address: s.address,
      value: s.value,
      length: s.length,
      encoding: 'ascii' as const,
      xrefs: []
    }));
    builder.setStrings(strings);

    // Get imports
    const ghidraImports = await this.bridge.getImports();
    const imports: ImportInfo[] = ghidraImports.map((i) => ({
      name: i.name,
      library: i.library,
      address: i.address,
      type: 'function' as const
    }));
    builder.setImports(imports);

    return builder.build('bridge');
  }

  private async analyzeViaHeadless(binaryPath: string): Promise<AnalysisResult> {
    const result = await this.headless.analyze(binaryPath);

    if (!result.success || !result.result) {
      throw new Error(result.error ?? 'Headless analysis failed');
    }

    // Transform the raw headless output to AnalysisResult format
    const builder = new AnalysisBuilder();
    await builder.setBinaryFromPath(binaryPath);

    // The headless result is already in the right format, just merge it
    const headlessData = result.result as any;

    const normalizeAddr = (value: unknown): string | undefined => {
      if (typeof value !== 'string') {
        return undefined;
      }
      const trimmed = value.trim();
      if (!trimmed || trimmed.toLowerCase() === 'unknown') {
        return undefined;
      }
      return trimmed;
    };

    const entryPoint = normalizeAddr(headlessData.entryPoint);
    const imageBase = normalizeAddr(headlessData.imageBase);

    const isZeroAddress = (value?: string): boolean => {
      if (!value) return false;
      const normalized = value.toLowerCase();
      return normalized === '0x0' || normalized === '0x00000000' || normalized === '0x0000000000000000';
    };

    if ((entryPoint && !isZeroAddress(entryPoint)) || imageBase) {
      builder.setAddresses(
        entryPoint && !isZeroAddress(entryPoint) ? entryPoint : undefined,
        imageBase
      );
    }

    // Use functions from headless output (already have pseudocode)
    if (headlessData.functions) {
      builder.setFunctions(headlessData.functions);
    }

    // Use strings from headless output
    if (headlessData.strings) {
      const strings: StringInfo[] = headlessData.strings.map((s: any) => ({
        address: s.address,
        value: s.value,
        length: s.length,
        encoding: s.encoding || 'ascii',
        xrefs: []
      }));
      builder.setStrings(strings);
    }

    // Use imports from headless output
    if (headlessData.imports) {
      const imports: ImportInfo[] = headlessData.imports.map((i: any) => ({
        name: i.name,
        library: i.library || '',
        address: i.address || '',
        type: 'function' as const
      }));
      builder.setImports(imports);
    }

    return builder.build('headless');
  }

  /**
   * Decompile a specific function.
   */
  async decompile(binaryPath: string, functionNameOrAddress: string): Promise<string | null> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.mode === 'bridge') {
      return this.bridge.decompile(functionNameOrAddress);
    } else {
      // For headless, we need to run a full analysis and extract the function
      const result = await this.analyzeViaHeadless(binaryPath);
      const func = result.functions.find(
        (f) => f.name === functionNameOrAddress || f.address === functionNameOrAddress
      );
      return func?.pseudocode ?? null;
    }
  }

  /**
   * Disassemble a function or address range.
   */
  async disassemble(
    binaryPath: string,
    addressOrFunction: string,
    length?: number,
    includeBytes = true,
    includeReferences = true
  ): Promise<any[] | null> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.mode === 'bridge') {
      // Bridge mode not yet implemented for disassembly
      // Will need to be added to GhidraBridge
      logger.warn('Disassembly via bridge not yet implemented, using headless');
      return this.disassembleViaHeadless(
        binaryPath,
        addressOrFunction,
        length,
        includeBytes,
        includeReferences
      );
    } else {
      return this.disassembleViaHeadless(
        binaryPath,
        addressOrFunction,
        length,
        includeBytes,
        includeReferences
      );
    }
  }

  /**
   * Disassemble via headless mode (Python script).
   */
  private async disassembleViaHeadless(
    binaryPath: string,
    addressOrFunction: string,
    length?: number,
    includeBytes = true,
    includeReferences = true
  ): Promise<any[] | null> {
    return this.headless.disassemble(
      binaryPath,
      addressOrFunction,
      length,
      includeBytes,
      includeReferences
    );
  }

  /**
   * Get cross-references to/from an address.
   */
  async getXrefs(
    binaryPath: string,
    address: string,
    direction: 'to' | 'from' | 'both' = 'both',
    maxResults = 100
  ): Promise<any[] | null> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.mode === 'bridge') {
      logger.warn('Cross-references via bridge not yet implemented, using headless');
      return this.getXrefsViaHeadless(binaryPath, address, direction, maxResults);
    } else {
      return this.getXrefsViaHeadless(binaryPath, address, direction, maxResults);
    }
  }

  /**
   * Get cross-references via headless mode (Python script).
   */
  private async getXrefsViaHeadless(
    binaryPath: string,
    address: string,
    direction: 'to' | 'from' | 'both',
    maxResults: number
  ): Promise<any[] | null> {
    return this.headless.getXrefs(binaryPath, address, direction, maxResults);
  }

  /**
   * Get exported symbols from a binary.
   */
  async getExports(
    binaryPath: string,
    filter?: {
      namePattern?: string;
      type?: 'function' | 'data' | 'all';
    }
  ): Promise<any[] | null> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.mode === 'bridge') {
      logger.warn('Exports via bridge not yet implemented, using headless');
      return this.getExportsViaHeadless(binaryPath, filter);
    } else {
      return this.getExportsViaHeadless(binaryPath, filter);
    }
  }

  /**
   * Get exports via headless mode (Python script).
   */
  private async getExportsViaHeadless(
    binaryPath: string,
    filter?: {
      namePattern?: string;
      type?: 'function' | 'data' | 'all';
    }
  ): Promise<any[] | null> {
    return this.headless.getExports(binaryPath, filter);
  }

  /**
   * Generate a call graph for the binary.
   */
  async getCallgraph(
    binaryPath: string,
    options: {
      format: 'json' | 'dot' | 'mermaid';
      rootFunction?: string;
      maxDepth?: number;
      excludeExternal?: boolean;
      includeThunks?: boolean;
    }
  ): Promise<any | null> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.mode === 'bridge') {
      logger.warn('Call graph via bridge not yet implemented, using headless');
      return this.getCallgraphViaHeadless(binaryPath, options);
    } else {
      return this.getCallgraphViaHeadless(binaryPath, options);
    }
  }

  /**
   * Get call graph via headless mode (Python script).
   */
  private async getCallgraphViaHeadless(
    binaryPath: string,
    options: {
      format: 'json' | 'dot' | 'mermaid';
      rootFunction?: string;
      maxDepth?: number;
      excludeExternal?: boolean;
      includeThunks?: boolean;
    }
  ): Promise<any | null> {
    return this.headless.getCallgraph(binaryPath, options);
  }
}

// Singleton connection instance
let connectionInstance: GhidraConnection | null = null;

export function getConnection(config?: ConnectionConfig): GhidraConnection {
  if (!connectionInstance && config) {
    connectionInstance = new GhidraConnection(config);
  }
  if (!connectionInstance) {
    throw new Error('Connection not initialized. Call getConnection with config first.');
  }
  return connectionInstance;
}
