import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import {
  AnalysisResult,
  AnalysisMetadata,
  BinaryInfo,
  FunctionInfo,
  StringInfo,
  ImportInfo
} from './schema';
import { generateFileHashes } from '../cache/keys';
import { validateBinary } from '../utils/preflight';
import { detectPacking } from '../utils/packing';
import { analyzeSections } from '../utils/sections';
import { categorizeImports } from '../utils/import-analysis';

/**
 * Builder class for constructing AnalysisResult objects.
 */
export class AnalysisBuilder {
  private result: Partial<AnalysisResult>;
  private startTime: number;

  constructor() {
    this.result = {
      version: '1.0.0',
      functions: [],
      strings: [],
      imports: []
    };
    this.startTime = Date.now();
  }

  /**
   * Set binary information from file path.
   */
  async setBinaryFromPath(filepath: string): Promise<this> {
    const preflight = await validateBinary(filepath);
    const hashes = generateFileHashes(filepath);
    const stats = fs.statSync(preflight.absolutePath);

    this.result.binary = {
      filename: path.basename(filepath),
      filepath: preflight.absolutePath,
      size: stats.size,
      hashes,
      format: preflight.format,
      architecture: preflight.architecture ?? 'unknown',
      machine: preflight.machine,
      bits: preflight.bits,
      endianness: preflight.endianness ?? 'little',
      entryPoint: preflight.entryPoint ?? '0x0', // Will be set by Ghidra if available
      imageBase: preflight.imageBase ?? '0x0' // Will be set by Ghidra if available
    };

    // Automatically detect packing
    try {
      const packingInfo = await detectPacking(
        preflight.absolutePath,
        path.basename(filepath)
      );
      this.result.binary.packing = packingInfo;
    } catch (e) {
      // Packing detection is non-critical, continue without it
    }

    // Automatically analyze sections
    try {
      const sectionAnalysis = await analyzeSections(preflight.absolutePath);
      this.result.sections = sectionAnalysis.sections;
    } catch (e) {
      // Section analysis is non-critical, continue without it
    }

    return this;
  }

  /**
   * Set binary information directly.
   */
  setBinary(binary: BinaryInfo): this {
    this.result.binary = binary;
    return this;
  }

  /**
   * Add functions from Ghidra analysis.
   */
  setFunctions(functions: FunctionInfo[]): this {
    this.result.functions = functions;
    return this;
  }

  /**
   * Add a single function.
   */
  addFunction(func: FunctionInfo): this {
    this.result.functions?.push(func);
    return this;
  }

  /**
   * Set strings from Ghidra analysis.
   */
  setStrings(strings: StringInfo[]): this {
    this.result.strings = strings;
    return this;
  }

  /**
   * Set imports from Ghidra analysis.
   */
  setImports(imports: ImportInfo[]): this {
    // Categorize imports automatically
    const categorization = categorizeImports(imports);

    // Merge categorization data back into imports
    this.result.imports = imports.map((imp) => {
      const categorized = categorization.categorizedImports.find(
        (c) => c.name === imp.name && c.library === imp.library
      );

      if (categorized) {
        return {
          ...imp,
          capabilities: categorized.capabilities,
          riskLevel: categorized.riskLevel,
          description: categorized.description
        };
      }

      return imp;
    });

    return this;
  }

  /**
   * Update entry point and image base from Ghidra.
   */
  setAddresses(entryPoint?: string, imageBase?: string): this {
    if (this.result.binary) {
      if (entryPoint) {
        this.result.binary.entryPoint = entryPoint;
      }
      if (imageBase) {
        this.result.binary.imageBase = imageBase;
      }
    }
    return this;
  }

  /**
   * Build the final AnalysisResult.
   */
  build(connectionMode: 'bridge' | 'headless', cached = false): AnalysisResult {
    const duration = Date.now() - this.startTime;

    // Get Arael version
    let araelVersion = '1.0.0';
    try {
      const packagePath = path.join(__dirname, '../../package.json');
      if (fs.existsSync(packagePath)) {
        const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf-8')) as { version?: string };
        araelVersion = pkg.version ?? '1.0.0';
      }
    } catch {
      // Use default
    }

    const metadata: AnalysisMetadata = {
      analysisId: uuidv4(),
      timestamp: new Date().toISOString(),
      araelVersion,
      ghidraVersion: process.env['GHIDRA_VERSION'] ?? 'unknown',
      analysisDurationMs: duration,
      connectionMode,
      cached
    };

    if (!this.result.binary) {
      throw new Error('Binary information is required');
    }

    return {
      $schema: 'https://arael.iseethereaper.com/schemas/analysis_output.schema.json',
      version: '1.0.0',
      metadata,
      binary: this.result.binary,
      entryPoint: this.result.binary.entryPoint,
      imageBase: this.result.binary.imageBase,
      sections: this.result.sections,
      functions: this.result.functions ?? [],
      strings: this.result.strings ?? [],
      imports: this.result.imports ?? []
    };
  }
}
