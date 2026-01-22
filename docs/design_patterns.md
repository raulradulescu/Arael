# Design Patterns in Arael

This document describes the software design patterns employed in the Arael codebase.

---

## Summary Table

| Pattern | Location | Purpose |
|---------|----------|---------|
| **Singleton** | `connection.ts`, `store.ts`, `logger.ts` | Single instance of critical components |
| **Builder** | `output/builder.ts` | Fluent API for constructing AnalysisResult |
| **Strategy** | `ghidra/connection.ts` | Switch between bridge/headless modes |
| **Adapter** | `ghidra/connection.ts` | Unify different analysis result formats |
| **Facade** | `ghidra/connection.ts` | Simple interface to complex Ghidra operations |
| **Chain of Responsibility** | `mcp/handlers/*` | Sequential request processing pipeline |
| **Factory** | `output/builder.ts`, `connection.ts` | Complex object creation |
| **Command** | `mcp/server.ts` | Encapsulate tool requests as commands |
| **Observer** | `ghidra/bridge.ts` | EventEmitter base (extensible) |
| **Template Method** | `ghidra/headless.ts` | Subprocess spawning pattern |

---

## 1. Singleton Pattern

**Locations:**
- `src/ghidra/connection.ts:456-466` - `getConnection()` function
- `src/cache/store.ts:173-181` - `getCache()` function
- `src/utils/logger.ts:71` - `logger` exported singleton instance

**Description:**
The codebase uses the Singleton pattern to ensure only one instance of critical components exists throughout the application lifecycle.

```typescript
// Connection singleton
let connectionInstance: GhidraConnection | null = null;
export function getConnection(config?: ConnectionConfig): GhidraConnection {
  if (!connectionInstance && config) {
    connectionInstance = new GhidraConnection(config);
  }
  if (!connectionInstance) {
    throw new Error('Connection not initialized...');
  }
  return connectionInstance;
}

// Cache singleton
let cacheInstance: AnalysisCache | null = null;
export function getCache(): AnalysisCache {
  if (!cacheInstance) {
    cacheInstance = new AnalysisCache();
  }
  return cacheInstance;
}

// Logger singleton
export const logger = new Logger();
```

**Benefits:** Prevents multiple connections to Ghidra and multiple cache instances, ensuring consistency across the application.

---

## 2. Builder Pattern

**Location:** `src/output/builder.ts:21-199`

**Description:**
The `AnalysisBuilder` class implements the Builder pattern for constructing complex `AnalysisResult` objects through a fluent interface.

```typescript
export class AnalysisBuilder {
  private result: Partial<AnalysisResult>;

  setBinary(binary: BinaryInfo): this { ... }
  setFunctions(functions: FunctionInfo[]): this { ... }
  setStrings(strings: StringInfo[]): this { ... }
  setImports(imports: ImportInfo[]): this { ... }
  setAddresses(entryPoint?: string, imageBase?: string): this { ... }
  build(connectionMode: 'bridge' | 'headless', cached = false): AnalysisResult { ... }
}
```

**Usage in** `src/ghidra/connection.ts`:
```typescript
const builder = new AnalysisBuilder();
await builder.setBinaryFromPath(binaryPath);
builder.setAddresses(entryPoint, imageBase);
builder.setFunctions(functions);
builder.setStrings(strings);
builder.setImports(imports);
return builder.build('bridge');
```

**Benefits:** Provides a clean, readable, chainable API for constructing complex analysis results with proper initialization order.

---

## 3. Strategy Pattern

**Locations:**
- `src/ghidra/connection.ts:48-78` - Connection mode selection
- `src/ghidra/connection.ts:97-109` - Switching between bridge/headless strategies
- `src/ghidra/bridge.ts` vs `src/ghidra/headless.ts` - Alternative implementations

**Description:**
The GhidraConnection class encapsulates different connection strategies and switches between them at runtime.

```typescript
export type ConnectionMode = 'bridge' | 'headless' | 'none';

export class GhidraConnection {
  private bridge: GhidraBridge;
  private headless: GhidraHeadless;
  private mode: ConnectionMode = 'none';

  async connect(): Promise<ConnectionMode> {
    if (this.config.preferBridge !== false) {
      const bridgeAvailable = await this.bridge.isAvailable();
      if (bridgeAvailable) {
        this.mode = 'bridge';
        return this.mode;
      }
    }
    if (this.headless.isAvailable()) {
      this.mode = 'headless';
      return this.mode;
    }
  }

  async analyze(binaryPath: string): Promise<AnalysisResult> {
    if (this.mode === 'bridge') {
      return this.analyzeViaBridge(binaryPath);
    } else if (this.mode === 'headless') {
      return this.analyzeViaHeadless(binaryPath);
    }
  }
}
```

**Benefits:** Allows seamless switching between different Ghidra connection mechanisms (bridge vs headless) without changing client code.

---

## 4. Adapter Pattern

**Locations:**
- `src/ghidra/connection.ts:111-196` (analyzeViaBridge)
- `src/ghidra/connection.ts:198-268` (analyzeViaHeadless)
- `src/mcp/handlers/analyze.ts` - Handler adapters

**Description:**
The codebase adapts different analysis result formats from bridge and headless modes into a unified `AnalysisResult` format.

```typescript
// Bridge mode returns raw Ghidra objects
private async analyzeViaBridge(binaryPath: string): Promise<AnalysisResult> {
  const ghidraFunctions = await this.bridge.getFunctions();
  const functions: FunctionInfo[] = ghidraFunctions.map((gf) => ({
    name: gf.name,
    address: gf.address,
    size: gf.size,
    // ... transform to standard format
  }));
  builder.setFunctions(functions);
}

// Headless mode returns JSON that needs transformation
private async analyzeViaHeadless(binaryPath: string): Promise<AnalysisResult> {
  const headlessData = result.result as any;
  const strings: StringInfo[] = headlessData.strings.map((s: any) => ({
    address: s.address,
    value: s.value,
    // ... adapt to standard format
  }));
}
```

**Benefits:** Provides a uniform interface for consuming analysis results regardless of the source.

---

## 5. Facade Pattern

**Location:** `src/ghidra/connection.ts` (entire class)

**Description:**
The `GhidraConnection` class acts as a facade, providing a simple unified interface to complex Ghidra operations.

```typescript
// Single simple method hiding complexity
async analyze(binaryPath: string): Promise<AnalysisResult>

// Facade methods simplify access to underlying components
async decompile(binaryPath: string, functionNameOrAddress: string)
async disassemble(binaryPath: string, addressOrFunction: string, length?, ...)
async getXrefs(binaryPath: string, address: string, direction?, maxResults?)
async getExports(binaryPath: string, filter?)
async getCallgraph(binaryPath: string, options)
```

**Benefits:** Simplifies client interaction with complex Ghidra bridge and headless systems.

---

## 6. Chain of Responsibility Pattern

**Location:** `src/mcp/handlers/` - Handler chain

**Description:**
The MCP handlers implement a processing chain where requests flow through validation, caching, and execution.

```typescript
// Handler processing chain (in each handler)
export async function analyzeHandler(args: AnalyzeArgs): Promise<AnalysisResult> {
  // 1. Validate binary
  await validateBinary(filepath);

  // 2. Check cache
  const cache = getCache();
  if (!force) {
    const cached = cache.get(filepath);
    if (cached) return cached;
  }

  // 3. Perform analysis
  const connection = getConnection();
  const result = await connection.analyze(filepath);

  // 4. Cache result
  cache.set(filepath, result);

  return result;
}
```

**Benefits:** Creates a clear separation of concerns where each handler follows the same pattern: validate -> cache check -> process -> cache result.

---

## 7. Factory Pattern

**Locations:**
- `src/ghidra/connection.ts:35-43` - Constructor creates both bridge and headless instances
- `src/output/builder.ts:38-77` - `setBinaryFromPath()` factory method

**Description:**
Factory methods are used to create complex objects with proper initialization.

```typescript
// AnalysisBuilder factory method
async setBinaryFromPath(filepath: string): Promise<this> {
  const preflight = await validateBinary(filepath);
  const hashes = generateFileHashes(filepath);

  this.result.binary = {
    filename: path.basename(filepath),
    filepath: preflight.absolutePath,
    // ... creates and initializes BinaryInfo
  };

  // Automatically detects and creates packing info
  const packingInfo = await detectPacking(...);
  this.result.binary.packing = packingInfo;
}
```

**Benefits:** Encapsulates complex object creation logic and ensures proper initialization.

---

## 8. Command Pattern

**Location:** `src/mcp/server.ts:335-436` - Tool request handler

**Description:**
Each MCP tool call is encapsulated as a command that gets executed by the server.

```typescript
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'arael_analyze':
      result = await analyzeHandler(args);
      break;
    case 'arael_decompile':
      result = await decompileHandler(args);
      break;
    case 'arael_disassemble':
      result = await disassembleHandler(args);
      break;
    // ... more commands
  }
});
```

**Benefits:** Decouples command requests from their execution, making it easy to add new tools.

---

## 9. Observer Pattern

**Location:** `src/ghidra/bridge.ts:49` (extends EventEmitter)

**Description:**
The `GhidraBridge` class extends Node.js `EventEmitter` for potential event-driven communication.

```typescript
export class GhidraBridge extends EventEmitter {
  constructor(config: BridgeConfig = {}) {
    super();
    // ...
  }
}
```

While event emission isn't heavily used in the current codebase, the pattern is available for monitoring bridge operations.

**Benefits:** Provides extensibility for monitoring and reacting to bridge events.

---

## 10. Template Method Pattern

**Location:** `src/ghidra/headless.ts:156-282` and subprocess spawning methods

**Description:**
Multiple methods follow a common template for spawning Python subprocesses.

```typescript
// Pattern repeated in: disassemble(), getXrefs(), getExports(), getCallgraph()
async disassemble(...): Promise<any[] | null> {
  return new Promise((resolve, reject) => {
    const env = await this.buildEnv(binaryPath);
    const proc = spawn(this.pythonPath, args, { env });

    // Common pattern
    let stdout = '';
    proc.stdout.on('data', (data) => { stdout += data.toString(); });

    const timeout = setTimeout(() => { proc.kill(); }, this.timeout);

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Failed with code ${code}`));
      } else {
        resolve(JSON.parse(stdout));
      }
    });
  });
}
```

**Benefits:** Reduces code duplication and ensures consistent subprocess handling.

---

## Architectural Benefits

These patterns collectively provide:

1. **Maintainability** - Clear separation of concerns and consistent code structure
2. **Extensibility** - Easy to add new connection modes, handlers, or analysis features
3. **Testability** - Singleton patterns allow mocking, strategies enable isolated testing
4. **Flexibility** - Runtime switching between bridge/headless modes
5. **Consistency** - Unified output format regardless of analysis source
6. **Performance** - Singleton cache and connection prevent redundant operations

---

*Document generated: 2026-01-09*
*Arael v2.6.0*
