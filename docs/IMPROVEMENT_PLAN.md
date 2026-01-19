# Arael Improvement Plan

## Part 1: New Features to Add

### High Priority (Thesis Enhancements)

| Feature | Description | Complexity | Value |
|---------|-------------|------------|-------|
| `arael ask` | LLM-assisted analysis - ask questions about a binary | Medium | High |
| `arael vulnscan` | Detect common vulnerabilities (buffer overflows, format strings) | Medium | High |
| `arael diff` | Compare two binaries (function diff, strings diff) | Low | Medium |
| `arael benchmark` | Performance metrics for thesis evaluation | Low | High |

### Medium Priority (Nice to Have)

| Feature | Description | Complexity |
|---------|-------------|------------|
| `arael attack` | MITRE ATT&CK technique mapping from imports/behaviors | Medium |
| `arael rename` | AI-suggested function renaming | Medium |
| `arael sbom` | Software Bill of Materials (libraries, versions) | Low |
| `arael timeline` | Binary modification timeline from metadata | Low |
| VirusTotal integration | Hash lookup with VT API | Low |

### Low Priority (Future)

| Feature | Description |
|---------|-------------|
| IDA Pro backend | Alternative to Ghidra |
| Binary Ninja backend | Alternative to Ghidra |
| Web UI | Browser-based interface |
| VS Code extension | IDE integration |

---

## Part 2: Code Reduction Plan

### Summary

| Category | Current Lines | After Refactor | Reduction |
|----------|---------------|----------------|-----------|
| Handler duplication | ~350 lines | ~150 lines | -200 lines |
| packing.ts | 572 lines | ~200 lines | -370 lines |
| yara.ts | 1059 lines | ~650 lines | -400 lines |
| functions.ts | 83 lines | ~55 lines | -28 lines |
| strings.ts | 74 lines | ~50 lines | -24 lines |
| **Total** | - | - | **~1000 lines** |

---

### Phase 1: Quick Wins (1-2 hours)

#### 1.1 Extract `getCachedOrAnalyze()` utility

**Current pattern (repeated in 6 handlers):**
```typescript
// functions.ts, imports.ts, strings.ts, decompile.ts, exports.ts, xrefs.ts
const cache = getCache();
const cached = cache.get(filepath);
let data;
if (cached) {
  data = cached.functions; // varies per handler
} else {
  const result = await analyzeHandler({ filepath });
  data = result.functions;
}
```

**Proposed (new file: `src/utils/handler-utils.ts`):**
```typescript
import { getCache } from '../cache/store';
import { analyzeHandler } from '../mcp/handlers/analyze';
import type { AnalysisResult } from '../output/schema';

export async function getCachedOrAnalyze(filepath: string): Promise<AnalysisResult> {
  const cache = getCache();
  const cached = cache.get(filepath);
  if (cached) return cached;
  return analyzeHandler({ filepath });
}
```

**Impact:** -60 lines across 6 handlers

---

#### 1.2 Combine filter chains in `functions.ts`

**Current (lines 49-72):**
```typescript
if (filter.namePattern) {
  const regex = new RegExp(filter.namePattern);
  filtered = filtered.filter((f) => regex.test(f.name));
}
if (filter.minSize !== undefined) {
  filtered = filtered.filter((f) => f.size >= filter.minSize!);
}
if (filter.maxSize !== undefined) {
  filtered = filtered.filter((f) => f.size <= filter.maxSize!);
}
if (filter.excludeThunks) {
  filtered = filtered.filter((f) => !f.isThunk);
}
if (filter.excludeExternal) {
  filtered = filtered.filter((f) => !f.isExternal);
}
```

**Proposed:**
```typescript
const regex = filter.namePattern ? new RegExp(filter.namePattern) : null;
filtered = filtered.filter((f) =>
  (!regex || regex.test(f.name)) &&
  (filter.minSize === undefined || f.size >= filter.minSize) &&
  (filter.maxSize === undefined || f.size <= filter.maxSize) &&
  (!filter.excludeThunks || !f.isThunk) &&
  (!filter.excludeExternal || !f.isExternal)
);
```

**Impact:** -15 lines, single array pass (performance boost)

---

#### 1.3 Fix duplicate variable reads in `strings.ts`

**Current (lines 29 & 67):**
```typescript
// Line 29
const grepPattern = process.env['ARAEL_STRINGS_GREP'];
// ... code ...
// Line 67
const grepPattern = process.env['ARAEL_STRINGS_GREP']; // duplicate!
```

**Fix:** Move to top of function, read once.

**Impact:** -3 lines, cleaner code

---

### Phase 2: Data-Driven Packer Detection (2-3 hours)

#### 2.1 Refactor `packing.ts`

**Current (lines 143-340) - 10 nearly identical functions:**
```typescript
function checkUPX(buffer: Buffer): PackerSignature | null {
  if (buffer.includes(Buffer.from('UPX!')) ||
      buffer.includes(Buffer.from('UPX0'))) {
    return { name: 'UPX', confidence: 0.95, canUnpack: true, indicators: [...] };
  }
  return null;
}

function checkASPack(buffer: Buffer): PackerSignature | null {
  if (buffer.includes(Buffer.from('.aspack'))) {
    return { name: 'ASPack', confidence: 0.9, canUnpack: false, indicators: [...] };
  }
  return null;
}
// ... 8 more similar functions
```

**Proposed - Data-driven approach:**
```typescript
interface PackerConfig {
  name: string;
  signatures: string[];
  confidence: number;
  canUnpack: boolean;
  sectionNames?: string[];
}

const PACKER_CONFIGS: PackerConfig[] = [
  { name: 'UPX', signatures: ['UPX!', 'UPX0', 'UPX1'], confidence: 0.95, canUnpack: true },
  { name: 'ASPack', signatures: ['.aspack', 'ASPack'], confidence: 0.9, canUnpack: false },
  { name: 'PyInstaller', signatures: ['MEI\x00', 'PYZ\x00'], confidence: 0.95, canUnpack: true },
  { name: 'Themida', signatures: ['.themida', '.winlice'], confidence: 0.85, canUnpack: false },
  { name: 'VMProtect', signatures: ['.vmp0', '.vmp1', 'VMProtect'], confidence: 0.85, canUnpack: false },
  { name: 'MPRESS', signatures: ['.MPRESS1', '.MPRESS2'], confidence: 0.9, canUnpack: false },
  { name: 'Enigma', signatures: ['Enigma Protector'], confidence: 0.85, canUnpack: false },
  { name: 'PECompact', signatures: ['PEC2', '.pec'], confidence: 0.85, canUnpack: false },
  { name: 'NSPack', signatures: ['.nsp0', '.nsp1'], confidence: 0.85, canUnpack: false },
  { name: '.NET Reactor', signatures: ['__'], confidence: 0.7, canUnpack: false, sectionNames: ['.reacto'] },
];

function detectPackers(buffer: Buffer, sectionNames: string[] = []): PackerSignature[] {
  const detected: PackerSignature[] = [];

  for (const config of PACKER_CONFIGS) {
    const hasSignature = config.signatures.some(sig => buffer.includes(Buffer.from(sig)));
    const hasSection = config.sectionNames?.some(name => sectionNames.includes(name));

    if (hasSignature || hasSection) {
      detected.push({
        name: config.name,
        confidence: config.confidence,
        canUnpack: config.canUnpack,
        indicators: config.signatures.filter(sig => buffer.includes(Buffer.from(sig))),
      });
    }
  }

  return detected;
}
```

**Impact:** -200 lines, easier to add new packers (just add to config array)

---

### Phase 3: Split YARA Module (2-3 hours)

#### 3.1 Current structure (1059 lines in one file)

```
src/utils/yara.ts
├── Lines 1-34: Imports and types
├── Lines 35-585: 43 embedded YARA rule definitions (550 lines!)
├── Lines 586-800: ReversingLabs integration
├── Lines 801-950: Scanning functions
└── Lines 951-1059: CLI helpers and exports
```

#### 3.2 Proposed split

**`src/utils/yara/index.ts` (main API ~100 lines):**
```typescript
export { scan, scanWithBuiltinRules, scanWithRLRules } from './scanner';
export { getAvailableRuleSets, getAvailableCategories, isRLRulesAvailable } from './config';
export type { YaraScanResult, RuleSet, ScanOptions } from './types';
```

**`src/utils/yara/rules.ts` (rule definitions ~550 lines):**
```typescript
export const BUILTIN_RULES: YaraRule[] = [
  { name: 'UPX_Packed', category: 'packer', pattern: '...' },
  // ... all 43 rules
];
```

**`src/utils/yara/scanner.ts` (scanning logic ~250 lines):**
```typescript
export async function scan(filepath: string, options: ScanOptions): Promise<YaraScanResult> { ... }
export async function scanWithBuiltinRules(filepath: string): Promise<YaraScanResult> { ... }
export async function scanWithRLRules(filepath: string): Promise<YaraScanResult> { ... }
```

**`src/utils/yara/config.ts` (configuration ~100 lines):**
```typescript
export function getAvailableRuleSets(): RuleSetInfo[] { ... }
export function findRLRulesDir(): string | null { ... }
export function isRLRulesAvailable(): boolean { ... }
```

**`src/utils/yara/types.ts` (types ~50 lines):**
```typescript
export interface YaraScanResult { ... }
export interface YaraMatch { ... }
export type RuleSet = 'builtin' | 'reversinglabs' | 'all' | string;
```

**Impact:** Better maintainability, easier to add rules, clearer separation of concerns

---

### Phase 4: Handler Factory Pattern (3-4 hours)

#### 4.1 Current repetition

All handlers follow this pattern:
```typescript
export async function xxxHandler(args: Args): Promise<Result> {
  const { filepath, ...options } = args;
  await validateBinary(filepath);
  const result = await getCachedOrAnalyze(filepath);
  let data = result.xxx;
  // apply filters
  return data;
}
```

#### 4.2 Proposed factory

**`src/mcp/handlers/factory.ts`:**
```typescript
type DataExtractor<T> = (result: AnalysisResult) => T[];
type FilterFn<T> = (items: T[], options: Record<string, unknown>) => T[];

export function createHandler<T, O extends { filepath: string }>(
  extractor: DataExtractor<T>,
  filter?: FilterFn<T>
): (args: O) => Promise<T[]> {
  return async (args: O) => {
    const { filepath, ...options } = args;
    await validateBinary(filepath);
    const result = await getCachedOrAnalyze(filepath);
    let data = extractor(result);
    if (filter) data = filter(data, options);
    return data;
  };
}
```

**Usage:**
```typescript
// Before: 83 lines in functions.ts
// After: 15 lines
export const functionsHandler = createHandler(
  (r) => r.functions,
  (funcs, opts) => funcs.filter(f =>
    (!opts.namePattern || new RegExp(opts.namePattern).test(f.name)) &&
    (!opts.excludeThunks || !f.isThunk)
  )
);
```

**Impact:** -300 lines across all handlers, consistent behavior

---

## Implementation Priority

### Week 1: Quick Wins
1. [ ] Create `getCachedOrAnalyze()` utility
2. [ ] Combine filter chains in functions.ts
3. [ ] Fix duplicate variables in strings.ts
4. [ ] Remove unused exports (isElfBinary, hexToBytes)

**Estimated reduction: 100 lines**

### Week 2: Packer Refactor
1. [ ] Implement data-driven packer detection
2. [ ] Update tests for new packer API
3. [ ] Add 2-3 new packer signatures to validate approach

**Estimated reduction: 200 lines**

### Week 3: YARA Split
1. [ ] Create yara/ subdirectory structure
2. [ ] Split rules into separate file
3. [ ] Split scanner and config
4. [ ] Update imports across codebase

**Estimated reduction: 400 lines (via better organization)**

### Week 4: Handler Factory (Optional)
1. [ ] Create handler factory
2. [ ] Migrate simple handlers (imports, exports, strings)
3. [ ] Migrate complex handlers (functions, decompile)

**Estimated reduction: 200 lines**

---

## Metrics After Refactoring

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Total src/ lines | ~8,000 | ~7,000 | -12.5% |
| Largest file | yara.ts (1059) | ~400 | -62% |
| Handler avg size | 60 lines | 25 lines | -58% |
| Duplicate patterns | 6 instances | 0 | -100% |
| Unused exports | 2 | 0 | -100% |

---

## New Features Implementation Order

If adding new features alongside refactoring:

1. **`arael benchmark`** - Simple to add, needed for thesis
2. **`arael diff`** - Low complexity, reuses existing analysis
3. **`arael vulnscan`** - Pattern matching on decompiled code
4. **`arael ask`** - LLM integration, highest value

These features can be added in parallel with refactoring since they're new files.
