# Arael v2.5.0 - Proposed Features

## Bachelor's Thesis Enhancement Release

**Target:** Make Arael thesis-worthy with evaluation capabilities, LLM integration, and security analysis features.

**Thesis Value Focus:** Each feature is tagged with its academic contribution value.

---

## 🎓 Thesis-Critical Features (P0)

These features provide the **evaluation chapter** content and demonstrate **novel contribution**.

### 1. Benchmark Suite (`arael benchmark`)

**Thesis Value:** ⭐⭐⭐⭐⭐ (Essential for evaluation chapter)

```bash
# Benchmark a corpus of binaries
arael benchmark ./corpus/ --output benchmarks.json

# Generate LaTeX tables for thesis
arael benchmark ./corpus/ --format latex --output chapter5_tables.tex

# Compare with baseline (manual analysis times)
arael benchmark ./corpus/ --baseline manual_times.json
```

**Metrics Collected:**
| Metric | Description | Academic Value |
|--------|-------------|----------------|
| Analysis Time | Seconds to analyze binary | Efficiency comparison |
| Memory Usage | Peak RAM during analysis | Resource requirements |
| Function Count | Detected vs ground truth | Accuracy measurement |
| Cache Hit Rate | Percentage of cached results | Optimization validation |
| Decompilation Quality | Lines of pseudocode generated | Output completeness |

**Output Formats:**
- JSON (machine-readable for further analysis)
- LaTeX tables (direct thesis inclusion)
- CSV (spreadsheet analysis)
- Markdown (documentation)

**Implementation:**
- `src/cli/benchmark.ts` - CLI command
- `src/benchmark/runner.ts` - Benchmark execution engine
- `src/benchmark/metrics.ts` - Metric collection
- `src/benchmark/reporters/` - Output formatters (JSON, LaTeX, CSV, Markdown)

---

### 2. LLM Analysis Pipeline (`arael ask`)

**Thesis Value:** ⭐⭐⭐⭐⭐ (Demonstrates MCP/LLM integration - unique selling point)

```bash
# Ask questions about a binary
arael ask ./binary "What does the validate_password function check?"
arael ask ./binary "Is this binary packed? What packer?"
arael ask ./binary "Find potential vulnerabilities in main()"
arael ask ./binary "Summarize what this malware does"

# Use specific LLM backend
arael ask ./binary "Explain the encryption" --model claude-3-opus
arael ask ./binary "Explain the encryption" --model ollama/llama3
```

**How It Works:**
1. Analyzes binary (or uses cache)
2. Gathers relevant context based on question:
   - Function decompilation
   - Related strings
   - Import analysis
   - Cross-references
3. Constructs structured prompt with context
4. Sends to LLM (Claude API / Ollama / LM Studio)
5. Returns analysis with address citations

**Context Selection Algorithm:**
```typescript
interface QueryContext {
  question: string;
  relevantFunctions: DecompiledFunction[];
  relevantStrings: StringMatch[];
  relevantImports: Import[];
  xrefs: CrossReference[];
  maxTokens: number;
}

function selectContext(analysis: AnalysisResult, question: string): QueryContext {
  // Semantic matching to find relevant functions
  // Token budget management
  // Priority: direct matches > xrefs > related strings
}
```

**Supported Backends:**
| Backend | Configuration | Notes |
|---------|---------------|-------|
| Claude API | `ANTHROPIC_API_KEY` env var | Best quality, requires API key |
| Ollama | `--model ollama/modelname` | Local, free, good for privacy |
| LM Studio | `--model lmstudio/modelname` | Local with OpenAI-compatible API |
| OpenAI | `OPENAI_API_KEY` env var | Alternative cloud option |

**Implementation:**
- `src/cli/ask.ts` - CLI command
- `src/llm/pipeline.ts` - Query processing
- `src/llm/context.ts` - Context selection
- `src/llm/backends/` - Claude, Ollama, OpenAI adapters
- `src/llm/prompts.ts` - Prompt templates

---

### 3. Vulnerability Pattern Scanner (`arael vulnscan`)

**Thesis Value:** ⭐⭐⭐⭐ (Practical security application)

```bash
# Scan for vulnerability patterns
arael vulnscan ./binary

# Output specific format
arael vulnscan ./binary --format sarif  # For GitHub Security tab
arael vulnscan ./binary --format json
arael vulnscan ./binary --format markdown

# Filter by severity
arael vulnscan ./binary --min-severity high
```

**Detection Patterns:**

| Category | Pattern | Detection Method |
|----------|---------|------------------|
| **Buffer Overflow** | `strcpy`, `sprintf`, `gets` without bounds | Import + decompilation analysis |
| **Format String** | `printf(user_input)` | Decompilation pattern matching |
| **Integer Overflow** | Unchecked arithmetic before allocation | Control flow analysis |
| **Use-After-Free** | Free followed by use without nullification | Data flow analysis |
| **Hardcoded Secrets** | API keys, passwords in strings | String pattern + entropy |
| **Weak Crypto** | DES, MD5, RC4, hardcoded keys | Import + constant analysis |
| **Command Injection** | `system()`, `exec()` with user input | Taint analysis (basic) |
| **Path Traversal** | File operations with `../` patterns | String + import analysis |

**Output Schema:**
```typescript
interface VulnerabilityReport {
  binary: string;
  scanTime: string;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  category: string;
  location: {
    function: string;
    address: string;
    line?: number;
  };
  description: string;
  evidence: string;  // Code snippet
  cwe?: string;      // CWE-ID
  remediation?: string;
}
```

**Implementation:**
- `src/cli/vulnscan.ts` - CLI command
- `src/security/scanner.ts` - Main scanner orchestrator
- `src/security/patterns/` - Individual pattern detectors
- `src/security/reporters/` - Output formatters (JSON, SARIF, Markdown)

---

### 4. Binary Diff (`arael diff`)

**Thesis Value:** ⭐⭐⭐⭐ (Patch analysis, version comparison)

```bash
# Compare two versions
arael diff ./v1.exe ./v2.exe

# Output formats
arael diff ./v1.exe ./v2.exe --format html --output diff.html
arael diff ./v1.exe ./v2.exe --format json
arael diff ./v1.exe ./v2.exe --format markdown

# Focus on specific aspects
arael diff ./v1.exe ./v2.exe --functions-only
arael diff ./v1.exe ./v2.exe --security-focus  # Highlight security-relevant changes
```

**Diff Categories:**
| Category | Description | Security Relevance |
|----------|-------------|-------------------|
| Added Functions | New code introduced | New attack surface |
| Removed Functions | Code deleted | Removed functionality |
| Modified Functions | Changed implementation | Bug fixes or new bugs |
| Added Imports | New external calls | New capabilities |
| Removed Imports | Removed dependencies | Capability reduction |
| String Changes | Modified/added strings | Messages, keys, URLs |
| Section Changes | Memory layout changes | Protection changes |

**Output:**
```typescript
interface DiffResult {
  binary1: BinaryInfo;
  binary2: BinaryInfo;
  functions: {
    added: FunctionInfo[];
    removed: FunctionInfo[];
    modified: FunctionDiff[];
  };
  imports: {
    added: Import[];
    removed: Import[];
  };
  strings: {
    added: StringInfo[];
    removed: StringInfo[];
  };
  sections: {
    added: Section[];
    removed: Section[];
    modified: SectionDiff[];
  };
  securitySummary?: SecurityDiffSummary;
}
```

**Implementation:**
- `src/cli/diff.ts` - CLI command
- `src/diff/analyzer.ts` - Diff computation
- `src/diff/function-diff.ts` - Function-level comparison
- `src/diff/reporters/` - Output formatters

---

## 🔬 High-Value Features (P1)

### 5. Semantic Function Naming (`arael rename`)

**Thesis Value:** ⭐⭐⭐ (Improves analysis quality)

```bash
# Suggest names for unnamed functions
arael rename ./binary --suggest

# Apply suggestions to Ghidra project
arael rename ./binary --apply --ghidra-project ./project.gpr

# Export as Ghidra script
arael rename ./binary --export rename_script.py
```

**Naming Heuristics:**
| Signal | Example | Suggested Name |
|--------|---------|----------------|
| String usage | Uses "Invalid password" | `validate_password` |
| Import calls | Calls `socket`, `connect` | `network_init` |
| Return patterns | Returns 0/1 only | `check_*` or `is_*` |
| Argument count | Takes FILE* | `file_*` |
| Loop patterns | Iterates over array | `process_*` |

**Implementation:**
- `src/cli/rename.ts` - CLI command
- `src/naming/suggester.ts` - Name suggestion engine
- `src/naming/heuristics/` - Individual naming rules
- `src/naming/ghidra-export.ts` - Ghidra script generator

---

### 6. SBOM Generation (`arael sbom`)

**Thesis Value:** ⭐⭐⭐ (Supply chain security research)

```bash
# Generate Software Bill of Materials
arael sbom ./binary --format cyclonedx --output sbom.json
arael sbom ./binary --format spdx --output sbom.spdx
```

**Detection Methods:**
- Library signature matching (OpenSSL, zlib, etc.)
- String-based version detection
- Import pattern matching
- Debug symbol analysis (if available)

**Implementation:**
- `src/cli/sbom.ts` - CLI command
- `src/sbom/detector.ts` - Library detection
- `src/sbom/formats/` - CycloneDX, SPDX formatters

---

### 7. Enhanced Report Generation (`arael report`)

**Thesis Value:** ⭐⭐⭐ (Documentation, presentation)

```bash
# Generate thesis-ready report
arael report ./binary --format latex --output analysis.tex

# Executive summary for non-technical readers
arael report ./binary --format executive --output summary.pdf

# Full HTML report with interactive elements
arael report ./binary --format html --output report.html
```

**LaTeX Output Features:**
- Proper code listings with syntax highlighting
- Figure generation for call graphs
- Table formatting for function/string lists
- Citation-ready format
- Chapter/section structure matching thesis template

**Implementation:**
- `src/cli/report.ts` - CLI command
- `src/report/generators/` - LaTeX, HTML, PDF, Markdown
- `src/report/templates/` - Output templates

---

## 🛠️ Quality of Life (P2)

### 8. Interactive Shell (`arael shell`)

```bash
arael shell ./binary
> functions | grep crypto
> decompile encrypt_data
> xrefs 0x401234
> strings | grep password
> vulnscan --min-severity high
> ask "What encryption algorithm is used?"
> exit
```

**Features:**
- Tab completion for function names
- History persistence
- Pipeline support (`|`, `grep`, `head`, `tail`)
- Variable binding (`$lastresult`)

**Implementation:**
- `src/cli/shell.ts` - REPL implementation
- `src/shell/commands.ts` - Command registry
- `src/shell/completion.ts` - Tab completion
- `src/shell/pipeline.ts` - Command piping

---

### 9. Batch Analysis (`arael batch`)

```bash
# Analyze all executables in directory
arael batch ./samples/ --output results/

# With specific analysis options
arael batch ./samples/ --vulnscan --sbom --parallel 4

# Generate aggregate report
arael batch ./samples/ --aggregate --output corpus_report.json
```

**Implementation:**
- `src/cli/batch.ts` - CLI command
- `src/batch/runner.ts` - Parallel execution
- `src/batch/aggregator.ts` - Result aggregation

---

### 10. Watch Mode (`arael watch`)

```bash
# Re-analyze when binary changes
arael watch ./binary --on-change "arael vulnscan"

# Development workflow
arael watch ./project/build/output.exe --notify
```

**Implementation:**
- `src/cli/watch.ts` - CLI command
- `src/watch/monitor.ts` - File system watcher

---

## 🔒 Security Integrations (P2)

### 11. YARA Scanning (`arael yara`)

```bash
# Scan with built-in rules
arael yara ./binary

# Custom rules
arael yara ./binary --rules ./my_rules/

# Categories
arael yara ./binary --category packers
arael yara ./binary --category crypto
arael yara ./binary --category malware
```

**Built-in Rulesets:**
- Packers (UPX, Themida, VMProtect, etc.)
- Crypto (AES, RSA, suspicious constants)
- Capabilities (network, file, process, registry)
- Malware families (common indicators)

**Implementation:**
- `src/cli/yara.ts` - CLI command
- `src/yara/scanner.ts` - YARA integration
- `src/yara/rules/` - Built-in rulesets

---

### 12. MITRE ATT&CK Mapping (`arael attack`)

```bash
# Map behaviors to ATT&CK techniques
arael attack ./binary

# Output as ATT&CK Navigator layer
arael attack ./binary --format navigator --output layer.json
```

**Mapping Sources:**
- Import analysis → Technique mapping
- String patterns → Indicator matching
- Behavior patterns → Tactic identification

**Implementation:**
- `src/cli/attack.ts` - CLI command
- `src/attack/mapper.ts` - ATT&CK mapping
- `src/attack/database.ts` - Technique definitions

---

## 🏗️ Architecture Expansion (P2)

### 13. ARM64 Support

```bash
arael analyze ./arm64_binary
```

**Target Use Cases:**
- macOS Apple Silicon binaries
- Android native libraries
- iOS applications
- IoT/embedded devices

---

### 14. ARM32 Support

```bash
arael analyze ./arm32_binary
```

**Target Use Cases:**
- Android 32-bit libraries
- Raspberry Pi binaries
- Embedded systems

---

## 📊 Implementation Priority Matrix

| Feature | Thesis Value | Effort | Priority | Sprint |
|---------|--------------|--------|----------|--------|
| `arael benchmark` | ⭐⭐⭐⭐⭐ | Medium | P0 | 1 |
| `arael ask` | ⭐⭐⭐⭐⭐ | Medium | P0 | 1 |
| `arael vulnscan` | ⭐⭐⭐⭐ | High | P0 | 2 |
| `arael diff` | ⭐⭐⭐⭐ | Medium | P0 | 2 |
| `arael rename` | ⭐⭐⭐ | Medium | P1 | 3 |
| `arael sbom` | ⭐⭐⭐ | Low | P1 | 3 |
| `arael report` (LaTeX) | ⭐⭐⭐ | Low | P1 | 3 |
| `arael shell` | ⭐⭐ | Medium | P2 | 4 |
| `arael batch` | ⭐⭐ | Low | P2 | 4 |
| `arael yara` | ⭐⭐ | Medium | P2 | 4 |
| `arael attack` | ⭐⭐ | Medium | P2 | 5 |
| ARM64/ARM32 | ⭐⭐ | Low | P2 | 5 |

---

## 📝 Thesis Chapter Mapping

| Chapter | Arael Feature | Content |
|---------|---------------|---------|
| **1. Introduction** | - | Problem: manual RE is slow; LLMs need structured data |
| **2. Background** | - | RE tools survey, MCP protocol, LLM capabilities |
| **3. Design** | Architecture docs | System design, MCP integration, caching strategy |
| **4. Implementation** | Source code | Technical details, Ghidra integration, Python scripts |
| **5. Evaluation** | `arael benchmark` | Performance metrics, accuracy comparison, case studies |
| **6. Security Analysis** | `arael vulnscan`, `arael ask` | Vulnerability detection, LLM-assisted analysis |
| **7. Case Studies** | chekhov CTF, malware samples | Real-world application |
| **8. Conclusion** | Roadmap | Contributions, limitations, future work |

---

## 🧪 Test Plan for v2.5

### New Test Suites

| Feature | Test File | Type |
|---------|-----------|------|
| Benchmark | `tests/unit/benchmark.test.ts` | Unit |
| Benchmark E2E | `tests/integration/benchmark.test.ts` | Integration |
| LLM Pipeline | `tests/unit/llm-pipeline.test.ts` | Unit (mocked) |
| Vulnerability Scanner | `tests/unit/vulnscan.test.ts` | Unit |
| Vulnerability E2E | `tests/integration/vulnscan.test.ts` | Integration |
| Binary Diff | `tests/unit/diff.test.ts` | Unit |
| Binary Diff E2E | `tests/integration/diff.test.ts` | Integration |
| Function Naming | `tests/unit/rename.test.ts` | Unit |
| SBOM | `tests/unit/sbom.test.ts` | Unit |

### Test Fixtures Needed

| Fixture | Purpose |
|---------|---------|
| `vulnerable_sample.c` | Known vulnerabilities for vulnscan testing |
| `v1_sample.exe`, `v2_sample.exe` | Binary diff testing |
| `corpus/` directory | Benchmark testing (10-20 varied binaries) |

---

## 📅 Development Timeline

### Sprint 1 (Week 1-2): Benchmark + LLM
- [ ] `arael benchmark` implementation
- [ ] `arael ask` with Claude backend
- [ ] Ollama backend support
- [ ] Unit tests

### Sprint 2 (Week 3-4): Security Analysis
- [ ] `arael vulnscan` core patterns
- [ ] `arael diff` implementation
- [ ] SARIF output format
- [ ] Integration tests

### Sprint 3 (Week 5-6): Polish
- [ ] `arael rename` suggestions
- [ ] `arael report` LaTeX output
- [ ] `arael sbom` generation
- [ ] Documentation update

### Sprint 4 (Week 7-8): QoL + Security
- [ ] `arael shell` interactive mode
- [ ] `arael batch` processing
- [ ] `arael yara` scanning
- [ ] ARM architecture prep

---

## v2.4.0 Completed Features (Reference)

For reference, these features are already implemented in v2.4.0:

```
✅ arael_analyze (full binary analysis)
✅ arael_decompile (pseudocode extraction)
✅ arael_disassemble (assembly listing)
✅ arael_functions (function listing)
✅ arael_strings (string extraction)
✅ arael_imports (import analysis)
✅ arael_exports (export listing)
✅ arael_xrefs (cross-references)
✅ arael_callgraph (call graphs)
✅ arael_hexdump (raw bytes)
✅ Packing detection (UPX, PyInstaller, 10+ signatures)
✅ Section analysis (entropy, RWX)
✅ Import categorization (12 categories)
✅ x86 32-bit support
✅ x86 16-bit support
✅ .pyc decompilation
✅ SQLite caching
✅ Cross-platform .env support
✅ npm package ready
```
