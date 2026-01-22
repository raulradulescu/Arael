# Arael v2.6 Roadmap

**Milestone:** v2.6.0 - LLM Context Layer
**Status:** Complete

---

## Phase Overview

| Phase | Name | Status | Goal |
|-------|------|--------|------|
| 1 | Foundation & Testing | **Complete** | TDD tests for all v2.6 features |
| 2 | Import Database Expansion | **Complete** | 483 function capability database |
| 3 | IOC Extraction | **Complete** | Extract IPs, domains, URLs, registry keys from strings |
| 4 | Behavior Detection | **Complete** | Automated behavioral classification from imports/strings |
| 5 | String Cross-References | **Complete** | Utility functions for string xref analysis |
| 6 | MITRE ATT&CK Mapping | **Complete** | 36 ATT&CK techniques mapped |
| 7 | LLM Context Command | **Complete** | `arael context` - unified LLM-optimized output |
| 8 | Ask Command | **Complete** | `arael ask` - natural language binary queries |

---

## Phase 1: Foundation & Testing

**Goal:** Create comprehensive TDD tests defining expected behavior before implementation

**Requirements:**
- REQ-TEST-01: Tests for LLM context generation schema
- REQ-TEST-02: Tests for enhanced import analysis
- REQ-TEST-03: Tests for IOC extraction patterns
- REQ-TEST-04: Tests for behavior detection rules
- REQ-TEST-05: Tests for string xref resolution
- REQ-TEST-06: Tests for MITRE ATT&CK mapping

**Success Criteria:**
- [x] All test files created in `tests/unit/`
- [x] Tests define expected interfaces and behaviors
- [x] Tests serve as specification for implementation

**Files Created:**
- `tests/unit/llm-context.test.ts` - LLM context generation tests (42 tests)
- `tests/unit/import-database.test.ts` - Import capability tests (42 tests)
- `tests/unit/string-xrefs.test.ts` - String cross-reference tests (26 tests)
- `tests/unit/mitre-attack.test.ts` - MITRE ATT&CK mapping tests (42 tests)

**Total: 152 tests passing**

---

## Phase 2: Import Database Expansion

**Goal:** Expand import capability database from ~50 to 500+ functions

**Requirements:**
- REQ-IMP-01: Network functions (socket, HTTP, DNS)
- REQ-IMP-02: Process functions (create, inject, terminate)
- REQ-IMP-03: Crypto functions (Windows CryptoAPI, OpenSSL)
- REQ-IMP-04: Registry functions (read, write, enumerate)
- REQ-IMP-05: File I/O functions (create, read, write, delete)
- REQ-IMP-06: Service functions (create, start, stop)
- REQ-IMP-07: Credential functions (DPAPI, credential store)
- REQ-IMP-08: Anti-debug functions (IsDebuggerPresent, ptrace)
- REQ-IMP-09: UI/Keylogger functions (GetAsyncKeyState, SetWindowsHookEx)
- REQ-IMP-10: Linux syscalls (fork, execve, mmap, mprotect)

**Success Criteria:**
- [ ] 500+ functions in database
- [ ] Each function has: name, capabilities[], risk level, description
- [ ] >80% recognition rate on common malware

---

## Phase 3: IOC Extraction

**Goal:** Automatically extract Indicators of Compromise from strings

**Requirements:**
- REQ-IOC-01: IPv4/IPv6 address extraction
- REQ-IOC-02: Domain name extraction
- REQ-IOC-03: URL extraction (http/https/ftp)
- REQ-IOC-04: Email address extraction
- REQ-IOC-05: File path extraction (Windows/Linux)
- REQ-IOC-06: Registry key extraction
- REQ-IOC-07: Mutex name extraction
- REQ-IOC-08: User agent extraction

**Success Criteria:**
- [ ] IOCExtractor module created
- [ ] Regex patterns for all IOC types
- [ ] False positive filtering
- [ ] Deduplication

---

## Phase 4: Behavior Detection

**Goal:** Infer malicious behaviors from imports and strings

**Requirements:**
- REQ-BEH-01: Network client detection (outbound connections)
- REQ-BEH-02: Network server detection (listening)
- REQ-BEH-03: Process injection detection
- REQ-BEH-04: Credential theft detection
- REQ-BEH-05: Registry persistence detection
- REQ-BEH-06: Anti-analysis detection (debugger checks, VM detection)
- REQ-BEH-07: File encryption detection (ransomware indicator)
- REQ-BEH-08: Keylogging detection

**Success Criteria:**
- [ ] BehaviorDetector module created
- [ ] Rules for each behavior category
- [ ] Confidence scores
- [ ] Evidence linking (which imports/strings triggered)

---

## Phase 5: String Cross-References

**Goal:** Show which functions reference which strings

**Requirements:**
- REQ-XREF-01: Extract string references from Ghidra
- REQ-XREF-02: Map strings to referencing functions
- REQ-XREF-03: Include instruction address and type
- REQ-XREF-04: Support reverse lookup (functions using pattern)

**Success Criteria:**
- [x] StringXref module created (`src/analysis/string-xrefs.ts`)
- [x] Function-centric and string-centric views
- [x] Suspicious function detection

**Implementation:**
- `getStringsUsedByFunction()` - Get all strings referenced by a function
- `getFunctionsUsingString()` - Find functions referencing a string pattern
- `getStringUsageByFunction()` - Build complete usage map
- `findSuspiciousFunctions()` - Identify functions with suspicious strings
- `getXrefStats()` - Cross-reference statistics

---

## Phase 6: MITRE ATT&CK Mapping

**Goal:** Map detected behaviors to ATT&CK techniques

**Requirements:**
- REQ-ATT-01: Tactics mapping (execution, persistence, defense evasion, etc.)
- REQ-ATT-02: Technique identification from behaviors
- REQ-ATT-03: Confidence scoring
- REQ-ATT-04: Evidence linking

**Technique Coverage:**
- T1055 (Process Injection)
- T1547.001 (Registry Run Keys)
- T1070 (Indicator Removal)
- T1027 (Obfuscated Files)
- T1082 (System Information Discovery)
- T1083 (File and Directory Discovery)
- T1071 (Application Layer Protocol)
- T1486 (Data Encrypted for Impact)

**Success Criteria:**
- [ ] MITREMapper module created
- [ ] 20+ techniques mapped
- [ ] Confidence thresholds

---

## Phase 7: LLM Context Command

**Goal:** `arael context` - unified LLM-optimized output

**Requirements:**
- REQ-CTX-01: Summary generation (2-3 sentences)
- REQ-CTX-02: Classification (benign/suspicious/malware)
- REQ-CTX-03: Malware type identification
- REQ-CTX-04: Key function identification
- REQ-CTX-05: Suggested function names
- REQ-CTX-06: Suggested analysis steps
- REQ-CTX-07: Focus modes (security/functionality/vulnerabilities)

**CLI Interface:**
```bash
arael context ./malware.exe
arael context ./malware.exe --json
arael context ./malware.exe --focus security
```

**Success Criteria:**
- [ ] CLI command implemented
- [ ] LLMContext schema populated
- [ ] <5s generation time
- [ ] Human-readable and JSON output

---

## Phase 8: Ask Command

**Goal:** `arael ask` - natural language queries about binaries

**Requirements:**
- REQ-ASK-01: LLM provider abstraction (OpenAI, Anthropic, Ollama)
- REQ-ASK-02: Prompt templates for common questions
- REQ-ASK-03: Context injection from analysis
- REQ-ASK-04: Source attribution in answers
- REQ-ASK-05: Interactive mode

**CLI Interface:**
```bash
arael ask ./binary -q "What does the main function do?"
arael ask ./binary -q malicious
arael ask --list-templates
arael ask --list-providers
```

**Success Criteria:**
- [x] CLI command implemented
- [x] 4 LLM providers supported (OpenAI, Anthropic, Google Gemini, Ollama)
- [x] 9 question templates (malicious, purpose, main, network, persistence, credentials, evasion, iocs, summary)
- [x] Context injection from analysis

**Implementation:**
- `src/llm/provider.ts` - OpenAI, Anthropic, Google, Ollama providers
- `src/llm/prompts.ts` - System prompt and question templates
- CLI `arael ask` command with `-q`, `-p`, `-m`, `--list-templates`, `--list-providers`

**Default Models:**
- OpenAI: gpt-4o-mini
- Anthropic: claude-sonnet-4-20250514
- Google: gemini-2.0-flash
- Ollama: llama3.2

---

## Dependencies

```
Phase 1 (Testing) ─┬─> Phase 2 (Imports)
                   ├─> Phase 3 (IOC)
                   ├─> Phase 4 (Behavior) ──> Phase 6 (MITRE)
                   └─> Phase 5 (Xrefs)
                                          ↓
                              Phase 7 (Context) ──> Phase 8 (Ask)
```

---

## Timeline

| Phase | Estimated Effort |
|-------|------------------|
| Phase 1 | In Progress |
| Phase 2 | 4h |
| Phase 3 | 4h |
| Phase 4 | 8h |
| Phase 5 | 4h |
| Phase 6 | 8h |
| Phase 7 | 8h |
| Phase 8 | 12h |
