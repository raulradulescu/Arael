# Arael v2.6 - LLM-Optimized Reverse Engineering

## Version Overview

**Version:** 2.6.0
**Codename:** "LLM Context Layer"
**Focus:** Making analysis output optimal for LLM-based reverse engineering
**Status:** Planning

---

## Executive Summary

Arael v2.6 focuses on enhancing the analysis output to be more useful for Large Language Models performing reverse engineering tasks. While the current output provides raw data, LLMs benefit from structured context, behavioral summaries, and semantic hints.

### Key Deliverables

1. **`arael context`** - LLM-optimized analysis summary
2. **`arael ask`** - Natural language queries about binaries
3. **Enhanced import analysis** - Better capability detection
4. **Cross-reference enrichment** - String and data xrefs
5. **Control flow hints** - Basic CFG information

---

## Problem Statement

### Current State (v2.5)

The current JSON output is **technically complete** but **not LLM-optimized**:

```json
{
  "functions": [
    {"name": "FUN_00401000", "address": "00401000", "size": 127, ...},
    {"name": "FUN_00401080", "address": "00401080", "size": 45, ...}
  ],
  "imports": [
    {"name": "recv", "library": "<EXTERNAL>", "capabilities": [], "description": "Unknown function"}
  ]
}
```

**Issues:**
- Generic function names (`FUN_00401000`) provide no semantic meaning
- Import capabilities often empty or "Unknown"
- No behavioral summary
- No security-focused context
- No suggested analysis paths

### Desired State (v2.6)

```json
{
  "llmContext": {
    "summary": "Windows x64 executable with network capabilities. Connects to remote server, receives commands, and executes them. Shows characteristics of a reverse shell.",
    "classification": {
      "type": "backdoor",
      "confidence": 0.85,
      "family": "generic-reverse-shell"
    },
    "behaviors": [
      {"category": "network", "description": "Establishes TCP connection to remote host"},
      {"category": "execution", "description": "Executes received commands via CreateProcess"},
      {"category": "persistence", "description": "No persistence mechanism detected"}
    ],
    "keyFunctions": [
      {
        "address": "00401000",
        "suggestedName": "establish_c2_connection",
        "purpose": "Creates socket and connects to hardcoded IP:port",
        "securityRelevance": "high",
        "pseudocode": "..."
      }
    ],
    "iocs": {
      "ips": ["192.168.1.100"],
      "domains": [],
      "urls": ["http://192.168.1.100:4444/beacon"]
    },
    "suggestedAnalysis": [
      "Examine function at 0x401000 for C2 configuration",
      "Check strings for additional hardcoded credentials",
      "Analyze command parsing in FUN_00401200"
    ]
  }
}
```

---

## Feature Specifications

### Feature 1: `arael context` Command

**Priority:** P0 (Critical)
**Complexity:** Medium
**Dependencies:** Existing analysis infrastructure

#### Description

Generate an LLM-optimized context summary from binary analysis.

#### CLI Interface

```bash
# Generate context summary
arael context ./malware.exe

# JSON output for programmatic use
arael context ./malware.exe --json

# Include full pseudocode for key functions
arael context ./malware.exe --include-code

# Focus on specific aspects
arael context ./malware.exe --focus security
arael context ./malware.exe --focus functionality
arael context ./malware.exe --focus vulnerabilities
```

#### Output Schema

```typescript
interface LLMContext {
  // High-level summary (2-3 sentences)
  summary: string;

  // Binary classification
  classification: {
    type: 'benign' | 'suspicious' | 'malware' | 'unknown';
    malwareType?: 'backdoor' | 'ransomware' | 'trojan' | 'worm' | 'dropper' | 'rat';
    confidence: number;
    reasoning: string[];
  };

  // Detected behaviors
  behaviors: {
    category: BehaviorCategory;
    description: string;
    evidence: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  }[];

  // Important functions with semantic analysis
  keyFunctions: {
    address: string;
    originalName: string;
    suggestedName: string;
    purpose: string;
    securityRelevance: 'low' | 'medium' | 'high' | 'critical';
    calledBy: string[];
    calls: string[];
    pseudocode?: string;
  }[];

  // Indicators of Compromise
  iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    emails: string[];
    filePaths: string[];
    registryKeys: string[];
    mutexes: string[];
    userAgents: string[];
  };

  // Attack surface analysis
  attackSurface: {
    entryPoints: string[];
    inputHandlers: string[];
    networkEndpoints: string[];
    fileOperations: string[];
  };

  // Suggested next steps for analysis
  suggestedAnalysis: string[];

  // MITRE ATT&CK mapping (if detectable)
  mitreAttack?: {
    tactics: string[];
    techniques: {id: string; name: string; confidence: number}[];
  };
}

type BehaviorCategory =
  | 'network'
  | 'filesystem'
  | 'process'
  | 'registry'
  | 'crypto'
  | 'execution'
  | 'persistence'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'collection'
  | 'exfiltration';
```

#### Implementation Notes

1. Analyze imports to infer capabilities
2. Pattern match on function names and strings
3. Examine call graphs for behavioral chains
4. Extract IOCs from strings using regex patterns
5. Generate suggested names based on function behavior

---

### Feature 2: `arael ask` Command

**Priority:** P0 (Critical)
**Complexity:** High
**Dependencies:** `arael context`, LLM integration

#### Description

Natural language interface for querying binary analysis.

#### CLI Interface

```bash
# Ask questions about the binary
arael ask ./binary "What does the main function do?"
arael ask ./binary "Is this binary malicious?"
arael ask ./binary "How does the authentication work?"
arael ask ./binary "What network connections does it make?"

# Use specific LLM provider
arael ask ./binary "Explain the encryption" --provider openai
arael ask ./binary "Find vulnerabilities" --provider anthropic
arael ask ./binary "Summarize" --provider ollama

# Interactive mode
arael ask ./binary --interactive
```

#### Implementation

```typescript
interface AskConfig {
  provider: 'openai' | 'anthropic' | 'ollama' | 'local';
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens?: number;
}

interface AskResult {
  question: string;
  answer: string;
  confidence: number;
  sources: {
    type: 'function' | 'string' | 'import' | 'section';
    reference: string;
    relevance: number;
  }[];
  followUpQuestions?: string[];
}
```

---

### Feature 3: Enhanced Import Analysis

**Priority:** P1 (High)
**Complexity:** Low
**Dependencies:** None

#### Problem

Current import analysis shows many functions as "Unknown":

```json
{"name": "recv", "capabilities": [], "description": "Unknown function"}
```

#### Solution

Expand the import capability database with 500+ common functions:

```typescript
const IMPORT_DATABASE: Record<string, ImportMetadata> = {
  // Network
  'recv': { capabilities: ['Network'], risk: 'medium', description: 'Receive data from socket' },
  'send': { capabilities: ['Network'], risk: 'medium', description: 'Send data to socket' },
  'WSAStartup': { capabilities: ['Network'], risk: 'low', description: 'Initialize Winsock' },
  'connect': { capabilities: ['Network'], risk: 'medium', description: 'Connect to remote host' },
  'bind': { capabilities: ['Network'], risk: 'medium', description: 'Bind socket to address' },
  'listen': { capabilities: ['Network'], risk: 'medium', description: 'Listen for connections' },
  'accept': { capabilities: ['Network'], risk: 'medium', description: 'Accept incoming connection' },

  // Process
  'CreateProcessA': { capabilities: ['Process', 'Execution'], risk: 'high', description: 'Create new process' },
  'CreateProcessW': { capabilities: ['Process', 'Execution'], risk: 'high', description: 'Create new process (Unicode)' },
  'ShellExecuteA': { capabilities: ['Process', 'Execution'], risk: 'high', description: 'Execute file/command' },
  'WinExec': { capabilities: ['Process', 'Execution'], risk: 'critical', description: 'Execute command (legacy)' },
  'system': { capabilities: ['Process', 'Execution'], risk: 'critical', description: 'Execute shell command' },

  // Injection
  'VirtualAllocEx': { capabilities: ['Memory', 'Injection'], risk: 'high', description: 'Allocate memory in remote process' },
  'WriteProcessMemory': { capabilities: ['Memory', 'Injection'], risk: 'critical', description: 'Write to remote process memory' },
  'CreateRemoteThread': { capabilities: ['Process', 'Injection'], risk: 'critical', description: 'Create thread in remote process' },
  'NtCreateThreadEx': { capabilities: ['Process', 'Injection'], risk: 'critical', description: 'Create thread (NT API)' },

  // Crypto
  'CryptEncrypt': { capabilities: ['Crypto'], risk: 'medium', description: 'Encrypt data' },
  'CryptDecrypt': { capabilities: ['Crypto'], risk: 'medium', description: 'Decrypt data' },
  'CryptGenKey': { capabilities: ['Crypto'], risk: 'medium', description: 'Generate crypto key' },
  'CryptHashData': { capabilities: ['Crypto'], risk: 'low', description: 'Hash data' },

  // Anti-Debug
  'IsDebuggerPresent': { capabilities: ['AntiDebug'], risk: 'medium', description: 'Check if debugger attached' },
  'CheckRemoteDebuggerPresent': { capabilities: ['AntiDebug'], risk: 'medium', description: 'Check for remote debugger' },
  'NtQueryInformationProcess': { capabilities: ['AntiDebug', 'System'], risk: 'medium', description: 'Query process info (anti-debug)' },

  // Persistence
  'RegSetValueExA': { capabilities: ['Registry', 'Persistence'], risk: 'high', description: 'Set registry value' },
  'RegCreateKeyExA': { capabilities: ['Registry', 'Persistence'], risk: 'high', description: 'Create registry key' },
  'CreateServiceA': { capabilities: ['System', 'Persistence'], risk: 'high', description: 'Create Windows service' },

  // FileIO
  'CreateFileA': { capabilities: ['FileIO'], risk: 'low', description: 'Create or open file' },
  'ReadFile': { capabilities: ['FileIO'], risk: 'low', description: 'Read from file' },
  'WriteFile': { capabilities: ['FileIO'], risk: 'low', description: 'Write to file' },
  'DeleteFileA': { capabilities: ['FileIO'], risk: 'medium', description: 'Delete file' },

  // Linux syscalls
  'ptrace': { capabilities: ['AntiDebug', 'Process'], risk: 'high', description: 'Process trace (anti-debug on Linux)' },
  'fork': { capabilities: ['Process'], risk: 'medium', description: 'Create child process' },
  'execve': { capabilities: ['Process', 'Execution'], risk: 'high', description: 'Execute program' },
  'mmap': { capabilities: ['Memory'], risk: 'medium', description: 'Map memory region' },
  'mprotect': { capabilities: ['Memory'], risk: 'high', description: 'Change memory protection' },
};
```

---

### Feature 4: Cross-Reference Enrichment

**Priority:** P1 (High)
**Complexity:** Medium
**Dependencies:** Ghidra xref scripts

#### Problem

Strings currently lack cross-reference information:

```json
{"address": "00402000", "value": "http://evil.com", "xrefs": []}
```

#### Solution

Populate xrefs for strings showing where they're used:

```json
{
  "address": "00402000",
  "value": "http://evil.com",
  "xrefs": [
    {"address": "00401150", "function": "download_payload", "type": "data", "instruction": "lea rax, [0x402000]"},
    {"address": "00401200", "function": "init_c2", "type": "data", "instruction": "mov rdi, 0x402000"}
  ]
}
```

#### Implementation

Update `run_analysis.py` to include xref extraction:

```python
def get_string_xrefs(string_addr):
    xrefs = []
    for ref in getReferencesTo(toAddr(string_addr)):
        func = getFunctionContaining(ref.getFromAddress())
        xrefs.append({
            'address': str(ref.getFromAddress()),
            'function': func.getName() if func else 'unknown',
            'type': 'data' if ref.isDataReference() else 'code'
        })
    return xrefs
```

---

### Feature 5: Control Flow Hints

**Priority:** P2 (Medium)
**Complexity:** Medium
**Dependencies:** Ghidra CFG extraction

#### Description

Add basic control flow information to help LLMs understand function logic:

```typescript
interface ControlFlowHints {
  hasLoops: boolean;
  loopCount: number;
  hasBranches: boolean;
  branchCount: number;
  hasRecursion: boolean;
  complexity: 'low' | 'medium' | 'high';
  cyclomaticComplexity?: number;
  dominantPatterns: ('sequential' | 'loop' | 'switch' | 'conditional')[];
}
```

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Expand import database (200+ functions) | P1 | 4h | - |
| Add string xref extraction | P1 | 4h | - |
| Create `LLMContext` schema | P0 | 2h | - |
| Implement IOC extraction from strings | P1 | 4h | - |

### Phase 2: Context Command (Week 3-4)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Implement `arael context` CLI | P0 | 8h | - |
| Add behavior inference from imports | P0 | 8h | - |
| Add function purpose inference | P1 | 8h | - |
| Add suggested name generation | P2 | 4h | - |
| Add MITRE ATT&CK mapping | P2 | 8h | - |

### Phase 3: Ask Command (Week 5-6)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| LLM provider abstraction layer | P0 | 8h | - |
| Implement OpenAI integration | P0 | 4h | - |
| Implement Anthropic integration | P1 | 4h | - |
| Implement Ollama integration | P1 | 4h | - |
| Create prompt templates | P0 | 8h | - |
| Add interactive mode | P2 | 4h | - |

### Phase 4: Polish (Week 7-8)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Add control flow hints | P2 | 8h | - |
| Documentation | P1 | 4h | - |
| Testing with real malware samples | P0 | 8h | - |
| Performance optimization | P2 | 4h | - |

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Import recognition rate | >80% | % of imports with known capabilities |
| String xref coverage | >90% | % of strings with at least 1 xref |
| Context generation time | <5s | Time to generate LLM context |
| LLM query accuracy | >85% | Correctness of `arael ask` responses |
| User satisfaction | >4/5 | Survey rating for LLM features |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| LLM API costs | Medium | Medium | Support local models (Ollama) |
| Incorrect behavior inference | High | Medium | Show confidence scores, allow override |
| Performance degradation | Low | High | Cache context, lazy evaluation |
| API key security | Medium | High | Use env vars, never log keys |

---

## Appendix A: Behavior Detection Rules

```typescript
const BEHAVIOR_RULES: BehaviorRule[] = [
  {
    id: 'network_client',
    category: 'network',
    description: 'Establishes outbound network connections',
    triggers: {
      imports: ['connect', 'WSAConnect', 'HttpOpenRequest'],
      strings: [/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, /https?:\/\//]
    },
    riskLevel: 'medium'
  },
  {
    id: 'network_server',
    category: 'network',
    description: 'Listens for incoming network connections',
    triggers: {
      imports: ['bind', 'listen', 'accept'],
      patterns: ['socket.*bind.*listen']
    },
    riskLevel: 'high'
  },
  {
    id: 'process_injection',
    category: 'execution',
    description: 'Injects code into other processes',
    triggers: {
      imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
      requiredCount: 2
    },
    riskLevel: 'critical'
  },
  {
    id: 'credential_theft',
    category: 'credential_access',
    description: 'Accesses credential storage',
    triggers: {
      imports: ['CredEnumerate', 'CryptUnprotectData'],
      strings: ['password', 'credential', 'login', 'chrome', 'firefox']
    },
    riskLevel: 'critical'
  },
  {
    id: 'persistence_registry',
    category: 'persistence',
    description: 'Modifies registry for persistence',
    triggers: {
      imports: ['RegSetValueEx', 'RegCreateKeyEx'],
      strings: ['\\CurrentVersion\\Run', 'SOFTWARE\\Microsoft\\Windows']
    },
    riskLevel: 'high'
  },
  {
    id: 'anti_analysis',
    category: 'defense_evasion',
    description: 'Contains anti-analysis techniques',
    triggers: {
      imports: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
      strings: ['vmware', 'virtualbox', 'sandbox']
    },
    riskLevel: 'medium'
  },
  {
    id: 'encryption',
    category: 'crypto',
    description: 'Uses cryptographic functions',
    triggers: {
      imports: ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt'],
      yaraRules: ['Crypto_AES', 'Crypto_RSA']
    },
    riskLevel: 'medium'
  },
  {
    id: 'file_encryption',
    category: 'crypto',
    description: 'Encrypts files (ransomware indicator)',
    triggers: {
      imports: ['FindFirstFile', 'FindNextFile', 'CryptEncrypt'],
      strings: ['.encrypted', '.locked', 'your files have been encrypted']
    },
    riskLevel: 'critical'
  }
];
```

---

## Appendix B: Prompt Templates

### System Prompt for Binary Analysis

```
You are an expert reverse engineer and malware analyst. You are analyzing a binary executable.

Context:
- Binary: {filename}
- Format: {format} ({architecture}, {bits}-bit)
- Size: {size} bytes
- Entropy: {entropy}
- Packing: {packing_status}

Capabilities detected:
{capabilities_list}

Key functions:
{key_functions}

Strings of interest:
{interesting_strings}

Imports:
{imports_with_capabilities}

Answer questions about this binary accurately and concisely. If you're uncertain, say so.
Focus on security implications and potential malicious behavior.
```

### Question Templates

```typescript
const QUESTION_TEMPLATES = {
  purpose: "Based on the analysis, what is the primary purpose of this binary?",
  malicious: "Is this binary potentially malicious? List specific indicators.",
  network: "What network activity does this binary perform?",
  persistence: "Does this binary establish persistence? How?",
  vulnerabilities: "What potential vulnerabilities exist in this binary?",
  authentication: "How does authentication/validation work in this binary?",
  encryption: "What encryption or encoding is used?",
  c2: "If this is malware, describe the C2 communication protocol.",
};
```

---

## Appendix C: Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.6.0 | TBD | Initial LLM context layer |
| 2.5.2 | 2026-01 | Code refactoring, YARA tiered rules |
| 2.5.0 | 2026-01 | Shell, batch, YARA, reports |
| 2.4.0 | 2025-12 | x86 16/32-bit, ARM support |
