## Arael v2.3.0 - Proposed Features

### Immediate Priorities (Complete Phase 3)
```
□ Comprehensive error messages with troubleshooting hints
□ npm package configuration & publishing to npmjs.com
□ Claude Code MCP integration testing (real /arael command)
```

### New MCP Tools (P1)

| Tool | Description | Rationale |
|------|-------------|-----------|
| `arael_disassemble` | Raw assembly listing per function | Natural complement to decompile; needed for low-level analysis |
| `arael_xrefs` | Cross-references to/from address | Critical for tracing data flow; "who calls this? what does this call?" |
| `arael_exports` | Exported symbols | Already in schema, just needs MCP tool wrapper |
| `arael_callgraph` | Function call relationships (JSON + DOT) | Visualize program structure; useful for large binaries |

### Unpacking & Extraction (P1)

| Feature | Description | Rationale |
|---------|-------------|-----------|
| **UPX Auto-Unpack** | Detect + automatically unpack UPX binaries | Most common packer; `upx -d` is reliable |
| **PyInstaller Extract** | Detect + extract Python bytecode from PyInstaller bundles | Common in malware & CTFs; use pyinstxtractor |
| **Packing Detection** | Entropy analysis + packer signatures (UPX, Themida, ASPack, VMProtect, etc.) | Detection-only for unknown packers |
| **.pyc Decompilation** | Decompile extracted .pyc to .py (via uncompyle6/pycdc) | Complete the PyInstaller analysis workflow |

### Enhanced Analysis (P1)

| Feature | Description | Rationale |
|---------|-------------|-----------|
| **Section Analysis** | Permissions, entropy, anomalies per section | Detect rwx sections, high-entropy packed data |
| **Symbol Recovery** | Better naming for stripped binaries | Improve readability of analysis output |
| **Import Categorization** | Group imports by capability (Network, Crypto, Process, File, Registry) | Already in scripts, integrate to core |

### Architecture Expansion (P2)

| Architecture | Priority | Notes |
|--------------|----------|-------|
| x86 (32-bit) | High | Lots of legacy malware; minimal effort since x86_64 works |
| ARM64 | Medium | macOS Apple Silicon, Android, IoT |
| ARM32 | Medium | Embedded, IoT, Android |

### Quality of Life (P2)

| Feature | Description |
|---------|-------------|
| **Interactive Mode** | REPL for exploratory analysis: `arael shell ./binary` |
| **Watch Mode** | Re-analyze on file change (for iterating on RE) |
| **Batch Analysis** | Analyze directory of samples: `arael analyze ./samples/*.exe` |
| **Export Formats** | JSON (done), Markdown report, HTML report (scripts exist, integrate to CLI) |

### Security Integrations (P2)

| Feature | Description |
|---------|-------------|
| **YARA Scanning** | Run YARA rules against binary (built-in rulesets: packers, crypto, capabilities) |
| **VirusTotal Lookup** | Hash lookup (optional, requires API key) |
| **MITRE ATT&CK Mapping** | Map imports/behaviors to ATT&CK techniques |

---

## Suggested v2.3.0 Scope
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         v2.3.0 IMPLEMENTATION STATUS                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  MUST HAVE (Ship Blockers)                                                  │
│  ├─ npm publish ready                                            [⏸️ TODO] │
│  ├─ arael_disassemble tool                                       [✅ DONE] │
│  ├─ arael_xrefs tool                                             [✅ DONE] │
│  ├─ arael_exports tool                                           [✅ DONE] │
│  ├─ UPX auto-unpacking                                           [✅ DONE] │
│  └─ PyInstaller extraction                                       [✅ DONE] │
│                                                                             │
│  SHOULD HAVE (High Value)                                                   │
│  ├─ Packing detection (entropy + 10 packer signatures)           [✅ DONE] │
│  ├─ arael_callgraph tool                                         [✅ DONE] │
│  ├─ x86 (32-bit) architecture support                     [📋 TESTS READY] │
│  ├─ Section analysis (permissions, entropy)                      [✅ DONE] │
│  └─ .pyc decompilation (uncompyle6/pycdc)                 [📋 TESTS READY] │
│                                                                             │
│  NICE TO HAVE (If Time)                                                     │
│  ├─ Interactive shell mode                                       [     ]   │
│  ├─ Batch analysis                                               [     ]   │
│  ├─ YARA scanning with built-in rulesets                         [     ]   │
│  ├─ HTML report generation (CLI integration)                     [     ]   │
│  └─ x86 (16-bit) architecture support                     [📋 TESTS READY] │
│                                                                             │
│  Legend: ✅ DONE | 📋 TESTS READY (TDD) | ⏸️ TODO                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### TDD Test Suites Available
| Feature | Test File | Lines | Status |
|---------|-----------|-------|--------|
| .pyc Decompilation | tests/unit/pyc-decompilation.test.ts | ~380 | Ready for implementation |
| x86 32-bit Support | tests/integration/arch-x86-32bit.test.ts | ~330 | Ready for implementation |
| x86 16-bit Support | tests/integration/arch-x86-16bit.test.ts | ~470 | Ready for implementation |

### Supported Packers (Detection)

| Packer | Detection | Auto-Unpack |
|--------|-----------|-------------|
| UPX | ✅ Magic bytes, section names, `upx -l` | ✅ Yes |
| PyInstaller | ✅ MEI magic, strings | ✅ Yes (extraction) |
| ASPack | ✅ Section names | ❌ No |
| Themida | ✅ Section names, strings | ❌ No |
| VMProtect | ✅ Section names (.vmp) | ❌ No |
| PECompact | ✅ Section names | ❌ No |
| MPRESS | ✅ Section names (.MPRESS) | ❌ No |
| Enigma | ✅ Strings | ❌ No |
| .NET Reactor | ✅ .NET metadata | ❌ No |
| Py2Exe | ✅ Strings, resources | ✅ Partial |