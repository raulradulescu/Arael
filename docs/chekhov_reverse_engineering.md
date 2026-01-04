# Chekhov Binary Reverse Engineering Analysis

**Date:** 2025-12-28
**Analyst:** Arael Reverse Engineering Tool
**Binary:** `tests/fixtures/chekhov`
**Status:** Partial - 7/8 key groups recovered, anti-debug bypassed

---

## Executive Summary

The `chekhov` binary is a Linux ELF x86_64 license key validator with heavy anti-analysis protections. The binary expects a license key in a specific format and validates it through an obfuscated algorithm. This document details the reverse engineering progress and findings.

---

## 1. Binary Metadata

| Property | Value |
|----------|-------|
| **Filename** | chekhov |
| **Format** | ELF 64-bit LSB executable |
| **Architecture** | x86_64 |
| **Endianness** | Little Endian |
| **Size** | 659,240 bytes (644 KB) |
| **Entropy** | 5.76 (not packed) |

### Hashes
| Algorithm | Hash |
|-----------|------|
| MD5 | `13e58537f6454ed3589c08ff9fb45f7f` |
| SHA1 | `37e0f0cb11afd7c42be0b775cc1de3d67b31caf1` |
| SHA256 | `517bfe0b829557f7086a5abdbb60346e03b0bd00e6cdf888628f5cea756db8f1` |

---

## 2. Section Analysis

### Key Sections

| Section | Virtual Address | Size | Entropy | Permissions |
|---------|-----------------|------|---------|-------------|
| `.text` | 0x7990 | 620,827 | 5.83 | R-X |
| `.rodata` | 0x6600 | 844 | 5.98 | R-- |
| `.data` | 0xa3530 | 24 | 0.00 | RW- |
| `.bss` | 0xa3548 | 16 | 3.50 | RW- |

### Observations
- Main code section (`.text`) is large at ~606 KB
- Read-only data section contains validation constants and error strings
- No evidence of packing or compression

---

## 3. Identified Functions

| Address | Name | Size | Description |
|---------|------|------|-------------|
| 0x107990 | `entry` | 38 | ELF entry point, calls `__libc_start_main` |
| 0x107b90 | `FUN_00107b90` | 328 | Timing/PRNG initialization |
| 0x107ce0 | `FUN_00107ce0` | 3,227 | Main validation logic (obfuscated) |
| 0x108990 | `FUN_00108990` | 89 | Exit/failure handler |
| 0x108a60 | `_INIT_0` | 1,028 | Initialization routine |
| 0x108e80 | `FUN_00108e80` | 416 | **License key parser** |
| 0x109080 | `FUN_00109080` | 96 | Validation subroutine |
| 0x19e480 | `FUN_0019e480` | 2,525 | Main execution loop |

---

## 4. License Key Format

### Structure
```
XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
│      │      │      │      │      │      │      │
└──────┴──────┴──────┴──────┴──────┴──────┴──────┴── 8 groups
       └── 6 characters each (base-36: 0-9, A-Z)
```

### Specifications
- **Total Length:** 55 characters (48 alphanumeric + 7 dashes)
- **Character Set:** `0-9` (values 0-9) and `A-Z` (values 10-35)
- **Encoding:** Base-36
- **Maximum Value per Group:** 36^6 - 1 = 2,176,782,335

### Validation Regex
```regex
^[0-9A-Z]{6}(-[0-9A-Z]{6}){7}$
```

---

## 5. Key Parsing Algorithm

### Function: `FUN_00108e80` at 0x108e80

```c
void FUN_00108e80(char *key_string) {
    int group_values[8];  // Stored at global_struct + 0x1a0

    for (int group = 0; group < 8; group++) {
        // Check for dash separator (except first group)
        if (group != 0) {
            if (*key_string != '-') {
                exit_with_error("expected dash");
            }
            key_string++;
        }

        int value = 0;
        for (int i = 0; i < 6; i++) {
            char c = key_string[i];
            int char_index = c - '0';  // 0x30

            // Validate character (bitmask check)
            // Valid: 0-9 (indices 0-9) and A-Z (indices 17-42)
            if (char_index > 42 ||
                !((0x7fffffe03ff >> char_index) & 1)) {
                exit_with_error("bad character");
            }

            // Base-36 decode using lookup table at 0x68a0
            // lookup[0-9] = -48 (0xFFFFFFD0)
            // lookup[17-42] = -55 (0xFFFFFFC9)
            int digit = c + lookup_table[char_index];
            value = value * 36 + digit;
        }

        group_values[group] = value;
        key_string += 6;
    }

    // Verify null terminator
    if (*key_string != '\0') {
        exit_with_error("too long");
    }
}
```

### Lookup Table (0x68a0)

| Index Range | Value | Purpose |
|-------------|-------|---------|
| 0-9 | -48 (0xFFFFFFD0) | Convert '0'-'9' to 0-9 |
| 10-16 | 0 | Unused (gap between '9' and 'A') |
| 17-42 | -55 (0xFFFFFFC9) | Convert 'A'-'Z' to 10-35 |

### Character Validation Bitmask
```
0x7fffffe03ff = 0111 1111 1111 1111 1111 1110 0000 0011 1111 1111
                ├──────── A-Z (bits 17-42) ────────┤    ├ 0-9 ─┤
```

---

## 6. Anti-Analysis Techniques

### 6.1 Control Flow Obfuscation
- **Opaque Predicates:** Conditions that always evaluate to the same value but appear complex
- **Dead Code Insertion:** Many "unreachable blocks" reported by decompiler
- **Indirect Jumps:** Function pointers and computed gotos

### 6.2 Direct Syscalls
The binary uses raw `syscall` instructions instead of libc wrappers:
```asm
syscall  ; Used throughout for various operations
```
This bypasses:
- Library interposition (LD_PRELOAD)
- Debugger breakpoints on libc functions
- Tracing tools like ltrace

### 6.3 Timing Checks
XORshift64 PRNG pattern detected:
```c
// Timing-based anti-debug
x ^= x << 13;
x ^= x >> 7;
x ^= x << 17;
```
- Error message: "license validation timed out (your computer may be too slow)"

### 6.4 Required Linux Capabilities
```bash
setcap 'cap_dac_read_search=ep cap_sys_ptrace=ep' chekhov
```
- `cap_dac_read_search`: Bypass file read permission checks
- `cap_sys_ptrace`: Trace/debug processes (self-protection check)

---

## 7. Validation Data Analysis

### Data at 0x6620 (Potential Expected Values)

| Index | Hex | Decimal | Base-36 | Valid? |
|-------|-----|---------|---------|--------|
| 0 | 0x2d05a308 | 755,344,136 | CHPN9K | Yes |
| 1 | 0x1a12e1a9 | 437,445,033 | 78FYQX | Yes |
| 2 | 0x5eca6a4e | 1,590,323,790 | QAU5OU | Yes |
| 3 | 0x51a89f2d | 1,370,005,293 | MNNYUL | Yes |
| 4 | 0x6490ad1a | 1,687,203,098 | RWIM8Q | Yes |
| 5 | 0xc74866ca | 3,343,410,890 | N/A | **No** (exceeds max) |
| 6 | 0x273a7792 | 658,143,122 | AVUAHE | Yes |
| 7 | 0x4337ea19 | 1,127,737,881 | INFC49 | Yes |

### Data at 0x6680 (Potential XOR Mask)

| Index | Hex | Decimal |
|-------|-----|---------|
| 0 | 0xdbd54d40 | 3,688,189,248 |
| 1 | 0x3b244096 | 992,231,574 |
| 2 | 0xc52db7da | 3,308,107,738 |
| 3 | 0x5fe7a3e8 | 1,609,016,296 |
| 4 | 0xb4a73d6f | 3,030,859,119 |
| 5 | 0x5e576ff5 | 1,582,788,597 |
| 6 | 0xa402d1b6 | 2,751,648,182 |
| 7 | 0x5f91db9d | 1,603,394,461 |

### Observation
Value at index 5 in the 0x6620 table exceeds the maximum valid base-36 value, suggesting:
1. XOR transformation is applied before comparison
2. Values are computed dynamically
3. Different validation mechanism than direct comparison

---

## 8. Error Messages (from .rodata)

| Offset | Message | ANSI Color |
|--------|---------|------------|
| 0x66f0 | `invalid format (bad character)` | - |
| 0x6718 | `license validation timed out (your computer may be too slow)` | - |
| 0x6758 | `invalid format (too long)` | Reset (0m) |
| 0x6778 | `please setcap 'cap_dac_read_search=ep cap_sys_ptrace=ep' chekhov` | Green (32m) |
| 0x67c0 | `failed to validate license` | Red (31m) |
| 0x67dc | `no license key specified` | - |
| 0x67f8 | `invalid format (expected dash)` | - |

---

## 9. Partial Key Recovery

Based on the valid values from 0x6620:
```
CHPN9K-78FYQX-QAU5OU-MNNYUL-RWIM8Q-??????-AVUAHE-INFC49
```

**Missing:** Group 5 (value 0xc74866ca exceeds base-36 range)

---

## 10. Dynamic Analysis Results

### 10.1 Binary Patching (Successful)

Successfully patched the binary to bypass anti-analysis protections:

#### Capability Check Bypass
```
File offset: 0x8543 (0x7543 in .text)
Original:   je  (0x74 0x30) - jump if capabilities present
Patched:    jne (0x75 0x30) - invert condition
```

#### Ptrace Anti-Debug Bypass
```
File offset: 0x6f5f (0x5f5f in .text)
Original:   jae instruction
Patched:    90 90 (NOP NOP)

File offset: 0x6f79 (0x5f79 in .text)
Original:   jne instruction
Patched:    90 90 (NOP NOP)
```

### 10.2 Fork Behavior

The binary uses a parent-child process model:
- **Parent process:** Exits with code 0 immediately after fork
- **Child process:** Performs actual validation, exits with code 0 (success) or 1 (failure)

This makes simple exit-code testing unreliable. Use `strace -f` to trace child:
```bash
strace -f -e trace=exit_group ./chekhov_patched "KEY" 2>&1 | grep exit_group
```

### 10.3 Success Path Analysis

At address 0x7f38, there is a success exit path:
```asm
7f38:   31 ff           xor    %edi,%edi        ; exit code 0
7f40:   b8 e7 00 00 00  mov    $0xe7,%eax       ; syscall 231 = exit_group
7f45:   0f 05           syscall
```

The path to success requires:
1. Fork syscall returning child PID in r9d
2. Child performing validation (via ioctl/ptrace operations)
3. Parent waiting for child with waitid syscall (0x3d)
4. Child exit status matching expected value

### 10.4 Data Layout Confirmation

From disassembly at 0x7d09:
```asm
vmovaps -0x1691(%rip),%ymm0    # Loads 32 bytes from 0x6680 (XOR masks)
vmovups %ymm0,0x240(%rsp)      # Store masks
vmovaps 0x250(%rsp),%xmm0      # Load user data
vxorps  0x240(%rsp),%xmm0,%xmm0 # XOR operation
vmovaps %xmm0,0x1e0(%rsp)      # Store result
```

Additional data at 0x6640 (8 x 32-bit values):
| Index | Hex | Decimal |
|-------|-----|---------|
| 0 | 0xcca18906 | 3,433,138,438 |
| 1 | 0x35d813e5 | 903,353,317 |
| 2 | 0x89524b94 | 2,303,871,892 |
| 3 | 0xf181dfd1 | 4,051,820,497 |
| 4 | 0xa3d3f929 | 2,748,578,089 |
| 5 | 0x50ab3c86 | 1,353,399,430 |
| 6 | 0xfa7d2df8 | 4,202,507,768 |
| 7 | 0xf1f5bea5 | 4,059,414,181 |

---

## 11. Candidate Values Tested

### XOR-Based Candidates

| Hypothesis | Formula | Group 5 Value | Result |
|------------|---------|---------------|--------|
| XOR checksum = 0 | known_vals XOR x = 0 | FSFVWZ (954,763,091) | Failed |
| XOR = mask XOR | all XOR = masks XOR | N7YLTY (1,404,093,958) | Failed |
| Sum constraint | sum mod N = 0 | 00000R, FXS4JZ, etc. | Failed |
| Match other group | val[5] = val[i] | CHPN9K, etc. | Failed |

### Simple Value Tests
- 000000, AAAAAA, ZZZZZZ: All failed

---

## 12. Brute Force Attempt

### Approach
Created a high-performance C brute forcer using AES-NI intrinsics to test all 2,176,782,336 possible values for group 5.

### Assumptions
1. The 8 license key groups form a 32-byte AES-256 key (little-endian)
2. Ciphertext block at 0x6830 decrypts to flag starting with "hxp{"
3. Group 5 is the only unknown (value 0xc74866ca exceeds max base-36)

### Results
- **Full range tested:** 0 to 2,176,782,335
- **Rate:** ~25.5 million keys/second
- **Total time:** ~85 seconds
- **Result:** No match found for "hxp{" prefix

### Variants Tested
| Variant | Description | Result |
|---------|-------------|--------|
| LE key, decrypt | Little-endian key, AES decrypt | No match |
| BE key, decrypt | Big-endian key, AES decrypt | No match |
| LE key, encrypt | Little-endian key, AES encrypt | No match |
| Key XOR mask | Key values XORed with 0x6680 masks | No match |
| Masks as key | Using 0x6680 masks directly as key | No match |
| AES-128 | Using only first/last 4 groups | No match |

### Conclusion
The AES key derivation assumption appears incorrect. The actual validation mechanism is more complex and may involve:
- File system operations (observed `open()` syscalls)
- Process tracing via ptrace
- Dynamic key transformation
- Different cryptographic primitive

### Ciphertext Location Verified
```
Offset 0x6830: c1 3c 3d 6b 5f 7f 70 72 40 76 df 4f 5d 62 55 83
```

---

## 13. Remaining Analysis Required

### Symbolic Execution Approach
The validation logic is heavily obfuscated. Recommended approach:
```python
import angr

proj = angr.Project('./chekhov_patched')
state = proj.factory.entry_state(args=['./chekhov_patched', 'KEY'])
# Set up symbolic key groups
# Find path to 0x7f38 (success exit)
```

### Possible Validation Mechanisms
1. **Multi-step XOR:** Input XORed multiple times with different masks
2. **Rolling hash:** Each group depends on previous groups
3. **CRC/Checksum:** All 8 groups must satisfy a polynomial constraint
4. **Encryption:** Groups may be AES/RC4 encrypted before comparison

### Next Steps
1. Install angr and run symbolic execution targeting the success path
2. Use Frida to hook the comparison point and extract expected value
3. Trace memory writes during validation to understand data flow
4. Analyze the obfuscated VM-like code at 0x7ce0

---

## 14. Appendix

### A. Python Key Decoder
```python
def decode_base36(group: str) -> int:
    """Decode a 6-character base-36 group to integer."""
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    value = 0
    for c in group.upper():
        value = value * 36 + chars.index(c)
    return value

def encode_base36(value: int) -> str:
    """Encode an integer to 6-character base-36."""
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if value == 0:
        return '000000'
    result = ''
    while value > 0:
        result = chars[value % 36] + result
        value //= 36
    return result.zfill(6)

def parse_license_key(key: str) -> list[int]:
    """Parse a full license key into 8 integers."""
    groups = key.split('-')
    if len(groups) != 8:
        raise ValueError("Key must have 8 groups")
    return [decode_base36(g) for g in groups]
```

### B. Relevant Memory Addresses

| Address | Purpose |
|---------|---------|
| 0x6620 | Validation constants (8 x 32-bit) |
| 0x6680 | Possible XOR mask (8 x 32-bit) |
| 0x68a0 | Character lookup table (43 x 32-bit) |
| 0x1a3550 | Global state structure pointer |
| +0x1a0 | Parsed key values array (8 x 32-bit) |
| +0x20 | XORshift PRNG state |

### C. Command to Run
```bash
# On Linux, set capabilities first:
sudo setcap 'cap_dac_read_search=ep cap_sys_ptrace=ep' ./chekhov

# Run with key:
./chekhov "CHPN9K-78FYQX-QAU5OU-MNNYUL-RWIM8Q-XXXXXX-AVUAHE-INFC49"
```

---

**Document Version:** 3.0
**Last Updated:** 2025-12-28
