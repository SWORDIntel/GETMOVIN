"""Local Orientation Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.utils import execute_command, execute_powershell, execute_cmd


class OrientationModule:
    """Module for local orientation and understanding the beachhead"""
    
    def run(self, console: Console, session_data: dict):
        """Run orientation module"""
        while True:
            console.print(Panel(
                "[bold]Local Orientation[/bold]\n\n"
                "Understand identity, host role, and network visibility from beachhead.",
                title="Module 2",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Identity & Privilege Mapping")
            table.add_row("2", "Host Role Classification")
            table.add_row("3", "Network Visibility Assessment")
            table.add_row("4", "Service Account Discovery")
            table.add_row("5", "Scheduled Task Analysis")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._identity_mapping(console, session_data)
            elif choice == '2':
                self._host_classification(console, session_data)
            elif choice == '3':
                self._network_visibility(console, session_data)
            elif choice == '4':
                self._service_accounts(console, session_data)
            elif choice == '5':
                self._scheduled_tasks(console, session_data)
            
            console.print()
    
    def _identity_mapping(self, console: Console, session_data: dict):
        """Map identities and privileges"""
        console.print("\n[bold cyan]Identity & Privilege Mapping[/bold cyan]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        commands = [
            ("whoami /all", "Complete identity information"),
            ("net localgroup", "All local groups"),
            ("net localgroup administrators", "Local administrators"),
            ("net localgroup \"Remote Desktop Users\"", "RDP users"),
            ("net group /domain", "Domain groups (if domain joined)"),
            ("net group \"Domain Admins\" /domain", "Domain admins"),
            ("net group \"Enterprise Admins\" /domain", "Enterprise admins"),
        ]
        
        table = Table(title="[bold]Identity Mapping Commands[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in commands:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        console.print("[bold]Key Questions:[/bold]")
        questions = [
            "Local admin or SYSTEM-level rights?",
            "Membership in privileged domain groups?",
            "Which service accounts exist?",
            "Services running as domain users?",
            "Scheduled tasks using domain credentials?"
        ]
        
        for q in questions:
            console.print(f"  • {q}")
        
        if is_live or Confirm.ask("\n[bold]Execute identity mapping?[/bold]", default=is_live):
            console.print("\n[yellow]Executing commands...[/yellow]\n")
            
            # Execute whoami /all
            exit_code, stdout, stderr = execute_cmd("whoami /all", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Identity Information:[/green]\n{stdout[:500]}...")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Execute net localgroup administrators
            exit_code, stdout, stderr = execute_cmd("net localgroup administrators", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"\n[green]Local Administrators:[/green]\n{stdout}")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
    
    def _host_classification(self, console: Console, session_data: dict):
        """Classify host role"""
        console.print("\n[bold cyan]Host Role Classification[/bold cyan]\n")
        
        checks = {
            "Server Roles": [
                "Get-WindowsFeature | Where-Object Installed",
                "Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled'"
            ],
            "Listening Ports": [
                "netstat -ano | findstr LISTENING",
                "Get-NetTCPConnection | Where-Object State -eq 'Listen'"
            ],
            "Services": [
                "Get-Service | Where-Object Status -eq 'Running'",
                "Get-WmiObject Win32_Service | Select-Object Name, StartName, PathName"
            ],
            "Processes": [
                "Get-Process | Select-Object ProcessName, Path, Company",
                "Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath"
            ],
            "Software": [
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
                "Get-WmiObject Win32_Product | Select-Object Name, Version"
            ]
        }
        
        for category, cmds in checks.items():
            console.print(f"[bold]{category}:[/bold]")
            for cmd in cmds:
                console.print(f"  • {cmd}")
            console.print()
        
        console.print("[bold]Role Indicators:[/bold]")
        roles = {
            "Domain Controller": "AD DS role, LDAP (389), Kerberos (88), DNS (53)",
            "File Server": "File Server role, SMB (445), DFS",
            "Web Server": "IIS, HTTP (80), HTTPS (443)",
            "Database Server": "SQL Server (1433), MySQL (3306), PostgreSQL (5432)",
            "Management Server": "WinRM (5985/5986), RDP (3389), SCCM",
            "Backup Server": "Veeam, Backup Exec, DPM",
            "Hypervisor": "Hyper-V, VMware, Citrix"
        }
        
        for role, indicators in roles.items():
            console.print(f"  • [cyan]{role}:[/cyan] {indicators}")
    
    def _network_visibility(self, console: Console, session_data: dict):
        """Assess network visibility"""
        console.print("\n[bold cyan]Network Visibility Assessment[/bold cyan]\n")
        
        console.print("[bold]Network Configuration:[/bold]")
        config_cmds = [
            "ipconfig /all",
            "Get-NetIPAddress",
            "Get-NetRoute",
            "Get-DnsClientServerAddress"
        ]
        
        for cmd in config_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Network Discovery:[/bold]")
        discovery_cmds = [
            "arp -a",
            "Get-NetNeighbor",
            "nslookup <domain>",
            "Resolve-DnsName <domain>"
        ]
        
        for cmd in discovery_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Target Discovery:[/bold]")
        targets = {
            "Domain Controllers": "LDAP (389), Kerberos (88), DNS (53), SMB (445)",
            "File Servers": "SMB (445), DFS",
            "Management Systems": "WinRM (5985/5986), RDP (3389), WSUS",
            "Database Servers": "SQL (1433), MySQL (3306), PostgreSQL (5432)",
            "Backup Systems": "Veeam (9380), Backup Exec (6106), DPM",
            "Monitoring": "SNMP (161), WMI (135, 445)"
        }
        
        for target, ports in targets.items():
            console.print(f"  • [cyan]{target}:[/cyan] {ports}")
        
        console.print("\n[bold]Connectivity Testing:[/bold]")
        test_cmds = [
            "Test-NetConnection -ComputerName <target> -Port <port>",
            "Test-WSMan -ComputerName <target>",
            "Get-WmiObject -Class Win32_ComputerSystem -ComputerName <target>"
        ]
        
        for cmd in test_cmds:
            console.print(f"  • {cmd}")
    
    def _service_accounts(self, console: Console, session_data: dict):
        """Discover service accounts"""
        console.print("\n[bold cyan]Service Account Discovery[/bold cyan]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        commands = [
            ("Get-WmiObject Win32_Service | Select-Object Name, StartName, PathName", "All services with accounts"),
            ("Get-Service | Get-CimInstance | Select-Object Name, StartName", "Service accounts (CIM)"),
            ("Get-WmiObject Win32_Service | Where-Object {$_.StartName -like '*@*'} | Select-Object Name, StartName", "Domain service accounts"),
            ("Get-WmiObject Win32_Service | Where-Object {$_.StartName -eq 'LocalSystem'} | Select-Object Name", "SYSTEM services"),
        ]
        
        table = Table(title="[bold]Service Account Discovery[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in commands:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        console.print("[bold]Key Targets:[/bold]")
        targets = [
            "Services running as domain users",
            "Services with misconfigured permissions",
            "Services with unconstrained delegation",
            "Service accounts in privileged groups"
        ]
        
        for target in targets:
            console.print(f"  • {target}")
        
        if is_live or Confirm.ask("\n[bold]Discover service accounts?[/bold]", default=is_live):
            console.print("\n[yellow]Executing discovery...[/yellow]\n")
            
            ps_cmd = "Get-WmiObject Win32_Service | Where-Object {$_.StartName -like '*@*'} | Select-Object -First 20 Name, StartName, State"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Domain Service Accounts:[/green]\n{stdout}")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
    
    def _scheduled_tasks(self, console: Console, session_data: dict):
        """Analyze scheduled tasks"""
        console.print("\n[bold cyan]Scheduled Task Analysis[/bold cyan]\n")
        
        commands = [
            ("Get-ScheduledTask | Get-ScheduledTaskInfo", "All scheduled tasks"),
            ("Get-ScheduledTask | Where-Object {$_.Principal.UserId -like '*@*'} | Select-Object TaskName, Principal", "Domain account tasks"),
            ("schtasks /query /fo LIST /v", "Detailed task information"),
            ("Get-ScheduledTask | Select-Object TaskName, Actions, Principal, State", "Task details"),
        ]
        
        table = Table(title="[bold]Scheduled Task Analysis[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in commands:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        console.print("[bold]Look For:[/bold]")
        indicators = [
            "Tasks running as domain accounts",
            "Tasks with embedded credentials",
            "Tasks executing scripts from network shares",
            "Tasks with high privileges"
        ]
        
        for indicator in indicators:
            console.print(f"  • {indicator}")
