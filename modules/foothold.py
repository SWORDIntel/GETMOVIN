"""Foothold & Starting Point Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console


class FootholdModule:
    """Module for assessing SSH foothold and initial access"""
    
    def run(self, console: Console, session_data: dict):
        """Run foothold assessment"""
        while True:
            console.print(Panel(
                "[bold]Foothold Assessment[/bold]\n\n"
                "Assess your initial SSH access point on Windows host.",
                title="Module 1",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Who am I? (Identity & Privileges)")
            table.add_row("2", "What is this host? (Role Classification)")
            table.add_row("3", "What can this host see? (Network Visibility)")
            table.add_row("4", "Generate foothold report")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._assess_identity(console, session_data)
            elif choice == '2':
                self._assess_host_role(console, session_data)
            elif choice == '3':
                self._assess_network_visibility(console, session_data)
            elif choice == '4':
                self._generate_report(console, session_data)
            
            console.print()
    
    def _assess_identity(self, console: Console, session_data: dict):
        """Assess current identity and privileges"""
        console.print("\n[bold cyan]Identity & Privilege Assessment[/bold cyan]\n")
        
        # Simulate commands
        commands = [
            ("whoami", "Current user identity"),
            ("whoami /groups", "Group memberships"),
            ("whoami /priv", "Privileges"),
            ("net localgroup administrators", "Local admin members"),
            ("net user %USERNAME%", "User account details"),
        ]
        
        table = Table(title="[bold]Recommended Commands[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in commands:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        if Confirm.ask("[bold]Execute identity check?[/bold]", default=False):
            console.print("\n[yellow]Simulating execution...[/yellow]")
            console.print("[dim]whoami:[/dim] WIN-SRV-01\\svc_ssh")
            console.print("[dim]Groups:[/dim] Domain Users, Local Administrators")
            console.print("[dim]Privileges:[/dim] SeDebugPrivilege, SeImpersonatePrivilege")
            
            session_data['identity'] = {
                'user': 'WIN-SRV-01\\svc_ssh',
                'groups': ['Domain Users', 'Local Administrators'],
                'privileges': ['SeDebugPrivilege', 'SeImpersonatePrivilege']
            }
            console.print("\n[green]✓ Identity data stored in session[/green]")
    
    def _assess_host_role(self, console: Console, session_data: dict):
        """Assess host role and classification"""
        console.print("\n[bold cyan]Host Role Classification[/bold cyan]\n")
        
        checks = [
            ("Get-WindowsFeature | Where-Object Installed", "Installed server roles"),
            ("netstat -ano | findstr LISTENING", "Listening services"),
            ("Get-Service | Where-Object Status -eq 'Running'", "Running services"),
            ("Get-Process | Select-Object ProcessName, Path", "Running processes"),
            ("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion", "System info"),
        ]
        
        table = Table(title="[bold]Host Role Checks[/bold]", box=box.ROUNDED)
        table.add_column("Check", style="cyan")
        table.add_column("Purpose", style="white")
        
        for check, purpose in checks:
            table.add_row(check, purpose)
        
        console.print(table)
        console.print()
        
        console.print("[bold]Key Indicators:[/bold]")
        indicators = [
            "Domain Controller: AD DS role, LDAP (389), Kerberos (88)",
            "File Server: SMB (445), File Server role",
            "Web Server: IIS, HTTP/HTTPS ports",
            "Database Server: SQL Server, MySQL, PostgreSQL ports",
            "Management Server: WinRM (5985/5986), RDP (3389)"
        ]
        
        for indicator in indicators:
            console.print(f"  • {indicator}")
        
        if Confirm.ask("\n[bold]Classify host role?[/bold]", default=False):
            role = Prompt.ask("Host role", choices=[
                "Domain Controller", "File Server", "Web Server", 
                "Database Server", "Management Server", "Workstation", "Other"
            ], default="Management Server")
            
            session_data['host_role'] = role
            console.print(f"\n[green]✓ Host classified as: {role}[/green]")
    
    def _assess_network_visibility(self, console: Console, session_data: dict):
        """Assess network visibility from foothold"""
        console.print("\n[bold cyan]Network Visibility Assessment[/bold cyan]\n")
        
        commands = [
            ("ipconfig /all", "Network configuration"),
            ("route print", "Routing table"),
            ("arp -a", "ARP cache"),
            ("nslookup <domain>", "DNS resolution"),
            ("Test-NetConnection -ComputerName <target> -Port <port>", "Port connectivity"),
        ]
        
        table = Table(title="[bold]Network Discovery Commands[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in commands:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        console.print("[bold]Target Discovery:[/bold]")
        targets = [
            "Domain Controllers: LDAP, Kerberos, DNS",
            "File Servers: SMB (445)",
            "Management Systems: WinRM (5985/5986), RDP (3389)",
            "Database Servers: SQL (1433), MySQL (3306)",
            "Backup Systems: Veeam, Backup Exec ports"
        ]
        
        for target in targets:
            console.print(f"  • {target}")
        
        if Confirm.ask("\n[bold]Perform network scan?[/bold]", default=False):
            console.print("\n[yellow]Simulating network discovery...[/yellow]")
            console.print("[dim]Subnet:[/dim] 192.168.1.0/24")
            console.print("[dim]DC Found:[/dim] 192.168.1.10 (LDAP, Kerberos)")
            console.print("[dim]File Server:[/dim] 192.168.1.20 (SMB)")
            console.print("[dim]Management:[/dim] 192.168.1.30 (WinRM)")
            
            session_data['network'] = {
                'subnet': '192.168.1.0/24',
                'targets': ['192.168.1.10', '192.168.1.20', '192.168.1.30']
            }
            console.print("\n[green]✓ Network data stored[/green]")
    
    def _generate_report(self, console: Console, session_data: dict):
        """Generate foothold assessment report"""
        console.print("\n[bold cyan]Foothold Assessment Report[/bold cyan]\n")
        
        report = []
        report.append("[bold]FOOTHOLD ASSESSMENT REPORT[/bold]\n")
        
        if 'identity' in session_data:
            report.append(f"Identity: {session_data['identity'].get('user', 'Unknown')}")
            report.append(f"Groups: {', '.join(session_data['identity'].get('groups', []))}")
        else:
            report.append("Identity: [dim]Not assessed[/dim]")
        
        if 'host_role' in session_data:
            report.append(f"Host Role: {session_data['host_role']}")
        else:
            report.append("Host Role: [dim]Not assessed[/dim]")
        
        if 'network' in session_data:
            report.append(f"Network: {session_data['network'].get('subnet', 'Unknown')}")
            report.append(f"Targets: {', '.join(session_data['network'].get('targets', []))}")
        else:
            report.append("Network: [dim]Not assessed[/dim]")
        
        panel = Panel("\n".join(report), title="Report", border_style="green")
        console.print(panel)
