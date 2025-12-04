"""Foothold & Starting Point Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.utils import execute_command, execute_powershell, execute_cmd, validate_target, select_menu_option
from modules.loghunter_integration import WindowsMoonwalk


class FootholdModule:
    """Module for assessing SSH foothold and initial access"""
    
    def __init__(self):
        self.moonwalk = None
    
    def run(self, console: Console, session_data: dict):
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
        """Run foothold assessment"""
        while True:
            console.print(Panel(
                "[bold]Foothold Assessment[/bold]\n\n"
                "Assess your initial SSH access point on Windows host.\n"
                "[dim]Moonwalk: Auto-clearing logs and traces after each operation[/dim]",
                title="Module 1",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            menu_options = [
                {'key': '1', 'label': 'Who am I? (Identity & Privileges) [APT-41: Discovery]'},
                {'key': '2', 'label': 'What is this host? (Role Classification) [APT-41: Discovery]'},
                {'key': '3', 'label': 'What can this host see? (Network Visibility) [APT-41: Discovery]'},
                {'key': '4', 'label': 'APT-41 Initial Access Techniques'},
                {'key': '5', 'label': 'Generate foothold report'},
                {'key': '?', 'label': 'Module Guide - Usage instructions and TTPs'},
                {'key': '0', 'label': 'Return to main menu'},
            ]
            
            choice = select_menu_option(console, menu_options, "Select function", default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
            elif choice == '1':
                self._assess_identity(console, session_data)
            elif choice == '2':
                self._assess_host_role(console, session_data)
            elif choice == '3':
                self._assess_network_visibility(console, session_data)
            elif choice == '4':
                self._apt41_initial_access(console, session_data)
            elif choice == '5':
                self._generate_report(console, session_data)
            
            # Moonwalk cleanup after operations (enabled by default)
            if choice != '0':
                self._moonwalk_cleanup(console, 'execution')
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]Foothold & Starting Point Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Assess your initial SSH access point on Windows host and establish foothold.

[bold]Key Functions:[/bold]
1. Identity & Privileges - Check current user, groups, and privileges
2. Host Role Classification - Determine if host is workstation, server, or DC
3. Network Visibility - Discover network topology and reachable hosts
4. APT-41 Initial Access - Common initial access techniques
5. Generate Report - Create comprehensive foothold assessment report

[bold]MITRE ATT&CK TTPs:[/bold]
• T1078 - Valid Accounts
• T1087.001 - Account Discovery: Local Accounts
• T1087.002 - Account Discovery: Domain Accounts
• T1018 - Remote System Discovery
• T1082 - System Information Discovery
• T1059 - Command and Scripting Interpreter

[bold]Usage Tips:[/bold]
• Start with option 1 to understand your current privileges
• Use option 2 to identify high-value targets (DCs, file servers)
• Option 3 helps map the network for lateral movement planning
• Moonwalk automatically clears traces after each operation

[bold]Best Practices:[/bold]
• Document all findings for later reference
• Identify service accounts for potential privilege escalation
• Note network segments and firewall rules
• Check for security software before proceeding"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
    def _assess_identity(self, console: Console, session_data: dict):
        """Assess current identity and privileges"""
        console.print("\n[bold cyan]Identity & Privilege Assessment[/bold cyan]")
        console.print("[dim]TTP: T1078 (Valid Accounts), T1087.001 (Account Discovery: Local), T1087.002 (Account Discovery: Domain)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        commands = [
            ("whoami", "Current user identity"),
            ("whoami /groups", "Group memberships"),
            ("whoami /priv", "Privileges"),
            ("net localgroup administrators", "Local admin members"),
            ("net user %USERNAME%", "User account details"),
            ("net user", "All local users [APT-41]"),
            ("net group /domain", "Domain groups [APT-41]"),
            ("net group \"Domain Admins\" /domain", "Domain Admins [APT-41]"),
        ]
        
        table = Table(title="[bold]Recommended Commands[/bold]", box=box.ROUNDED)
        table.add_column("Command", style="cyan")
        table.add_column("Purpose", style="white")
        
        for cmd, purpose in commands:
            table.add_row(cmd, purpose)
        
        console.print(table)
        console.print()
        
        if is_live or Confirm.ask("[bold]Execute identity check?[/bold]", default=is_live):
            console.print("\n[yellow]Executing commands...[/yellow]\n")
            
            identity_data = {}
            
            # Execute whoami
            exit_code, stdout, stderr = execute_cmd("whoami", lab_use=lab_use)
            if exit_code == 0:
                user = stdout.strip()
                console.print(f"[green]whoami:[/green] {user}")
                identity_data['user'] = user
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Execute whoami /groups
            exit_code, stdout, stderr = execute_cmd("whoami /groups", lab_use=lab_use)
            if exit_code == 0:
                groups = [line.strip() for line in stdout.split('\n') if 'Group Name' in line or 'S-1-5' in line]
                console.print(f"[green]Groups:[/green] {len(groups)} groups found")
                identity_data['groups'] = groups[:10]  # Store first 10
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Execute whoami /priv
            exit_code, stdout, stderr = execute_cmd("whoami /priv", lab_use=lab_use)
            if exit_code == 0:
                privs = [line.strip() for line in stdout.split('\n') if 'Se' in line]
                console.print(f"[green]Privileges:[/green] {len(privs)} privileges found")
                identity_data['privileges'] = privs[:10]  # Store first 10
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Execute net localgroup administrators
            exit_code, stdout, stderr = execute_cmd("net localgroup administrators", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Local Administrators:[/green] Retrieved")
                identity_data['local_admins'] = stdout
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # APT-41: Check for service accounts
            exit_code, stdout, stderr = execute_cmd("net user", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Local users:[/green] Retrieved")
                identity_data['local_users'] = stdout
            
            # APT-41: Domain account discovery
            exit_code, stdout, stderr = execute_cmd("net group /domain", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Domain groups:[/green] Retrieved")
                identity_data['domain_groups'] = stdout
            
            session_data['identity'] = identity_data
            console.print("\n[green]✓ Identity data stored in session[/green]")
            console.print("\n[bold]TTP Context:[/bold]")
            console.print("  • T1078 (Valid Accounts): Current account may be used for lateral movement")
            console.print("  • T1087 (Account Discovery): Identify high-value accounts for pivoting")
            console.print("  • Focus on service accounts and domain admin memberships")
    
    def _assess_host_role(self, console: Console, session_data: dict):
        """Assess host role and classification"""
        console.print("\n[bold cyan]Host Role Classification[/bold cyan]")
        console.print("[dim]TTP: T1082 (System Information Discovery), T1018 (Remote System Discovery)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        checks = [
            ("Get-WindowsFeature | Where-Object Installed", "Installed server roles"),
            ("netstat -ano | findstr LISTENING", "Listening services"),
            ("Get-Service | Where-Object Status -eq 'Running'", "Running services"),
            ("Get-Process | Select-Object ProcessName, Path", "Running processes"),
            ("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion", "System info"),
            ("systeminfo", "System information [APT-41]"),
            ("Get-WmiObject Win32_ComputerSystem", "Computer system details [APT-41]"),
            ("Get-WmiObject Win32_OperatingSystem", "OS version and details [APT-41]"),
            ("Get-WmiObject Win32_Product", "Installed software [APT-41]"),
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
        
        if is_live or Confirm.ask("\n[bold]Execute host role checks?[/bold]", default=is_live):
            console.print("\n[yellow]Executing checks...[/yellow]\n")
            
            # Check listening ports
            exit_code, stdout, stderr = execute_cmd("netstat -ano | findstr LISTENING", lab_use=lab_use)
            if exit_code == 0:
                ports = {}
                for line in stdout.split('\n'):
                    if 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            addr = parts[1]
                            if ':' in addr:
                                port = addr.split(':')[-1]
                                ports[port] = ports.get(port, 0) + 1
                
                console.print(f"[green]Listening ports found:[/green] {len(ports)} unique ports")
                session_data['listening_ports'] = list(ports.keys())[:20]  # Store first 20
            
            # Check running services
            ps_cmd = "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 20 Name, DisplayName"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Running services:[/green] Retrieved")
            
            # Auto-classify based on ports
            role = "Unknown"
            if 'listening_ports' in session_data:
                ports = session_data['listening_ports']
                if '389' in ports or '88' in ports or '53' in ports:
                    role = "Domain Controller"
                elif '445' in ports:
                    role = "File Server"
                elif '80' in ports or '443' in ports:
                    role = "Web Server"
                elif '1433' in ports or '3306' in ports or '5432' in ports:
                    role = "Database Server"
                elif '5985' in ports or '5986' in ports or '3389' in ports:
                    role = "Management Server"
            
            if not is_live:
                role = Prompt.ask("Host role", choices=[
                    "Domain Controller", "File Server", "Web Server", 
                    "Database Server", "Management Server", "Workstation", "Other"
                ], default=role)
            
            # APT-41: System information discovery
            exit_code, stdout, stderr = execute_cmd("systeminfo", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]System information:[/green] Retrieved")
                session_data['system_info'] = stdout[:500]  # Store first 500 chars
            
            # APT-41: Installed software discovery
            ps_cmd = "Get-WmiObject Win32_Product | Select-Object -First 20 Name, Version, Vendor"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Installed software:[/green] Retrieved")
                session_data['installed_software'] = stdout
            
            session_data['host_role'] = role
            console.print(f"\n[green]✓ Host classified as: {role}[/green]")
            console.print("\n[bold]TTP Context:[/bold]")
            console.print("  • T1082 (System Information Discovery): Understanding host role")
            console.print("  • T1018 (Remote System Discovery): Identify high-value targets")
            console.print("  • Focus: DCs, backup servers, management systems, file servers")
    
    def _assess_network_visibility(self, console: Console, session_data: dict):
        """Assess network visibility from foothold"""
        console.print("\n[bold cyan]Network Visibility Assessment[/bold cyan]")
        console.print("[dim]TTP: T1018 (Remote System Discovery), T1135 (Network Share Discovery), T1021.004 (SSH)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        is_local_ip = session_data.get('is_local_ip', lambda x: False)
        
        commands = [
            ("ipconfig /all", "Network configuration"),
            ("route print", "Routing table"),
            ("arp -a", "ARP cache"),
            ("nslookup <domain>", "DNS resolution"),
            ("Test-NetConnection -ComputerName <target> -Port <port>", "Port connectivity"),
            ("net view /domain", "Domain network discovery [APT-41]"),
            ("net view /domain:<domain>", "Domain computer list [APT-41]"),
            ("nltest /dclist:<domain>", "Domain controller discovery [APT-41]"),
            ("for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i", "Network scanning [APT-41]"),
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
        
        if is_live or Confirm.ask("\n[bold]Perform network discovery?[/bold]", default=is_live):
            console.print("\n[yellow]Executing network discovery...[/yellow]\n")
            
            network_data = {}
            
            # Get network configuration
            exit_code, stdout, stderr = execute_cmd("ipconfig /all", lab_use=lab_use)
            if exit_code == 0:
                console.print("[green]Network configuration:[/green] Retrieved")
                # Extract IP addresses
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, stdout)
                local_ips = [ip for ip in ips if is_local_ip(ip)]
                if local_ips:
                    network_data['local_ips'] = list(set(local_ips))
                    console.print(f"[green]Local IPs found:[/green] {', '.join(network_data['local_ips'][:5])}")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Get routing table
            exit_code, stdout, stderr = execute_cmd("route print", lab_use=lab_use)
            if exit_code == 0:
                console.print("[green]Routing table:[/green] Retrieved")
                # Extract subnets
                import re
                subnet_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                subnets = re.findall(subnet_pattern, stdout)
                if subnets:
                    network_data['subnets'] = subnets[:5]
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # Get ARP cache
            exit_code, stdout, stderr = execute_cmd("arp -a", lab_use=lab_use)
            if exit_code == 0:
                console.print("[green]ARP cache:[/green] Retrieved")
                # Extract IPs from ARP
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                arp_ips = re.findall(ip_pattern, stdout)
                local_arp_ips = [ip for ip in arp_ips if is_local_ip(ip)]
                if local_arp_ips:
                    network_data['arp_targets'] = list(set(local_arp_ips))[:10]
                    console.print(f"[green]ARP targets:[/green] {len(network_data['arp_targets'])} local IPs")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
            
            # If LAB_USE=1, only show local IPs
            if lab_use == 1:
                console.print("\n[yellow]LAB MODE: Only local IP ranges shown[/yellow]")
            
            # APT-41: Domain network discovery
            exit_code, stdout, stderr = execute_cmd("net view /domain", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Domain networks:[/green] Retrieved")
                network_data['domains'] = stdout
            
            # APT-41: Domain controller discovery
            exit_code, stdout, stderr = execute_cmd("nltest /dclist:", lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Domain controllers:[/green] Retrieved")
                network_data['domain_controllers'] = stdout
            
            session_data['network'] = network_data
            console.print("\n[green]✓ Network data stored[/green]")
            console.print("\n[bold]TTP Context:[/bold]")
            console.print("  • T1018 (Remote System Discovery): Enumerate reachable hosts")
            console.print("  • T1135 (Network Share Discovery): Identify accessible shares")
            console.print("  • T1021.004 (SSH): Current foothold via SSH on Windows")
            console.print("  • Prioritize: DCs, file servers, management systems for lateral movement")
    
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
    
    def _apt41_initial_access(self, console: Console, session_data: dict):
        """Initial Access & Authentication Techniques"""
        console.print("\n[bold cyan]Initial Access & Authentication[/bold cyan]")
        console.print("[dim]TTP: T1078 (Valid Accounts), T1550 (Use Alternate Authentication Material), T1021.004 (SSH)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        techniques = {
            "T1078 - Valid Accounts": [
                "Use compromised domain/local/service accounts",
                "Service account abuse for lateral movement",
                "Default credentials exploitation",
                "Credential reuse across systems",
                "Stolen credentials from previous breaches"
            ],
            "T1550 - Alternate Authentication Material": [
                "Pass-the-Hash (PtH) - NTLM hash reuse",
                "Pass-the-Ticket (PtT) - Kerberos ticket reuse",
                "Pass-the-Token - Token manipulation",
                "Golden Ticket creation",
                "Silver Ticket creation"
            ],
            "T1021.004 - SSH": [
                "Headless SSH service on Windows host",
                "SSH key-based authentication",
                "SSH tunneling for port forwarding",
                "SSH as persistent control channel",
                "Use SSH for file transfer and command execution"
            ]
        }
        
        for technique, methods in techniques.items():
            console.print(f"[bold]{technique}:[/bold]")
            for method in methods:
                console.print(f"  • {method}")
            console.print()
        
        console.print("\n[bold]Authentication Material Usage:[/bold]")
        auth_material = [
            "T1550.002 (Pass-the-Hash): Use NTLM hashes for SMB/WinRM",
            "T1550.003 (Pass-the-Ticket): Reuse Kerberos tickets",
            "T1078.001 (Domain Accounts): Use domain credentials",
            "T1078.002 (Domain Accounts): Use local accounts",
            "T1078.003 (Local Accounts): Use service accounts"
        ]
        
        for material in auth_material:
            console.print(f"  • {material}")
        
        console.print("\n[bold]SSH Foothold Characteristics (T1021.004):[/bold]")
        ssh_chars = [
            "Persistent encrypted control channel",
            "Bound to Windows service account",
            "Ability to execute commands and scripts",
            "File transfer in/out capability",
            "Use as relay point for port forwarding",
            "Effective power depends on account privileges"
        ]
        
        for char in ssh_chars:
            console.print(f"  • {char}")
        
        if is_live or Confirm.ask("\n[bold]Check for APT-41 indicators?[/bold]", default=False):
            console.print("\n[yellow]Checking for APT-41 indicators...[/yellow]\n")
            
            # Check for suspicious scheduled tasks
            ps_cmd = "Get-ScheduledTask | Where-Object {$_.TaskName -like '*update*' -or $_.TaskName -like '*maintenance*'} | Select-Object TaskName, State, Actions"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Suspicious scheduled tasks:[/green]\n{stdout}")
            
            # Check for WMI event subscriptions
            ps_cmd = "Get-WmiObject -Namespace root\\subscription -Class __EventFilter"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]WMI event subscriptions:[/green]\n{stdout}")
            
            # Check for DLL sideloading opportunities
            ps_cmd = "Get-ChildItem -Path C:\\Windows\\System32 -Filter *.exe | Select-Object -First 10 Name"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]Potential DLL sideloading targets:[/green]\n{stdout}")
