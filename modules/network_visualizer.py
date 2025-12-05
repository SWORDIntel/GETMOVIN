"""Network Visualization Module

Sophisticated network visualization and exploration tool for lateral movement.
Provides interactive network mapping, host discovery, credential mapping, and path visualization.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.layout import Layout
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich import box
from rich.live import Live
from rich.columns import Columns
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
from modules.utils import execute_cmd, execute_powershell
from modules.credential_manager import get_credential_manager, CredentialType


@dataclass
class NetworkHost:
    """Represents a network host"""
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    services: Dict[str, List[int]] = field(default_factory=dict)  # protocol -> ports
    credentials: List[str] = field(default_factory=list)  # credential IDs
    accessible: bool = False
    access_methods: List[str] = field(default_factory=list)  # smb, winrm, ssh, etc.
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""
    
    def __hash__(self):
        return hash(self.ip)
    
    def __eq__(self, other):
        return isinstance(other, NetworkHost) and self.ip == other.ip


@dataclass
class NetworkPath:
    """Represents a lateral movement path"""
    source: str
    target: str
    method: str  # smb, winrm, wmi, ssh, etc.
    credentials_used: Optional[str] = None
    hops: List[str] = field(default_factory=list)  # Intermediate hops
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class NetworkVisualizer:
    """Network visualization and exploration engine"""
    
    def __init__(self, console: Console, session_data: dict):
        self.console = console
        self.session_data = session_data
        self.hosts: Dict[str, NetworkHost] = {}  # ip -> Host
        self.paths: List[NetworkPath] = []
        self.cred_manager = get_credential_manager()
        self.lab_use = session_data.get('LAB_USE', 0)
        self.current_focus: Optional[str] = None  # Currently focused host IP
    
    def discover_local_network(self) -> List[str]:
        """Discover local network hosts"""
        self.console.print("[cyan]Discovering local network...[/cyan]")
        
        discovered_ips = set()
        
        # Get local IP configuration
        exit_code, stdout, stderr = execute_cmd("ipconfig /all", lab_use=self.lab_use)
        if exit_code == 0:
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, stdout)
            is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
            local_ips = [ip for ip in ips if is_local_ip(ip)]
            discovered_ips.update(local_ips)
        
        # ARP cache
        exit_code, stdout, stderr = execute_cmd("arp -a", lab_use=self.lab_use)
        if exit_code == 0:
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            arp_ips = re.findall(ip_pattern, stdout)
            is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
            local_arp_ips = [ip for ip in arp_ips if is_local_ip(ip)]
            discovered_ips.update(local_arp_ips)
        
        # Net view (domain/workgroup)
        exit_code, stdout, stderr = execute_cmd("net view", lab_use=self.lab_use)
        if exit_code == 0:
            # Extract hostnames/IPs from net view output
            lines = stdout.split('\n')
            for line in lines:
                if '\\\\' in line:
                    hostname = line.split('\\\\')[1].split()[0] if '\\\\' in line else None
                    if hostname:
                        discovered_ips.add(hostname)
        
        return list(discovered_ips)
    
    def scan_host(self, target: str) -> NetworkHost:
        """Scan a host and populate host information"""
        if target in self.hosts:
            host = self.hosts[target]
        else:
            host = NetworkHost(ip=target)
            self.hosts[target] = host
        
        self.console.print(f"[cyan]Scanning {target}...[/cyan]")
        
        # Try to resolve hostname
        try:
            exit_code, stdout, stderr = execute_cmd(f"nslookup {target}", lab_use=self.lab_use)
            if exit_code == 0 and "Name:" in stdout:
                hostname_line = [l for l in stdout.split('\n') if 'Name:' in l]
                if hostname_line:
                    host.hostname = hostname_line[0].split('Name:')[1].strip()
        except Exception:
            pass
        
        # Test SMB
        exit_code, stdout, stderr = execute_cmd(f"net view \\\\{target}", lab_use=self.lab_use)
        if exit_code == 0:
            host.accessible = True
            host.access_methods.append("smb")
            host.services["smb"] = [445]
            # Try to enumerate shares
            shares = []
            for line in stdout.split('\n'):
                if 'Disk' in line or 'Print' in line:
                    share_name = line.split()[0] if line.split() else None
                    if share_name:
                        shares.append(share_name)
            if shares:
                host.notes = f"Shares: {', '.join(shares[:5])}"
        
        # Test WinRM
        ps_cmd = f"Test-WSMan -ComputerName {target} -ErrorAction SilentlyContinue"
        exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
        if exit_code == 0:
            host.accessible = True
            if "winrm" not in host.access_methods:
                host.access_methods.append("winrm")
            host.services["winrm"] = [5985, 5986]
        
        # Test RDP (check if port 3389 is open)
        exit_code, stdout, stderr = execute_cmd(f"powershell -Command \"Test-NetConnection -ComputerName {target} -Port 3389 -InformationLevel Quiet\"", lab_use=self.lab_use)
        if exit_code == 0 and "True" in stdout:
            if "rdp" not in host.access_methods:
                host.access_methods.append("rdp")
            host.services["rdp"] = [3389]
        
        # Get credentials for this host
        creds = self.cred_manager.get_credentials_by_target(target)
        host.credentials = [c.id for c in creds]
        
        # Try to get OS info via WMI
        ps_cmd = f"Get-WmiObject -Class Win32_OperatingSystem -ComputerName {target} -ErrorAction SilentlyContinue | Select-Object Caption, Version"
        exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
        if exit_code == 0 and stdout:
            host.os = stdout.strip()[:50]
        
        return host
    
    def visualize_network(self):
        """Create interactive network visualization"""
        while True:
            self.console.clear()
            
            # Create layout
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="main"),
                Layout(name="footer", size=3)
            )
            
            layout["main"].split_row(
                Layout(name="hosts", ratio=2),
                Layout(name="details", ratio=1)
            )
            
            # Header
            header_text = Text()
            header_text.append("Network Visualization & Exploration", style="bold cyan")
            header_text.append(" | ", style="dim")
            header_text.append(f"Hosts: {len(self.hosts)}", style="green")
            header_text.append(" | ", style="dim")
            header_text.append(f"Paths: {len(self.paths)}", style="yellow")
            layout["header"] = Panel(header_text, border_style="cyan")
            
            # Hosts panel
            hosts_table = Table(title="Discovered Hosts", box=box.ROUNDED, show_header=True)
            hosts_table.add_column("IP/Hostname", style="cyan", width=20)
            hosts_table.add_column("OS", style="white", width=25)
            hosts_table.add_column("Access", style="green", width=15)
            hosts_table.add_column("Services", style="yellow", width=20)
            hosts_table.add_column("Creds", style="magenta", width=6)
            hosts_table.add_column("Status", style="green" if True else "red", width=8)
            
            for ip, host in sorted(self.hosts.items()):
                hostname_display = host.hostname or ip
                access_display = ", ".join(host.access_methods[:3]) if host.access_methods else "None"
                services_display = ", ".join([f"{k}:{','.join(map(str, v[:2]))}" for k, v in list(host.services.items())[:2]])
                cred_count = len(host.credentials)
                status = "✓" if host.accessible else "?"
                
                hosts_table.add_row(
                    hostname_display,
                    host.os[:25] if host.os else "Unknown",
                    access_display,
                    services_display[:20],
                    str(cred_count),
                    status
                )
            
            layout["hosts"] = Panel(hosts_table, border_style="cyan")
            
            # Details panel
            if self.current_focus and self.current_focus in self.hosts:
                host = self.hosts[self.current_focus]
                details_tree = Tree(f"[bold cyan]{host.ip}[/bold cyan]")
                
                if host.hostname:
                    details_tree.add(f"[white]Hostname:[/white] {host.hostname}")
                if host.domain:
                    details_tree.add(f"[white]Domain:[/white] {host.domain}")
                if host.os:
                    details_tree.add(f"[white]OS:[/white] {host.os}")
                
                access_branch = details_tree.add("[green]Access Methods[/green]")
                for method in host.access_methods:
                    access_branch.add(f"[yellow]{method}[/yellow]")
                
                services_branch = details_tree.add("[yellow]Services[/yellow]")
                for protocol, ports in host.services.items():
                    services_branch.add(f"[cyan]{protocol}[/cyan]: {', '.join(map(str, ports))}")
                
                if host.credentials:
                    creds_branch = details_tree.add(f"[magenta]Credentials ({len(host.credentials)})[/magenta]")
                    for cred_id in host.credentials[:5]:
                        cred = self.cred_manager.get_credential(cred_id)
                        if cred:
                            creds_branch.add(f"[white]{cred.username}@{cred.domain or 'local'}[/white]")
                
                if host.notes:
                    details_tree.add(f"[dim]{host.notes}[/dim]")
                
                layout["details"] = Panel(details_tree, title="Host Details", border_style="green")
            else:
                layout["details"] = Panel(
                    "[dim]Select a host to view details[/dim]",
                    title="Host Details",
                    border_style="dim"
                )
            
            # Footer with commands
            footer_text = Text()
            footer_text.append("[bold]Commands:[/bold] ", style="cyan")
            footer_text.append("(d)iscover ", style="yellow")
            footer_text.append("(s)can ", style="yellow")
            footer_text.append("(c)onnect ", style="yellow")
            footer_text.append("(p)ath ", style="yellow")
            footer_text.append("(e)xport ", style="yellow")
            footer_text.append("(q)uit", style="yellow")
            layout["footer"] = Panel(footer_text, border_style="dim")
            
            self.console.print(layout)
            
            # Get user command
            command = Prompt.ask("\n[bold cyan]Command[/bold cyan]", choices=['d', 's', 'c', 'p', 'e', 'q', 'select'], default='q')
            
            if command == 'q':
                break
            elif command == 'd':
                self._discover_network()
            elif command == 's':
                self._scan_target()
            elif command == 'c':
                self._connect_to_host()
            elif command == 'p':
                self._show_paths()
            elif command == 'e':
                self._export_network_map()
            elif command == 'select':
                self._select_host()
    
    def _discover_network(self):
        """Discover network hosts"""
        self.console.print("\n[bold cyan]Network Discovery[/bold cyan]")
        
        discovery_type = Prompt.ask(
            "Discovery method",
            choices=['local', 'arp', 'net_view', 'custom_range'],
            default='local'
        )
        
        if discovery_type == 'local':
            ips = self.discover_local_network()
            self.console.print(f"[green]Discovered {len(ips)} potential hosts[/green]")
            
            if Confirm.ask("Scan discovered hosts?", default=True):
                for ip in ips[:20]:  # Limit to 20
                    try:
                        self.scan_host(ip)
                    except Exception:
                        continue
        
        elif discovery_type == 'arp':
            exit_code, stdout, stderr = execute_cmd("arp -a", lab_use=self.lab_use)
            if exit_code == 0:
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, stdout)
                is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
                local_ips = [ip for ip in ips if is_local_ip(ip)]
                
                self.console.print(f"[green]Found {len(local_ips)} IPs in ARP cache[/green]")
                if Confirm.ask("Scan ARP hosts?", default=True):
                    for ip in set(local_ips)[:20]:
                        try:
                            self.scan_host(ip)
                        except Exception:
                            continue
        
        elif discovery_type == 'net_view':
            exit_code, stdout, stderr = execute_cmd("net view", lab_use=self.lab_use)
            if exit_code == 0:
                hosts = []
                for line in stdout.split('\n'):
                    if '\\\\' in line:
                        hostname = line.split('\\\\')[1].split()[0] if '\\\\' in line else None
                        if hostname:
                            hosts.append(hostname)
                
                self.console.print(f"[green]Found {len(hosts)} hosts in net view[/green]")
                if Confirm.ask("Scan net view hosts?", default=True):
                    for hostname in hosts[:20]:
                        try:
                            self.scan_host(hostname)
                        except Exception:
                            continue
        
        elif discovery_type == 'custom_range':
            ip_range = Prompt.ask("IP range (e.g., 192.168.1.0/24 or 192.168.1.1-254)")
            if '/' in ip_range:
                # CIDR notation
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    ips = [str(ip) for ip in network.hosts()][:50]  # Limit to 50
                    self.console.print(f"[green]Scanning {len(ips)} IPs...[/green]")
                    for ip in ips:
                        try:
                            self.scan_host(ip)
                        except Exception:
                            continue
                except Exception as e:
                    self.console.print(f"[red]Invalid CIDR: {e}[/red]")
    
    def _scan_target(self):
        """Scan a specific target"""
        target = Prompt.ask("Target IP or hostname")
        if target:
            host = self.scan_host(target)
            self.console.print(f"[green]Scan complete for {target}[/green]")
            self.current_focus = target
    
    def _select_host(self):
        """Select a host to focus on"""
        if not self.hosts:
            self.console.print("[yellow]No hosts discovered yet[/yellow]")
            return
        
        host_list = list(self.hosts.keys())
        for i, ip in enumerate(host_list, 1):
            host = self.hosts[ip]
            display = f"{i}. {host.hostname or ip} ({', '.join(host.access_methods) if host.access_methods else 'no access'})"
            self.console.print(display)
        
        choice = Prompt.ask("Select host number", choices=[str(i) for i in range(1, len(host_list) + 1)], default='1')
        self.current_focus = host_list[int(choice) - 1]
        self.console.print(f"[green]Focused on {self.current_focus}[/green]")
    
    def _connect_to_host(self):
        """Connect to a host using stored credentials"""
        if not self.current_focus or self.current_focus not in self.hosts:
            self.console.print("[yellow]Select a host first[/yellow]")
            return
        
        host = self.hosts[self.current_focus]
        
        if not host.access_methods:
            self.console.print("[yellow]No access methods available for this host[/yellow]")
            return
        
        method = Prompt.ask("Access method", choices=host.access_methods, default=host.access_methods[0])
        
        # Get credentials
        creds = [self.cred_manager.get_credential(cid) for cid in host.credentials if self.cred_manager.get_credential(cid)]
        password_creds = [c for c in creds if c and c.cred_type == CredentialType.PASSWORD.value and c.password]
        
        if password_creds:
            cred = password_creds[0]
            self.console.print(f"[cyan]Using credential: {cred.username}@{cred.domain or 'local'}[/cyan]")
            
            if method == 'smb':
                cmd = f'net use \\\\{host.ip}\\C$ /user:{cred.domain or ""}\\{cred.username} {cred.password}'
                self.console.print(f"[yellow]Executing: {cmd}[/yellow]")
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    self.console.print(f"[green]Connected via SMB[/green]")
                    # Create path
                    self.paths.append(NetworkPath(
                        source="local",
                        target=host.ip,
                        method="smb",
                        credentials_used=cred.id
                    ))
                else:
                    self.console.print(f"[red]Connection failed: {stderr}[/red]")
            
            elif method == 'winrm':
                ps_cmd = f"$cred = New-Object System.Management.Automation.PSCredential('{cred.domain or ''}\\{cred.username}', (ConvertTo-SecureString '{cred.password}' -AsPlainText -Force)); Invoke-Command -ComputerName {host.ip} -Credential $cred -ScriptBlock {{ whoami }}"
                self.console.print(f"[yellow]Executing WinRM command...[/yellow]")
                exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    self.console.print(f"[green]Connected via WinRM[/green]\n{stdout}")
                    self.paths.append(NetworkPath(
                        source="local",
                        target=host.ip,
                        method="winrm",
                        credentials_used=cred.id
                    ))
                else:
                    self.console.print(f"[red]Connection failed: {stderr}[/red]")
        else:
            self.console.print("[yellow]No password credentials available for this host[/yellow]")
    
    def _show_paths(self):
        """Show lateral movement paths"""
        if not self.paths:
            self.console.print("[yellow]No paths recorded yet[/yellow]")
            return
        
        paths_table = Table(title="Lateral Movement Paths", box=box.ROUNDED)
        paths_table.add_column("Source", style="cyan")
        paths_table.add_column("Target", style="green")
        paths_table.add_column("Method", style="yellow")
        paths_table.add_column("Credential", style="magenta")
        paths_table.add_column("Time", style="dim")
        
        for path in self.paths:
            cred_display = "N/A"
            if path.credentials_used:
                cred = self.cred_manager.get_credential(path.credentials_used)
                if cred:
                    cred_display = f"{cred.username}@{cred.domain or 'local'}"
            
            time_display = datetime.fromisoformat(path.timestamp).strftime("%H:%M:%S")
            
            paths_table.add_row(
                path.source,
                path.target,
                path.method,
                cred_display,
                time_display
            )
        
        self.console.print(paths_table)
        Prompt.ask("\nPress Enter to continue", default="")
    
    def _export_network_map(self):
        """Export network map"""
        export_format = Prompt.ask("Export format", choices=['json', 'text', 'mermaid'], default='text')
        
        if export_format == 'text':
            output = []
            output.append("=" * 80)
            output.append("NETWORK MAP")
            output.append(f"Generated: {datetime.now().isoformat()}")
            output.append("=" * 80)
            output.append("")
            
            output.append("HOSTS:")
            output.append("-" * 80)
            for ip, host in sorted(self.hosts.items()):
                output.append(f"\n{host.hostname or ip} ({ip})")
                output.append(f"  OS: {host.os or 'Unknown'}")
                output.append(f"  Access: {', '.join(host.access_methods) if host.access_methods else 'None'}")
                output.append(f"  Services: {', '.join([f'{k}:{v}' for k, v in host.services.items()])}")
                output.append(f"  Credentials: {len(host.credentials)}")
            
            output.append("\nPATHS:")
            output.append("-" * 80)
            for path in self.paths:
                output.append(f"{path.source} -> {path.target} via {path.method}")
            
            output_text = "\n".join(output)
            filename = f"network_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(output_text)
            self.console.print(f"[green]Network map exported to {filename}[/green]")
        
        elif export_format == 'mermaid':
            # Generate Mermaid diagram
            mermaid = []
            mermaid.append("graph TD")
            
            # Add nodes
            for ip, host in self.hosts.items():
                node_id = ip.replace('.', '_')
                label = host.hostname or ip
                style = "fill:#90EE90" if host.accessible else "fill:#FFB6C1"
                mermaid.append(f"    {node_id}[\"{label}\"]")
            
            # Add edges (paths)
            for path in self.paths:
                source_id = path.source.replace('.', '_')
                target_id = path.target.replace('.', '_')
                mermaid.append(f"    {source_id} -->|{path.method}| {target_id}")
            
            mermaid_text = "\n".join(mermaid)
            filename = f"network_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mmd"
            with open(filename, 'w') as f:
                f.write(mermaid_text)
            self.console.print(f"[green]Mermaid diagram exported to {filename}[/green]")
