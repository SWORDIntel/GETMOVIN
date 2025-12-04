"""Auto-Enumeration Module - Comprehensive Automated Enumeration"""

import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import box
from modules.utils import execute_cmd, execute_powershell, validate_target


class AutoEnumerator:
    """Automated enumeration engine"""
    
    def __init__(self, console: Console, session_data: dict):
        self.console = console
        self.session_data = session_data
        self.enumeration_data = {
            'timestamp': datetime.now().isoformat(),
            'foothold': {},
            'orientation': {},
            'identity': {},
            'network': {},
            'credentials': {},
            'lateral_targets': [],
            'persistence': {},
            'certificates': {},
            'lolbins_used': []
        }
        self.lab_use = session_data.get('LAB_USE', 0)
    
    def run_full_enumeration(self) -> Dict[str, Any]:
        """Run complete enumeration across all modules"""
        self.console.print(Panel(
            "[bold]AUTO-ENUMERATION MODE[/bold]\n\n"
            "Running comprehensive enumeration across all modules...",
            title="Auto-Enumeration",
            border_style="cyan"
        ))
        self.console.print()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            # Foothold enumeration
            task1 = progress.add_task("[cyan]Foothold Assessment...", total=100)
            self._enumerate_foothold(progress, task1)
            
            # Orientation enumeration
            task2 = progress.add_task("[cyan]Local Orientation...", total=100)
            self._enumerate_orientation(progress, task2)
            
            # Identity enumeration
            task3 = progress.add_task("[cyan]Identity Acquisition...", total=100)
            self._enumerate_identity(progress, task3)
            
            # Network enumeration
            task4 = progress.add_task("[cyan]Network Discovery...", total=100)
            self._enumerate_network(progress, task4)
            
            # Lateral movement targets
            task5 = progress.add_task("[cyan]Lateral Movement Targets...", total=100)
            self._enumerate_lateral_targets(progress, task5)
            
            # Persistence enumeration
            task6 = progress.add_task("[cyan]Persistence Mechanisms...", total=100)
            self._enumerate_persistence(progress, task6)
            
            # Certificate enumeration (if MADCert available)
            task7 = progress.add_task("[cyan]Certificate Enumeration...", total=100)
            self._enumerate_certificates(progress, task7)
        
        return self.enumeration_data
    
    def _enumerate_foothold(self, progress, task):
        """Enumerate foothold information"""
        try:
            # Identity
            progress.update(task, advance=10, description="[cyan]Identity check...")
            exit_code, stdout, stderr = execute_cmd("whoami", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['foothold']['identity'] = stdout.strip()
            
            progress.update(task, advance=10, description="[cyan]Group memberships...")
            exit_code, stdout, stderr = execute_cmd("whoami /groups", lab_use=self.lab_use)
            if exit_code == 0:
                groups = [line.strip() for line in stdout.split('\n') if 'Group Name' in line or 'S-1-5' in line]
                self.enumeration_data['foothold']['groups'] = groups[:20]
            
            progress.update(task, advance=10, description="[cyan]Privileges...")
            exit_code, stdout, stderr = execute_cmd("whoami /priv", lab_use=self.lab_use)
            if exit_code == 0:
                privs = [line.strip() for line in stdout.split('\n') if 'Se' in line]
                self.enumeration_data['foothold']['privileges'] = privs[:20]
            
            # Host role
            progress.update(task, advance=20, description="[cyan]Host role classification...")
            exit_code, stdout, stderr = execute_cmd("netstat -ano | findstr LISTENING", lab_use=self.lab_use)
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
                self.enumeration_data['foothold']['listening_ports'] = list(ports.keys())[:30]
                
                # Classify role
                if '389' in ports or '88' in ports:
                    self.enumeration_data['foothold']['role'] = 'Domain Controller'
                elif '445' in ports:
                    self.enumeration_data['foothold']['role'] = 'File Server'
                elif '80' in ports or '443' in ports:
                    self.enumeration_data['foothold']['role'] = 'Web Server'
                elif '5985' in ports or '5986' in ports:
                    self.enumeration_data['foothold']['role'] = 'Management Server'
                else:
                    self.enumeration_data['foothold']['role'] = 'Workstation/Other'
            
            # System info
            progress.update(task, advance=20, description="[cyan]System information...")
            exit_code, stdout, stderr = execute_cmd("systeminfo", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['foothold']['system_info'] = stdout[:1000]
            
            progress.update(task, advance=30, description="[green]Foothold enumeration complete")
        
        except Exception as e:
            self.enumeration_data['foothold']['error'] = str(e)
    
    def _enumerate_orientation(self, progress, task):
        """Enumerate local orientation"""
        try:
            # Local groups
            progress.update(task, advance=15, description="[cyan]Local groups...")
            exit_code, stdout, stderr = execute_cmd("net localgroup", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['orientation']['local_groups'] = stdout
            
            # Local administrators
            progress.update(task, advance=10, description="[cyan]Local administrators...")
            exit_code, stdout, stderr = execute_cmd("net localgroup administrators", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['orientation']['local_admins'] = stdout
            
            # Domain groups (if domain joined)
            progress.update(task, advance=15, description="[cyan]Domain groups...")
            exit_code, stdout, stderr = execute_cmd("net group /domain", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['orientation']['domain_groups'] = stdout.split('\n')[:50]
            
            # Service accounts
            progress.update(task, advance=20, description="[cyan]Service accounts...")
            ps_cmd = "Get-WmiObject Win32_Service | Where-Object {$_.StartName -like '*@*'} | Select-Object -First 30 Name, StartName, State"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['orientation']['service_accounts'] = stdout
            
            # Scheduled tasks
            progress.update(task, advance=20, description="[cyan]Scheduled tasks...")
            ps_cmd = "Get-ScheduledTask | Select-Object -First 30 TaskName, State, Actions"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['orientation']['scheduled_tasks'] = stdout
            
            # Security software
            progress.update(task, advance=20, description="[cyan]Security software...")
            ps_cmd = "Get-Process | Where-Object {$_.ProcessName -match 'defender|security|av|firewall'} | Select-Object ProcessName, Id"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['orientation']['security_software'] = stdout
            
            progress.update(task, advance=100, description="[green]Orientation enumeration complete")
        
        except Exception as e:
            self.enumeration_data['orientation']['error'] = str(e)
    
    def _enumerate_identity(self, progress, task):
        """Enumerate identity and credentials"""
        try:
            # Credential stores
            progress.update(task, advance=25, description="[cyan]Credential stores...")
            exit_code, stdout, stderr = execute_cmd("cmdkey /list", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['identity']['stored_credentials'] = stdout
            
            # Vault
            progress.update(task, advance=25, description="[cyan]Windows Vault...")
            exit_code, stdout, stderr = execute_cmd("vaultcmd /list", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['identity']['vault_credentials'] = stdout
            
            # Domain context
            progress.update(task, advance=25, description="[cyan]Domain context...")
            exit_code, stdout, stderr = execute_cmd("net group \"Domain Admins\" /domain", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['identity']['domain_admins'] = stdout
            
            # LSASS process
            progress.update(task, advance=25, description="[cyan]LSASS process...")
            ps_cmd = "Get-Process lsass -ErrorAction SilentlyContinue | Select-Object Id, ProcessName"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['identity']['lsass_process'] = stdout
            
            progress.update(task, advance=100, description="[green]Identity enumeration complete")
        
        except Exception as e:
            self.enumeration_data['identity']['error'] = str(e)
    
    def _enumerate_network(self, progress, task):
        """Enumerate network information"""
        try:
            # Network configuration
            progress.update(task, advance=20, description="[cyan]Network configuration...")
            exit_code, stdout, stderr = execute_cmd("ipconfig /all", lab_use=self.lab_use)
            if exit_code == 0:
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, stdout)
                is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
                local_ips = [ip for ip in ips if is_local_ip(ip)]
                self.enumeration_data['network']['local_ips'] = list(set(local_ips))[:10]
                self.enumeration_data['network']['ipconfig'] = stdout[:500]
            
            # ARP cache
            progress.update(task, advance=20, description="[cyan]ARP cache...")
            exit_code, stdout, stderr = execute_cmd("arp -a", lab_use=self.lab_use)
            if exit_code == 0:
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                arp_ips = re.findall(ip_pattern, stdout)
                is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
                local_arp_ips = [ip for ip in arp_ips if is_local_ip(ip)]
                self.enumeration_data['network']['arp_targets'] = list(set(local_arp_ips))[:20]
            
            # Domain networks
            progress.update(task, advance=20, description="[cyan]Domain networks...")
            exit_code, stdout, stderr = execute_cmd("net view /domain", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['network']['domains'] = stdout
            
            # Domain controllers
            progress.update(task, advance=20, description="[cyan]Domain controllers...")
            exit_code, stdout, stderr = execute_cmd("nltest /dclist:", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['network']['domain_controllers'] = stdout
            
            # Network shares
            progress.update(task, advance=20, description="[cyan]Network shares...")
            exit_code, stdout, stderr = execute_cmd("net share", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['network']['local_shares'] = stdout
            
            progress.update(task, advance=100, description="[green]Network enumeration complete")
        
        except Exception as e:
            self.enumeration_data['network']['error'] = str(e)
    
    def _enumerate_lateral_targets(self, progress, task):
        """Enumerate potential lateral movement targets"""
        try:
            targets = []
            
            # Get network targets from ARP
            if 'arp_targets' in self.enumeration_data.get('network', {}):
                arp_targets = self.enumeration_data['network'].get('arp_targets', [])
                targets.extend(arp_targets[:10])
            
            # Test connectivity to targets
            progress.update(task, advance=30, description="[cyan]Testing target connectivity...")
            tested_targets = []
            for target in targets[:10]:  # Limit to 10 targets
                if not isinstance(target, str):
                    continue
                try:
                    # Test SMB
                    exit_code, stdout, stderr = execute_cmd(f"net view \\\\{target}", lab_use=self.lab_use)
                    if exit_code == 0:
                        self.enumeration_data['lateral_targets'].append({
                            'target': target,
                            'smb_accessible': True,
                            'shares': stdout[:200]
                        })
                    
                    # Test WinRM
                    ps_cmd = f"Test-WSMan -ComputerName {target} -ErrorAction SilentlyContinue"
                    exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
                    if exit_code == 0:
                        # Update existing target or create new
                        found = False
                        for t in self.enumeration_data['lateral_targets']:
                            if isinstance(t, dict) and t.get('target') == target:
                                t['winrm_accessible'] = True
                                found = True
                                break
                        if not found:
                            self.enumeration_data['lateral_targets'].append({
                                'target': target,
                                'winrm_accessible': True
                            })
                
                except Exception:
                    continue
                
                tested_targets.append(target)
            
            progress.update(task, advance=70, description="[green]Lateral targets enumeration complete")
        
        except Exception as e:
            self.enumeration_data['lateral_targets'] = {'error': str(e)}
    
    def _enumerate_persistence(self, progress, task):
        """Enumerate persistence mechanisms"""
        try:
            # Scheduled tasks
            progress.update(task, advance=25, description="[cyan]Scheduled tasks...")
            ps_cmd = "Get-ScheduledTask | Get-ScheduledTaskInfo | Where-Object {$_.LastRunTime -gt (Get-Date).AddDays(-30)} | Select-Object TaskName, State, LastRunTime"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['persistence']['recent_tasks'] = stdout
            
            # Services
            progress.update(task, advance=25, description="[cyan]Services...")
            ps_cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 30 Name, DisplayName, Status"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['persistence']['services'] = stdout
            
            # WMI event subscriptions
            progress.update(task, advance=25, description="[cyan]WMI event subscriptions...")
            ps_cmd = "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select-Object Name, Query"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['persistence']['wmi_subscriptions'] = stdout
            
            # Registry run keys
            progress.update(task, advance=25, description="[cyan]Registry run keys...")
            exit_code, stdout, stderr = execute_cmd("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['persistence']['registry_run_hkcu'] = stdout
            
            exit_code, stdout, stderr = execute_cmd("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['persistence']['registry_run_hklm'] = stdout
            
            progress.update(task, advance=100, description="[green]Persistence enumeration complete")
        
        except Exception as e:
            self.enumeration_data['persistence']['error'] = str(e)
    
    def _enumerate_certificates(self, progress, task):
        """Enumerate certificates (if MADCert available)"""
        try:
            from modules.madcert_integration import MADCertGenerator
            madcert_gen = MADCertGenerator(self.console, self.session_data)
            certs = madcert_gen.list_certificates()
            
            if certs:
                self.enumeration_data['certificates']['generated_certs'] = [
                    {
                        'name': c['name'],
                        'type': c['type'],
                        'ca': c.get('ca_name', 'N/A'),
                        'validity_days': c.get('validity_days', 0)
                    }
                    for c in certs
                ]
            
            progress.update(task, advance=100, description="[green]Certificate enumeration complete")
        
        except Exception:
            self.enumeration_data['certificates']['status'] = 'MADCert not available'
            progress.update(task, advance=100)


class ReportGenerator:
    """Generate comprehensive enumeration reports"""
    
    def __init__(self, console: Console, enumeration_data: Dict[str, Any]):
        self.console = console
        self.data = enumeration_data
    
    def generate_text_report(self) -> str:
        """Generate text report"""
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE ENUMERATION REPORT")
        report.append(f"Generated: {self.data['timestamp']}")
        report.append("=" * 80)
        report.append("")
        
        # Foothold
        report.append("FOOTHOLD ASSESSMENT")
        report.append("-" * 80)
        if 'foothold' in self.data:
            fh = self.data['foothold']
            report.append(f"Identity: {fh.get('identity', 'Unknown')}")
            report.append(f"Role: {fh.get('role', 'Unknown')}")
            report.append(f"Groups: {len(fh.get('groups', []))} groups found")
            report.append(f"Privileges: {len(fh.get('privileges', []))} privileges")
            report.append(f"Listening Ports: {len(fh.get('listening_ports', []))} ports")
            if fh.get('listening_ports'):
                report.append(f"  Ports: {', '.join(fh['listening_ports'][:10])}")
        report.append("")
        
        # Orientation
        report.append("LOCAL ORIENTATION")
        report.append("-" * 80)
        if 'orientation' in self.data:
            orient = self.data['orientation']
            report.append(f"Local Groups: Found")
            report.append(f"Local Admins: Found")
            report.append(f"Domain Groups: {len(orient.get('domain_groups', []))} groups")
            report.append(f"Service Accounts: Found")
            report.append(f"Scheduled Tasks: Found")
            report.append(f"Security Software: Found")
        report.append("")
        
        # Identity
        report.append("IDENTITY & CREDENTIALS")
        report.append("-" * 80)
        if 'identity' in self.data:
            ident = self.data['identity']
            report.append(f"Stored Credentials: {'Found' if ident.get('stored_credentials') else 'None'}")
            report.append(f"Vault Credentials: {'Found' if ident.get('vault_credentials') else 'None'}")
            report.append(f"Domain Admins: {'Found' if ident.get('domain_admins') else 'None'}")
            report.append(f"LSASS Process: {'Found' if ident.get('lsass_process') else 'Not found'}")
        report.append("")
        
        # Network
        report.append("NETWORK DISCOVERY")
        report.append("-" * 80)
        if 'network' in self.data:
            net = self.data['network']
            report.append(f"Local IPs: {len(net.get('local_ips', []))} IPs")
            if net.get('local_ips'):
                report.append(f"  IPs: {', '.join(net['local_ips'][:5])}")
            report.append(f"ARP Targets: {len(net.get('arp_targets', []))} targets")
            report.append(f"Domains: {'Found' if net.get('domains') else 'None'}")
            report.append(f"Domain Controllers: {'Found' if net.get('domain_controllers') else 'None'}")
            report.append(f"Local Shares: {'Found' if net.get('local_shares') else 'None'}")
        report.append("")
        
        # Lateral Targets
        report.append("LATERAL MOVEMENT TARGETS")
        report.append("-" * 80)
        if 'lateral_targets' in self.data:
            targets = self.data['lateral_targets']
            if isinstance(targets, list):
                report.append(f"Potential Targets: {len(targets)}")
                for target in targets[:10]:
                    if isinstance(target, dict):
                        report.append(f"  - {target.get('target', 'Unknown')}: SMB={target.get('smb_accessible', False)}, WinRM={target.get('winrm_accessible', False)}")
            else:
                report.append("Potential Targets: 0")
        else:
            report.append("Potential Targets: 0")
        report.append("")
        
        # Persistence
        report.append("PERSISTENCE MECHANISMS")
        report.append("-" * 80)
        if 'persistence' in self.data:
            persist = self.data['persistence']
            report.append(f"Recent Tasks: {'Found' if persist.get('recent_tasks') else 'None'}")
            report.append(f"Services: {'Found' if persist.get('services') else 'None'}")
            report.append(f"WMI Subscriptions: {'Found' if persist.get('wmi_subscriptions') else 'None'}")
            report.append(f"Registry Run Keys: {'Found' if persist.get('registry_run_hkcu') or persist.get('registry_run_hklm') else 'None'}")
        report.append("")
        
        # Certificates
        report.append("CERTIFICATES")
        report.append("-" * 80)
        if 'certificates' in self.data:
            certs = self.data['certificates']
            if certs.get('generated_certs'):
                report.append(f"Generated Certificates: {len(certs['generated_certs'])}")
                for cert in certs['generated_certs']:
                    report.append(f"  - {cert['name']} ({cert['type']})")
            else:
                report.append("Generated Certificates: None")
        report.append("")
        
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return '\n'.join(report)
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        return json.dumps(self.data, indent=2, default=str)
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html><head><title>Enumeration Report</title>")
        html.append("<style>body{font-family:Arial;margin:20px;}h1{color:#333;}h2{border-bottom:2px solid #333;padding-bottom:5px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background-color:#4CAF50;color:white;}</style>")
        html.append("</head><body>")
        html.append(f"<h1>Comprehensive Enumeration Report</h1>")
        html.append(f"<p><strong>Generated:</strong> {self.data['timestamp']}</p>")
        
        # Foothold
        html.append("<h2>Foothold Assessment</h2>")
        if 'foothold' in self.data:
            fh = self.data['foothold']
            html.append(f"<p><strong>Identity:</strong> {fh.get('identity', 'Unknown')}</p>")
            html.append(f"<p><strong>Role:</strong> {fh.get('role', 'Unknown')}</p>")
            html.append(f"<p><strong>Groups:</strong> {len(fh.get('groups', []))} groups</p>")
            html.append(f"<p><strong>Listening Ports:</strong> {len(fh.get('listening_ports', []))} ports</p>")
        
        # Network
        html.append("<h2>Network Discovery</h2>")
        if 'network' in self.data:
            net = self.data['network']
            html.append(f"<p><strong>Local IPs:</strong> {len(net.get('local_ips', []))}</p>")
            html.append(f"<p><strong>ARP Targets:</strong> {len(net.get('arp_targets', []))}</p>")
        
        # Lateral Targets
        html.append("<h2>Lateral Movement Targets</h2>")
        if 'lateral_targets' in self.data:
            targets = self.data['lateral_targets']
            if targets and isinstance(targets, list):
                html.append("<table><tr><th>Target</th><th>SMB</th><th>WinRM</th></tr>")
                for target in targets[:10]:
                    if isinstance(target, dict):
                        html.append(f"<tr><td>{target.get('target', 'Unknown')}</td>")
                        html.append(f"<td>{'Yes' if target.get('smb_accessible') else 'No'}</td>")
                        html.append(f"<td>{'Yes' if target.get('winrm_accessible') else 'No'}</td></tr>")
                html.append("</table>")
            else:
                html.append("<p>No targets found</p>")
        
        html.append("</body></html>")
        return '\n'.join(html)
    
    def display_report(self):
        """Display report in console"""
        self.console.print("\n[bold cyan]ENUMERATION REPORT[/bold cyan]\n")
        
        # Summary table
        table = Table(title="Enumeration Summary", box=box.ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Items Found", style="green")
        
        # Foothold
        fh = self.data.get('foothold', {})
        table.add_row("Foothold", "Complete", f"{len(fh.get('groups', []))} groups, {len(fh.get('listening_ports', []))} ports")
        
        # Orientation
        orient = self.data.get('orientation', {})
        table.add_row("Orientation", "Complete", "Service accounts, tasks, security software")
        
        # Identity
        ident = self.data.get('identity', {})
        cred_count = sum([1 for k in ['stored_credentials', 'vault_credentials', 'domain_admins'] if ident.get(k)])
        table.add_row("Identity", "Complete", f"{cred_count} credential sources")
        
        # Network
        net = self.data.get('network', {})
        table.add_row("Network", "Complete", f"{len(net.get('local_ips', []))} IPs, {len(net.get('arp_targets', []))} targets")
        
        # Lateral Targets
        targets = self.data.get('lateral_targets', [])
        target_count = len(targets) if isinstance(targets, list) else 0
        table.add_row("Lateral Targets", "Complete", f"{target_count} targets")
        
        # Persistence
        persist = self.data.get('persistence', {})
        persist_count = sum([1 for k in ['recent_tasks', 'services', 'wmi_subscriptions'] if persist.get(k)])
        table.add_row("Persistence", "Complete", f"{persist_count} mechanisms")
        
        self.console.print(table)
        self.console.print()


class AutoEnumerateModule:
    """Auto-Enumeration Module for TUI"""
    
    def run(self, console: Console, session_data: dict):
        """Run auto-enumeration"""
        enumerator = AutoEnumerator(console, session_data)
        
        console.print("\n[bold yellow]Starting comprehensive enumeration...[/bold yellow]\n")
        
        # Run enumeration
        enumeration_data = enumerator.run_full_enumeration()
        
        # Generate report
        report_gen = ReportGenerator(console, enumeration_data)
        report_gen.display_report()
        
        # Export options
        console.print("\n[bold]Export Options:[/bold]\n")
        
        export_format = Prompt.ask(
            "Export format",
            choices=['text', 'json', 'html', 'all', 'none'],
            default='all'
        )
        
        if export_format != 'none':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if export_format in ['text', 'all']:
                text_report = report_gen.generate_text_report()
                filename = f"enumeration_report_{timestamp}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text_report)
                console.print(f"[green]Text report saved:[/green] {filename}")
            
            if export_format in ['json', 'all']:
                json_report = report_gen.generate_json_report()
                filename = f"enumeration_report_{timestamp}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(json_report)
                console.print(f"[green]JSON report saved:[/green] {filename}")
            
            if export_format in ['html', 'all']:
                html_report = report_gen.generate_html_report()
                filename = f"enumeration_report_{timestamp}.html"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_report)
                console.print(f"[green]HTML report saved:[/green] {filename}")
        
        console.print("\n[green]Enumeration complete![/green]")
