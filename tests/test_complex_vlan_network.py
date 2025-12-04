#!/usr/bin/env python3
"""Complex VLAN Network Enumeration Test

This test emulates a realistic enterprise network with:
- Multiple VLANs (Management, Servers, Users, DMZ, IoT, Guest)
- 20+ machines across different network segments
- Switches and routers
- Proper network segmentation
- Depth-based enumeration to find all machines

Run with: python3 tests/test_complex_vlan_network.py
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

from modules.auto_enumerate import AutoEnumerator, ReportGenerator
from modules.diagram_generator import DiagramGenerator
from modules.utils import is_local_ip


class VLANNetwork:
    """
    Complex Enterprise Network with VLANs
    
    Network Architecture:
    =====================
    
    [Internet] ─── [Firewall] ─── [Core Router]
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
              [L3 Switch 1]      [L3 Switch 2]      [L3 Switch 3]
                    │                  │                  │
         ┌─────────┼─────────┐        │         ┌───────┼───────┐
         │         │         │        │         │       │       │
      VLAN 10   VLAN 20   VLAN 30  VLAN 40   VLAN 50  VLAN 60  VLAN 100
      (Mgmt)   (Servers) (Users)   (DMZ)     (IoT)  (Guest)  (Security)
    
    VLAN Configuration:
    - VLAN 10 (10.10.10.0/24): Management - Network devices, jump hosts
    - VLAN 20 (10.10.20.0/24): Servers - Domain controllers, file servers, databases
    - VLAN 30 (10.10.30.0/24): Users - Workstations, laptops
    - VLAN 40 (10.10.40.0/24): DMZ - Web servers, mail servers, proxy
    - VLAN 50 (10.10.50.0/24): IoT - Cameras, sensors, printers
    - VLAN 60 (10.10.60.0/24): Guest - Guest WiFi devices
    - VLAN 100 (10.10.100.0/24): Security - SIEM, vulnerability scanners
    """
    
    def __init__(self):
        self.vlans = {
            10: {'name': 'Management', 'subnet': '10.10.10.0/24', 'gateway': '10.10.10.1'},
            20: {'name': 'Servers', 'subnet': '10.10.20.0/24', 'gateway': '10.10.20.1'},
            30: {'name': 'Users', 'subnet': '10.10.30.0/24', 'gateway': '10.10.30.1'},
            40: {'name': 'DMZ', 'subnet': '10.10.40.0/24', 'gateway': '10.10.40.1'},
            50: {'name': 'IoT', 'subnet': '10.10.50.0/24', 'gateway': '10.10.50.1'},
            60: {'name': 'Guest', 'subnet': '10.10.60.0/24', 'gateway': '10.10.60.1'},
            100: {'name': 'Security', 'subnet': '10.10.100.0/24', 'gateway': '10.10.100.1'},
        }
        
        # Network infrastructure devices
        self.infrastructure = {
            '10.10.10.1': {
                'hostname': 'CORE-RTR01',
                'type': 'Router',
                'os': 'Cisco IOS XE 17.3',
                'role': 'Core Router',
                'vlan': 10,
                'ports': ['Gi0/0', 'Gi0/1', 'Gi0/2'],
                'routing_protocols': ['OSPF', 'BGP'],
            },
            '10.10.10.2': {
                'hostname': 'L3-SW01',
                'type': 'L3 Switch',
                'os': 'Cisco IOS 15.2',
                'role': 'Distribution Switch',
                'vlan': 10,
                'ports': 48,
                'vlans_trunked': [10, 20, 30],
            },
            '10.10.10.3': {
                'hostname': 'L3-SW02',
                'type': 'L3 Switch',
                'os': 'Cisco IOS 15.2',
                'role': 'Distribution Switch',
                'vlan': 10,
                'ports': 48,
                'vlans_trunked': [40, 50, 60],
            },
            '10.10.10.4': {
                'hostname': 'L3-SW03',
                'type': 'L3 Switch',
                'os': 'Cisco IOS 15.2',
                'role': 'Distribution Switch',
                'vlan': 10,
                'ports': 24,
                'vlans_trunked': [100],
            },
        }
        
        # All machines organized by VLAN
        self.machines = {}
        
        # VLAN 10 - Management
        self.machines.update({
            '10.10.10.10': {
                'hostname': 'JUMP-HOST01',
                'fqdn': 'jump01.corp.local',
                'os': 'Windows Server 2022',
                'role': 'Jump Host',
                'vlan': 10,
                'listening_ports': ['22', '3389', '5985', '5986'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'AdminTools'],
                'services': ['SSH', 'RDP', 'WinRM'],
                'domain': 'CORP',
            },
            '10.10.10.11': {
                'hostname': 'ANSIBLE-CTL01',
                'fqdn': 'ansible01.corp.local',
                'os': 'Ubuntu 22.04 LTS',
                'role': 'Automation Server',
                'vlan': 10,
                'listening_ports': ['22', '443'],
                'smb_accessible': False,
                'winrm_accessible': False,
                'ssh_accessible': True,
                'services': ['Ansible', 'SSH'],
            },
        })
        
        # VLAN 20 - Servers
        self.machines.update({
            '10.10.20.10': {
                'hostname': 'DC01',
                'fqdn': 'DC01.corp.local',
                'os': 'Windows Server 2022',
                'role': 'Primary Domain Controller',
                'vlan': 20,
                'listening_ports': ['53', '88', '135', '389', '445', '464', '636', '3268', '3269', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['SYSVOL', 'NETLOGON', 'C$', 'ADMIN$'],
                'services': ['ActiveDirectory', 'DNS', 'Kerberos', 'LDAP'],
                'domain': 'CORP',
                'is_dc': True,
                'fsmo_roles': ['PDC', 'RID', 'Infrastructure'],
            },
            '10.10.20.11': {
                'hostname': 'DC02',
                'fqdn': 'DC02.corp.local',
                'os': 'Windows Server 2022',
                'role': 'Secondary Domain Controller',
                'vlan': 20,
                'listening_ports': ['53', '88', '135', '389', '445', '464', '636', '3268', '3269', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['SYSVOL', 'NETLOGON', 'C$', 'ADMIN$'],
                'services': ['ActiveDirectory', 'DNS', 'Kerberos', 'LDAP'],
                'domain': 'CORP',
                'is_dc': True,
                'fsmo_roles': ['Schema', 'Naming'],
            },
            '10.10.20.20': {
                'hostname': 'SQL-PROD01',
                'fqdn': 'sql-prod01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Production SQL Server',
                'vlan': 20,
                'listening_ports': ['135', '445', '1433', '1434', '5022', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'SQLBackups', 'SQLData'],
                'services': ['MSSQLSERVER', 'SQLSERVERAGENT', 'AlwaysOn'],
                'domain': 'CORP',
                'databases': ['ERP_Production', 'HR_System', 'Finance_DB'],
            },
            '10.10.20.21': {
                'hostname': 'SQL-DEV01',
                'fqdn': 'sql-dev01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Development SQL Server',
                'vlan': 20,
                'listening_ports': ['135', '445', '1433', '1434', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'DevBackups'],
                'services': ['MSSQLSERVER', 'SQLSERVERAGENT'],
                'domain': 'CORP',
                'databases': ['ERP_Dev', 'TestDB'],
            },
            '10.10.20.30': {
                'hostname': 'FILE01',
                'fqdn': 'file01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Primary File Server',
                'vlan': 20,
                'listening_ports': ['135', '139', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'UserHome', 'Departments', 'Public', 'Finance', 'HR', 'IT', 'Legal'],
                'services': ['LanmanServer', 'DFS'],
                'domain': 'CORP',
                'storage': '50TB',
            },
            '10.10.20.31': {
                'hostname': 'FILE02',
                'fqdn': 'file02.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Secondary File Server',
                'vlan': 20,
                'listening_ports': ['135', '139', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'Archives', 'Backup'],
                'services': ['LanmanServer', 'DFS-R'],
                'domain': 'CORP',
                'storage': '100TB',
            },
            '10.10.20.40': {
                'hostname': 'EXCH01',
                'fqdn': 'exch01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Exchange Server',
                'vlan': 20,
                'listening_ports': ['25', '80', '135', '443', '445', '587', '993', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$'],
                'services': ['MSExchangeIS', 'MSExchangeTransport', 'MSExchangeMailboxAssistants'],
                'domain': 'CORP',
            },
            '10.10.20.50': {
                'hostname': 'PRINT01',
                'fqdn': 'print01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Print Server',
                'vlan': 20,
                'listening_ports': ['135', '139', '445', '515', '631', '9100', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'print$'],
                'services': ['Spooler'],
                'domain': 'CORP',
                'printers': 25,
            },
        })
        
        # VLAN 30 - Users (Workstations)
        self.machines.update({
            '10.10.30.100': {
                'hostname': 'HR-WS001',
                'fqdn': 'hr-ws001.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'HR Workstation',
                'vlan': 30,
                'listening_ports': ['135', '139', '445'],
                'smb_accessible': True,
                'winrm_accessible': False,
                'shares': ['C$', 'ADMIN$'],
                'user': 'jsmith',
                'department': 'Human Resources',
                'domain': 'CORP',
            },
            '10.10.30.101': {
                'hostname': 'FIN-WS001',
                'fqdn': 'fin-ws001.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'Finance Workstation',
                'vlan': 30,
                'listening_ports': ['135', '139', '445'],
                'smb_accessible': True,
                'winrm_accessible': False,
                'shares': ['C$', 'ADMIN$'],
                'user': 'mwilson',
                'department': 'Finance',
                'domain': 'CORP',
            },
            '10.10.30.102': {
                'hostname': 'IT-WS001',
                'fqdn': 'it-ws001.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'IT Admin Workstation',
                'vlan': 30,
                'listening_ports': ['135', '139', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'AdminTools'],
                'user': 'admin.jones',
                'department': 'IT',
                'domain': 'CORP',
                'admin_workstation': True,
            },
            '10.10.30.103': {
                'hostname': 'DEV-WS001',
                'fqdn': 'dev-ws001.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'Developer Workstation',
                'vlan': 30,
                'listening_ports': ['135', '139', '445', '5985', '3000', '8080'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'Code'],
                'user': 'dev.user1',
                'department': 'Development',
                'domain': 'CORP',
            },
            '10.10.30.104': {
                'hostname': 'EXEC-WS001',
                'fqdn': 'exec-ws001.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'Executive Workstation',
                'vlan': 30,
                'listening_ports': ['135', '139', '445'],
                'smb_accessible': True,
                'winrm_accessible': False,
                'shares': ['C$', 'ADMIN$'],
                'user': 'ceo',
                'department': 'Executive',
                'domain': 'CORP',
                'high_value_target': True,
            },
        })
        
        # VLAN 40 - DMZ
        self.machines.update({
            '10.10.40.10': {
                'hostname': 'WEB-EXT01',
                'fqdn': 'www.corp.com',
                'os': 'Ubuntu 22.04 LTS',
                'role': 'External Web Server',
                'vlan': 40,
                'listening_ports': ['22', '80', '443'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['nginx', 'php-fpm'],
                'public_facing': True,
            },
            '10.10.40.11': {
                'hostname': 'WEB-EXT02',
                'fqdn': 'portal.corp.com',
                'os': 'Ubuntu 22.04 LTS',
                'role': 'Customer Portal',
                'vlan': 40,
                'listening_ports': ['22', '80', '443'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['nginx', 'nodejs'],
                'public_facing': True,
            },
            '10.10.40.20': {
                'hostname': 'MAIL-GW01',
                'fqdn': 'mail.corp.com',
                'os': 'Linux (Postfix)',
                'role': 'Mail Gateway',
                'vlan': 40,
                'listening_ports': ['22', '25', '465', '587', '993', '995'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['postfix', 'dovecot', 'spamassassin'],
                'public_facing': True,
            },
            '10.10.40.30': {
                'hostname': 'PROXY01',
                'fqdn': 'proxy.corp.local',
                'os': 'Linux (Squid)',
                'role': 'Web Proxy',
                'vlan': 40,
                'listening_ports': ['22', '3128', '8080'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['squid'],
            },
            '10.10.40.40': {
                'hostname': 'VPN-GW01',
                'fqdn': 'vpn.corp.com',
                'os': 'Linux (OpenVPN)',
                'role': 'VPN Gateway',
                'vlan': 40,
                'listening_ports': ['22', '443', '1194'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['openvpn'],
                'public_facing': True,
            },
        })
        
        # VLAN 50 - IoT
        self.machines.update({
            '10.10.50.10': {
                'hostname': 'CAM-LOBBY01',
                'type': 'IP Camera',
                'os': 'Embedded Linux',
                'role': 'Security Camera',
                'vlan': 50,
                'listening_ports': ['80', '443', '554'],
                'smb_accessible': False,
                'http_accessible': True,
                'location': 'Lobby',
            },
            '10.10.50.20': {
                'hostname': 'HVAC-CTL01',
                'type': 'HVAC Controller',
                'os': 'Embedded',
                'role': 'Building Automation',
                'vlan': 50,
                'listening_ports': ['80', '502'],
                'smb_accessible': False,
                'http_accessible': True,
                'protocols': ['Modbus', 'BACnet'],
            },
            '10.10.50.30': {
                'hostname': 'BADGE-RDR01',
                'type': 'Badge Reader',
                'os': 'Embedded',
                'role': 'Access Control',
                'vlan': 50,
                'listening_ports': ['80', '443'],
                'smb_accessible': False,
                'http_accessible': True,
            },
        })
        
        # VLAN 100 - Security
        self.machines.update({
            '10.10.100.10': {
                'hostname': 'SIEM01',
                'fqdn': 'siem01.corp.local',
                'os': 'CentOS 8',
                'role': 'SIEM Server',
                'vlan': 100,
                'listening_ports': ['22', '443', '514', '1514', '9200', '5601'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['Splunk', 'Elasticsearch', 'Kibana'],
            },
            '10.10.100.20': {
                'hostname': 'VULN-SCAN01',
                'fqdn': 'vulnscan01.corp.local',
                'os': 'Debian 11',
                'role': 'Vulnerability Scanner',
                'vlan': 100,
                'listening_ports': ['22', '443', '8834'],
                'smb_accessible': False,
                'ssh_accessible': True,
                'services': ['Nessus'],
            },
            '10.10.100.30': {
                'hostname': 'BACKUP01',
                'fqdn': 'backup01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Backup Server',
                'vlan': 100,
                'listening_ports': ['135', '445', '5985', '9392', '9393'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'BackupRepo'],
                'services': ['VeeamBackup', 'VeeamAgent'],
                'domain': 'CORP',
                'storage': '200TB',
            },
        })
        
        # Inter-VLAN routing rules (what can talk to what)
        self.routing_rules = {
            10: [10, 20, 30, 40, 50, 100],  # Management can reach all
            20: [10, 20, 30, 100],           # Servers can reach mgmt, servers, users, security
            30: [10, 20, 30, 40],            # Users can reach mgmt, servers, users, DMZ
            40: [20, 40],                    # DMZ can reach servers (limited) and DMZ
            50: [50],                        # IoT isolated
            60: [40],                        # Guest can only reach DMZ (internet)
            100: [10, 20, 30, 40, 50, 100],  # Security can reach all
        }
    
    def get_reachable_vlans(self, source_vlan: int) -> List[int]:
        """Get VLANs reachable from source VLAN"""
        return self.routing_rules.get(source_vlan, [source_vlan])
    
    def get_machines_in_vlan(self, vlan_id: int) -> Dict[str, Any]:
        """Get all machines in a specific VLAN"""
        return {ip: m for ip, m in self.machines.items() if m.get('vlan') == vlan_id}
    
    def get_reachable_machines(self, source_ip: str) -> List[str]:
        """Get all machines reachable from source IP"""
        source_machine = self.machines.get(source_ip)
        if not source_machine:
            return []
        
        source_vlan = source_machine.get('vlan', 0)
        reachable_vlans = self.get_reachable_vlans(source_vlan)
        
        reachable = []
        for ip, machine in self.machines.items():
            if machine.get('vlan') in reachable_vlans:
                reachable.append(ip)
        
        return reachable
    
    def get_all_ips(self) -> List[str]:
        """Get all IP addresses"""
        return list(self.machines.keys())
    
    def get_machine_count(self) -> int:
        """Get total machine count"""
        return len(self.machines)
    
    def get_vlan_summary(self) -> Dict[int, int]:
        """Get count of machines per VLAN"""
        summary = {}
        for machine in self.machines.values():
            vlan = machine.get('vlan', 0)
            summary[vlan] = summary.get(vlan, 0) + 1
        return summary


def run_network_enumeration_test():
    """Run comprehensive network enumeration test"""
    console = Console()
    
    console.print(Panel.fit(
        "[bold cyan]Complex VLAN Network Enumeration Test[/bold cyan]\n\n"
        "Testing enumeration across a multi-VLAN enterprise network\n"
        "with 20+ machines, switches, routers, and proper segmentation.",
        title="🔍 Network Enumeration Test",
        border_style="cyan"
    ))
    console.print()
    
    # Create the network
    network = VLANNetwork()
    
    # Display network topology
    console.print("[bold]Network Topology:[/bold]")
    console.print()
    
    # Create network tree
    tree = Tree("🌐 [bold]CORP.LOCAL Enterprise Network[/bold]")
    
    # Add infrastructure
    infra = tree.add("📡 [cyan]Network Infrastructure[/cyan]")
    for ip, device in network.infrastructure.items():
        infra.add(f"[dim]{ip}[/dim] - {device['hostname']} ({device['type']})")
    
    # Add VLANs
    for vlan_id, vlan_info in network.vlans.items():
        vlan_machines = network.get_machines_in_vlan(vlan_id)
        vlan_branch = tree.add(f"🔷 [yellow]VLAN {vlan_id}[/yellow] - {vlan_info['name']} ({vlan_info['subnet']})")
        for ip, machine in vlan_machines.items():
            icon = "🖥️" if 'Windows' in machine.get('os', '') else "🐧"
            if machine.get('is_dc'):
                icon = "👑"
            elif machine.get('role') == 'Jump Host':
                icon = "🚪"
            elif 'Camera' in machine.get('type', ''):
                icon = "📷"
            vlan_branch.add(f"{icon} [dim]{ip}[/dim] - {machine['hostname']} ({machine['role']})")
    
    console.print(tree)
    console.print()
    
    # Show machine count
    vlan_summary = network.get_vlan_summary()
    table = Table(title="Machine Count by VLAN", box=box.ROUNDED)
    table.add_column("VLAN", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Count", style="green", justify="right")
    
    for vlan_id in sorted(vlan_summary.keys()):
        vlan_name = network.vlans.get(vlan_id, {}).get('name', 'Unknown')
        table.add_row(str(vlan_id), vlan_name, str(vlan_summary[vlan_id]))
    
    table.add_row("[bold]TOTAL[/bold]", "", f"[bold]{network.get_machine_count()}[/bold]")
    console.print(table)
    console.print()
    
    # Now run the enumeration simulation
    console.print("[bold cyan]Starting Network Enumeration Simulation...[/bold cyan]")
    console.print(f"[dim]Enumeration depth: 5 (to traverse all VLANs)[/dim]")
    console.print()
    
    # Session data with depth 5
    session_data = {
        'LAB_USE': 1,
        'AUTO_ENUMERATE': 1,
        'AUTO_ENUMERATE_DEPTH': 5,
        'is_local_ip': is_local_ip,
        'discovered_components': {},
    }
    
    # Starting point: IT Admin Workstation in VLAN 30
    start_ip = '10.10.30.102'
    start_machine = network.machines[start_ip]
    
    console.print(f"[green]✓[/green] Starting enumeration from: {start_machine['hostname']} ({start_ip})")
    console.print(f"[dim]  VLAN: {start_machine['vlan']} ({network.vlans[start_machine['vlan']]['name']})[/dim]")
    console.print()
    
    # Simulate enumeration with mocked commands
    discovered_machines = {}
    lateral_paths = []
    
    def enumerate_from_host(source_ip: str, depth: int, path: List[str], visited: set):
        """Recursively enumerate from a host"""
        if depth > session_data['AUTO_ENUMERATE_DEPTH']:
            return
        
        if source_ip in visited:
            return
        
        visited.add(source_ip)
        current_path = path + [source_ip]
        
        source_machine = network.machines.get(source_ip)
        if not source_machine:
            return
        
        # Record discovered machine
        discovered_machines[source_ip] = {
            'hostname': source_machine['hostname'],
            'os': source_machine.get('os', 'Unknown'),
            'role': source_machine.get('role', 'Unknown'),
            'vlan': source_machine.get('vlan'),
            'depth': depth,
            'path': current_path,
            'smb_accessible': source_machine.get('smb_accessible', False),
            'winrm_accessible': source_machine.get('winrm_accessible', False),
            'shares': source_machine.get('shares', []),
            'services': source_machine.get('services', []),
        }
        
        # Record lateral path
        if len(current_path) > 1:
            lateral_paths.append({
                'path': current_path.copy(),
                'depth': depth,
                'method': 'wmic' if source_machine.get('winrm_accessible') else 'smb',
                'target': source_ip,
            })
        
        # Get reachable machines
        reachable = network.get_reachable_machines(source_ip)
        
        # Enumerate reachable machines
        for target_ip in reachable:
            if target_ip not in visited:
                target = network.machines.get(target_ip)
                if target and (target.get('smb_accessible') or target.get('winrm_accessible') or target.get('ssh_accessible')):
                    enumerate_from_host(target_ip, depth + 1, current_path, visited)
    
    # Start enumeration
    console.print("[cyan]Enumerating network...[/cyan]")
    visited = set()
    enumerate_from_host(start_ip, 0, [], visited)
    
    # Display results
    console.print()
    console.print(f"[bold green]✓ Enumeration Complete![/bold green]")
    console.print(f"[bold]Discovered {len(discovered_machines)} machines across the network[/bold]")
    console.print()
    
    # Create discovery table
    discovery_table = Table(title="Discovered Machines", box=box.ROUNDED)
    discovery_table.add_column("IP", style="cyan")
    discovery_table.add_column("Hostname", style="white")
    discovery_table.add_column("VLAN", style="yellow")
    discovery_table.add_column("Role", style="green")
    discovery_table.add_column("Depth", style="magenta", justify="right")
    discovery_table.add_column("Access", style="dim")
    
    for ip in sorted(discovered_machines.keys(), key=lambda x: (discovered_machines[x]['vlan'], x)):
        m = discovered_machines[ip]
        vlan_name = network.vlans.get(m['vlan'], {}).get('name', 'Unknown')
        access = []
        if m['smb_accessible']:
            access.append("SMB")
        if m['winrm_accessible']:
            access.append("WinRM")
        
        discovery_table.add_row(
            ip,
            m['hostname'],
            f"{m['vlan']} ({vlan_name})",
            m['role'],
            str(m['depth']),
            ", ".join(access) if access else "Limited"
        )
    
    console.print(discovery_table)
    console.print()
    
    # Show lateral movement paths
    console.print("[bold]Lateral Movement Paths:[/bold]")
    path_tree = Tree("🚀 [bold]Lateral Movement from Initial Host[/bold]")
    
    # Group paths by depth
    paths_by_depth = {}
    for path_info in lateral_paths:
        depth = path_info['depth']
        if depth not in paths_by_depth:
            paths_by_depth[depth] = []
        paths_by_depth[depth].append(path_info)
    
    for depth in sorted(paths_by_depth.keys()):
        depth_branch = path_tree.add(f"[yellow]Depth {depth}[/yellow] ({len(paths_by_depth[depth])} paths)")
        for path_info in paths_by_depth[depth][:5]:  # Show max 5 per depth
            target = discovered_machines.get(path_info['target'], {})
            path_str = " → ".join([discovered_machines.get(ip, {}).get('hostname', ip) for ip in path_info['path']])
            depth_branch.add(f"[dim]{path_str}[/dim] ({path_info['method']})")
    
    console.print(path_tree)
    console.print()
    
    # Generate enumeration data for reports
    enumeration_data = {
        'timestamp': datetime.now().isoformat(),
        'initial_host': start_machine['hostname'],
        'foothold': {
            'identity': 'CORP\\admin.jones',
            'role': start_machine['role'],
            'has_system': False,
            'listening_ports': start_machine.get('listening_ports', []),
        },
        'network': {
            'local_ips': [start_ip],
            'arp_targets': list(discovered_machines.keys()),
            'domain_controllers': 'DC01.corp.local\nDC02.corp.local',
            'vlans_discovered': list(set(m['vlan'] for m in discovered_machines.values())),
        },
        'lateral_targets': [
            {
                'target': ip,
                'smb_accessible': m['smb_accessible'],
                'winrm_accessible': m['winrm_accessible'],
                'hostname': m['hostname'],
                'vlan': m['vlan'],
            }
            for ip, m in discovered_machines.items()
        ],
        'lateral_paths': lateral_paths,
        'privilege_escalation': {
            'pe5_available': True,
            'windows_version': {'pe5_compatible': True},
            'current_privileges': {
                'UserName': 'admin.jones',
                'IsSystem': False,
                'IsAdmin': True,
            },
        },
        'identity': {
            'stored_credentials': 'Found cached domain credentials',
            'vault_credentials': 'Found 3 vault entries',
        },
        'persistence': {
            'recent_tasks': 'Found 5 scheduled tasks',
            'services': 'Found service accounts',
        },
        'discovered_machines': discovered_machines,
        'vlan_info': network.vlans,
    }
    
    # Generate diagrams
    console.print("[bold]Generating Reports and Diagrams...[/bold]")
    console.print()
    
    # Create output directory
    output_dir = Path('enumeration_reports') / datetime.now().strftime('%Y-%m-%d') / f"vlan_network_test_{datetime.now().strftime('%H%M%S')}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate diagrams
    diagram_gen = DiagramGenerator(enumeration_data)
    diagrams = diagram_gen.generate_all_diagrams()
    saved_diagrams = diagram_gen.save_diagrams(output_dir)
    
    console.print(f"[green]✓[/green] Generated {len(diagrams)} diagrams:")
    for name, path in saved_diagrams.items():
        console.print(f"  [dim]• {name}: {path}[/dim]")
    console.print()
    
    # Generate reports
    report_console = Console(file=open('/dev/null', 'w'))
    report_gen = ReportGenerator(report_console, enumeration_data)
    
    # Text report
    text_report = report_gen.generate_text_report()
    text_report_path = output_dir / 'enumeration_report.txt'
    with open(text_report_path, 'w') as f:
        f.write(text_report)
    
    # JSON report
    json_report = report_gen.generate_json_report()
    json_report_path = output_dir / 'enumeration_report.json'
    with open(json_report_path, 'w') as f:
        f.write(json_report)
    
    # HTML report
    html_report = report_gen.generate_html_report()
    html_report_path = output_dir / 'enumeration_report.html'
    with open(html_report_path, 'w') as f:
        f.write(html_report)
    
    console.print(f"[green]✓[/green] Generated reports:")
    console.print(f"  [dim]• Text: {text_report_path}[/dim]")
    console.print(f"  [dim]• JSON: {json_report_path}[/dim]")
    console.print(f"  [dim]• HTML: {html_report_path}[/dim]")
    console.print()
    
    # Summary
    console.print(Panel.fit(
        f"[bold green]Test Complete![/bold green]\n\n"
        f"📊 [bold]Results Summary:[/bold]\n"
        f"   • Total machines in network: {network.get_machine_count()}\n"
        f"   • Machines discovered: {len(discovered_machines)}\n"
        f"   • VLANs traversed: {len(set(m['vlan'] for m in discovered_machines.values()))}\n"
        f"   • Lateral paths found: {len(lateral_paths)}\n"
        f"   • Maximum depth reached: {max(m['depth'] for m in discovered_machines.values())}\n\n"
        f"📁 [bold]Output Directory:[/bold]\n"
        f"   {output_dir}",
        title="✅ Test Summary",
        border_style="green"
    ))
    
    # Verify all machines were found
    total_in_network = network.get_machine_count()
    discovered_count = len(discovered_machines)
    
    if discovered_count >= total_in_network * 0.8:  # 80% discovery rate
        console.print(f"\n[bold green]✓ SUCCESS: Discovered {discovered_count}/{total_in_network} machines ({discovered_count/total_in_network*100:.1f}%)[/bold green]")
    else:
        console.print(f"\n[bold yellow]⚠ PARTIAL: Discovered {discovered_count}/{total_in_network} machines ({discovered_count/total_in_network*100:.1f}%)[/bold yellow]")
        console.print("[dim]Note: Some machines may be in isolated VLANs (IoT, Guest)[/dim]")
    
    return discovered_machines, lateral_paths, output_dir


if __name__ == '__main__':
    discovered, paths, output = run_network_enumeration_test()
    print(f"\n\nTest completed. Output saved to: {output}")
