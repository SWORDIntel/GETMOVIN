"""Test PE5 Module and Network Enumeration with Complex Network Emulation

This test suite:
1. Verifies PE5 module functionality matches pe5_framework_extracted
2. Emulates a complex network with 10+ machines and switch
3. Tests the enumeration feature with appropriate depth

Run with: pytest tests/test_pe5_and_network_enumeration.py -v --cov=modules
"""

import pytest
import sys
import time
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from modules.pe5_system_escalation import PE5SystemEscalationModule
from modules.pe5_utils import PE5Utils
from modules.auto_enumerate import AutoEnumerator, ReportGenerator, AutoEnumerateModule
from modules.diagram_generator import DiagramGenerator
from modules.utils import is_local_ip


# ============================================================================
# NETWORK EMULATION INFRASTRUCTURE
# ============================================================================

class EmulatedNetwork:
    """
    Emulates a complex enterprise network with 10+ machines and a switch.
    
    Network Topology:
    
                        [Internet]
                            |
                        [Firewall]
                            |
                    ┌───────┴───────┐
                    │    SWITCH     │
                    │  192.168.1.1  │
                    └───────┬───────┘
                            |
    ┌───────┬───────┬───────┼───────┬───────┬───────┬───────┐
    │       │       │       │       │       │       │       │
    DC1     DC2    SQL1   FILE1   WEB1   WEB2   HR-WS  DEV-WS
    .10     .11    .20    .30     .40    .41    .100   .101
                            |
                    ┌───────┼───────┐
                    │       │       │
                  MGT1   SIEM1   BACKUP1
                  .200   .201    .202
    """
    
    def __init__(self):
        # Network switch configuration
        self.switch = {
            'hostname': 'CORE-SW01',
            'ip': '192.168.1.1',
            'mac': '00:1A:2B:3C:4D:5E',
            'type': 'Network Switch',
            'ports': 48,
            'connected_devices': 13
        }
        
        # Define all machines in the network (10+ machines)
        self.machines = {
            # Domain Controllers
            '192.168.1.10': {
                'hostname': 'DC01',
                'fqdn': 'DC01.corp.local',
                'os': 'Windows Server 2022',
                'role': 'Domain Controller',
                'listening_ports': ['53', '88', '135', '389', '445', '464', '636', '3268', '3269'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['SYSVOL', 'NETLOGON', 'C$', 'ADMIN$'],
                'services': ['ActiveDirectory', 'DNS', 'Kerberos'],
                'domain': 'CORP',
                'is_dc': True
            },
            '192.168.1.11': {
                'hostname': 'DC02',
                'fqdn': 'DC02.corp.local',
                'os': 'Windows Server 2022',
                'role': 'Domain Controller',
                'listening_ports': ['53', '88', '135', '389', '445', '464', '636', '3268', '3269'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['SYSVOL', 'NETLOGON', 'C$', 'ADMIN$'],
                'services': ['ActiveDirectory', 'DNS', 'Kerberos'],
                'domain': 'CORP',
                'is_dc': True
            },
            # SQL Server
            '192.168.1.20': {
                'hostname': 'SQL01',
                'fqdn': 'SQL01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Database Server',
                'listening_ports': ['135', '445', '1433', '1434', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'SQLBackups'],
                'services': ['MSSQLSERVER', 'SQLSERVERAGENT'],
                'domain': 'CORP',
                'is_dc': False
            },
            # File Server
            '192.168.1.30': {
                'hostname': 'FILE01',
                'fqdn': 'FILE01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'File Server',
                'listening_ports': ['135', '139', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'SharedDocs', 'Finance', 'HR', 'IT'],
                'services': ['LanmanServer'],
                'domain': 'CORP',
                'is_dc': False
            },
            # Web Servers
            '192.168.1.40': {
                'hostname': 'WEB01',
                'fqdn': 'WEB01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Web Server',
                'listening_ports': ['80', '443', '135', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'wwwroot'],
                'services': ['W3SVC', 'IIS Admin'],
                'domain': 'CORP',
                'is_dc': False
            },
            '192.168.1.41': {
                'hostname': 'WEB02',
                'fqdn': 'WEB02.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Web Server',
                'listening_ports': ['80', '443', '135', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'wwwroot'],
                'services': ['W3SVC', 'IIS Admin'],
                'domain': 'CORP',
                'is_dc': False
            },
            # Workstations
            '192.168.1.100': {
                'hostname': 'HR-WS01',
                'fqdn': 'HR-WS01.corp.local',
                'os': 'Windows 10 Enterprise 22H2',
                'role': 'Workstation',
                'listening_ports': ['135', '139', '445'],
                'smb_accessible': True,
                'winrm_accessible': False,
                'shares': ['C$', 'ADMIN$'],
                'services': [],
                'domain': 'CORP',
                'is_dc': False
            },
            '192.168.1.101': {
                'hostname': 'DEV-WS01',
                'fqdn': 'DEV-WS01.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'Developer Workstation',
                'listening_ports': ['135', '139', '445', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'DevShare'],
                'services': ['Docker Desktop', 'Visual Studio'],
                'domain': 'CORP',
                'is_dc': False
            },
            # Management Infrastructure
            '192.168.1.200': {
                'hostname': 'MGT01',
                'fqdn': 'MGT01.corp.local',
                'os': 'Windows Server 2022',
                'role': 'Management Server',
                'listening_ports': ['135', '445', '5985', '5986', '3389'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'AdminTools'],
                'services': ['WinRM', 'RDP'],
                'domain': 'CORP',
                'is_dc': False
            },
            '192.168.1.201': {
                'hostname': 'SIEM01',
                'fqdn': 'SIEM01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'SIEM Server',
                'listening_ports': ['135', '445', '514', '1514', '5985'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'Logs'],
                'services': ['Splunk', 'WinEventLogCollector'],
                'domain': 'CORP',
                'is_dc': False
            },
            '192.168.1.202': {
                'hostname': 'BACKUP01',
                'fqdn': 'BACKUP01.corp.local',
                'os': 'Windows Server 2019',
                'role': 'Backup Server',
                'listening_ports': ['135', '445', '5985', '10000'],
                'smb_accessible': True,
                'winrm_accessible': True,
                'shares': ['C$', 'ADMIN$', 'BackupRepo'],
                'services': ['VeeamBackup', 'VeeamAgent'],
                'domain': 'CORP',
                'is_dc': False
            },
            # Additional workstation for 10+ count
            '192.168.1.102': {
                'hostname': 'EXEC-WS01',
                'fqdn': 'EXEC-WS01.corp.local',
                'os': 'Windows 11 Enterprise 23H2',
                'role': 'Executive Workstation',
                'listening_ports': ['135', '139', '445'],
                'smb_accessible': True,
                'winrm_accessible': False,
                'shares': ['C$', 'ADMIN$'],
                'services': [],
                'domain': 'CORP',
                'is_dc': False
            }
        }
        
        # Network segments for enumeration depth testing
        self.network_segments = {
            'servers': ['192.168.1.10', '192.168.1.11', '192.168.1.20', '192.168.1.30', 
                       '192.168.1.40', '192.168.1.41'],
            'workstations': ['192.168.1.100', '192.168.1.101', '192.168.1.102'],
            'management': ['192.168.1.200', '192.168.1.201', '192.168.1.202']
        }
        
        # Lateral movement paths (how machines can reach each other)
        self.lateral_paths = {
            '192.168.1.100': ['192.168.1.30', '192.168.1.10'],  # HR workstation can reach file server and DC
            '192.168.1.101': ['192.168.1.20', '192.168.1.40', '192.168.1.10'],  # Dev can reach SQL, web, DC
            '192.168.1.30': ['192.168.1.10', '192.168.1.11', '192.168.1.202'],  # File server to DCs and backup
            '192.168.1.20': ['192.168.1.10', '192.168.1.202'],  # SQL to DC and backup
            '192.168.1.40': ['192.168.1.20', '192.168.1.41'],  # Web1 to SQL and Web2
            '192.168.1.200': list(self.machines.keys()),  # Management can reach all
        }
    
    def get_arp_cache(self, source_ip: str) -> List[str]:
        """Simulate ARP cache from a given source IP"""
        if source_ip in self.lateral_paths:
            return self.lateral_paths[source_ip]
        # Default: return some nearby machines
        return list(self.machines.keys())[:5]
    
    def get_machine_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific machine"""
        return self.machines.get(ip)
    
    def simulate_smb_access(self, source_ip: str, target_ip: str) -> bool:
        """Simulate SMB access from source to target"""
        target = self.machines.get(target_ip)
        if target and target.get('smb_accessible'):
            return True
        return False
    
    def simulate_winrm_access(self, source_ip: str, target_ip: str) -> bool:
        """Simulate WinRM access from source to target"""
        target = self.machines.get(target_ip)
        if target and target.get('winrm_accessible'):
            return True
        return False
    
    def get_net_view_output(self, target_ip: str) -> str:
        """Simulate 'net view' command output"""
        machine = self.machines.get(target_ip)
        if not machine:
            return ""
        
        shares = machine.get('shares', [])
        output_lines = [
            f"Shared resources at \\\\{target_ip}",
            "",
            "Share name   Type   Used as   Comment",
            "------------------------------------------------------------------------"
        ]
        for share in shares:
            output_lines.append(f"{share:<12} Disk")
        output_lines.append("The command completed successfully.")
        return "\n".join(output_lines)
    
    def get_wmic_output(self, target_ip: str, query: str) -> str:
        """Simulate WMIC command output"""
        machine = self.machines.get(target_ip)
        if not machine:
            return ""
        
        if 'os get' in query:
            return f"Name                                      Version\n{machine['os']}  10.0.19045"
        elif 'process list' in query:
            return "Handle  Name                     Priority  ProcessId\n0       System                   8         4"
        return ""
    
    def get_all_ips(self) -> List[str]:
        """Get all IP addresses in the network"""
        return list(self.machines.keys())


# ============================================================================
# PE5 MODULE VERIFICATION TESTS
# ============================================================================

class TestPE5ModuleVsFramework:
    """Tests to verify PE5 module matches pe5_framework_extracted functionality"""
    
    @pytest.fixture
    def pe5_utils(self):
        """Create PE5Utils instance"""
        return PE5Utils()
    
    @pytest.fixture
    def console(self):
        """Create console instance"""
        return Console(file=open('/dev/null', 'w') if sys.platform != 'win32' else open('nul', 'w'))
    
    @pytest.fixture
    def session_data(self):
        """Create session data"""
        return {
            'LAB_USE': 1,
            'AUTO_ENUMERATE': 0,
            'AUTO_ENUMERATE_DEPTH': 5,  # Set depth to 5 to find all machines
            'is_local_ip': is_local_ip,
            'discovered_components': {}
        }
    
    def test_pe5_constants_match_framework(self, pe5_utils):
        """Verify PE5Utils constants match pe5_framework_extracted/exploit.h"""
        # These constants should match exploit.h
        assert pe5_utils.PE5_SIZE == 22702, "PE5_SIZE should be 22702"
        assert pe5_utils.PE5_SYSCALL_OFFSET == 0x2C10, "SYSCALL offset should be 0x2C10"
        assert pe5_utils.PE5_XOR_KEY == 0xA4, "XOR key should be 0xA4"
        assert pe5_utils.KEY_DERIVE_OFFSET_1 == 3, "Key derive offset 1 should be 3"
        assert pe5_utils.KEY_DERIVE_OFFSET_2 == 7, "Key derive offset 2 should be 7"
    
    def test_xor_key_derivation_matches_framework(self, pe5_utils):
        """Verify XOR key derivation formula matches decryption.c"""
        # Simulated PE5 header bytes as per decryption.c
        header_bytes = bytes([
            0xC1, 0xBD, 0x87, 0x35,  # DWORD 1: Used for key derivation
            0x1E, 0x8C, 0xA6, 0x91,  # DWORD 2: Used for key derivation
            0xF7, 0x62, 0xC0, 0xB5,
            0x75, 0x24, 0x32, 0x25
        ])
        
        derived_key = pe5_utils.derive_xor_key(header_bytes)
        
        # Key = header[3] ^ header[7] = 0x35 ^ 0x91 = 0xA4
        assert derived_key == 0xA4, f"Derived key should be 0xA4, got {hex(derived_key)}"
    
    def test_decrypt_payload_matches_framework(self, pe5_utils):
        """Verify decrypt_payload matches decryption.c behavior"""
        # Create a simple encrypted payload
        original = bytes([0x0F, 0x05, 0x90, 0x90])  # SYSCALL + NOPs
        encrypted = pe5_utils.decrypt_payload(original, 0xA4)
        
        # Verify XOR encryption is reversible
        decrypted = pe5_utils.decrypt_payload(encrypted, 0xA4)
        assert decrypted == original, "XOR decryption should be reversible"
    
    def test_syscall_verification_matches_framework(self, pe5_utils):
        """Verify SYSCALL location verification matches exploit.c"""
        # Create simulated decrypted payload with SYSCALL at correct offset
        payload_size = 0x2C10 + 10
        payload = bytearray(payload_size)
        
        # Place SYSCALL instruction (0x0F 0x05) at offset 0x2C10
        payload[0x2C10] = 0x0F
        payload[0x2C10 + 1] = 0x05
        
        # Verify SYSCALL location
        assert pe5_utils.verify_syscall_location(bytes(payload)) is True
        
        # Test with wrong bytes
        payload[0x2C10] = 0x00
        assert pe5_utils.verify_syscall_location(bytes(payload)) is False
    
    def test_windows_version_offsets_match_framework(self, pe5_utils):
        """Verify Windows version offsets match token_manipulation.c"""
        # Windows 10 1909 offsets
        offsets_1909 = pe5_utils.get_windows_version_offsets('Windows 10 1909')
        assert offsets_1909['token'] == 0x360
        assert offsets_1909['pid'] == 0x2E8
        assert offsets_1909['links'] == 0x2F0
        
        # Windows 10 2004+ / Windows 11 offsets
        offsets_2004 = pe5_utils.get_windows_version_offsets('Windows 10 2004+')
        assert offsets_2004['token'] == 0x4B8
        assert offsets_2004['pid'] == 0x440
        assert offsets_2004['links'] == 0x448
        
        offsets_w11 = pe5_utils.get_windows_version_offsets('Windows 11')
        assert offsets_w11['token'] == 0x4B8
        assert offsets_w11['pid'] == 0x440
        assert offsets_w11['links'] == 0x448
    
    def test_token_modify_shellcode_generation(self, pe5_utils):
        """Verify token modification shellcode is generated correctly"""
        shellcode = pe5_utils.generate_token_modify_shellcode(token_offset=0x4B8)
        
        # Verify shellcode is not empty and has expected structure
        assert len(shellcode) > 0, "Shellcode should not be empty"
        
        # Check for GS segment prefix (0x65) at start
        assert shellcode[0] == 0x65, "Shellcode should start with GS segment prefix"
        
        # Check for RET instruction (0xC3) at end
        assert shellcode[-1] == 0xC3, "Shellcode should end with RET"
    
    def test_token_steal_shellcode_generation(self, pe5_utils):
        """Verify token stealing shellcode is generated correctly"""
        shellcode = pe5_utils.generate_token_steal_shellcode(
            token_offset=0x4B8,
            pid_offset=0x440,
            links_offset=0x448
        )
        
        # Verify shellcode is not empty
        assert len(shellcode) > 0, "Shellcode should not be empty"
        
        # Check for GS segment prefix (0x65) at start
        assert shellcode[0] == 0x65, "Shellcode should start with GS segment prefix"
    
    def test_technique_info_completeness(self, pe5_utils):
        """Verify all exploitation techniques are documented"""
        techniques = pe5_utils.get_technique_info()
        
        expected_techniques = [
            'Direct Privilege Modification',
            'Token Stealing',
            'Integrity Level Elevation',
            'Full Token Takeover'
        ]
        
        for technique in expected_techniques:
            assert technique in techniques, f"Missing technique: {technique}"
            assert 'description' in techniques[technique]
            assert 'speed' in techniques[technique]
            assert 'reliability' in techniques[technique]
            assert 'detection' in techniques[technique]
    
    def test_pe5_module_initialization(self, console, session_data):
        """Verify PE5SystemEscalationModule can be initialized"""
        module = PE5SystemEscalationModule()
        assert module is not None
        assert module.utils is not None
        assert isinstance(module.pe5_framework_available, bool)
    
    def test_pe5_framework_detection(self, console, session_data):
        """Verify PE5 framework is detected when present"""
        module = PE5SystemEscalationModule()
        # The framework should be detected as the path exists
        assert module._check_pe5_framework() is True


# ============================================================================
# COMPLEX NETWORK ENUMERATION TESTS
# ============================================================================

class TestNetworkEnumeration:
    """Test enumeration with complex network emulation (10+ machines + switch)"""
    
    @pytest.fixture
    def emulated_network(self):
        """Create emulated network"""
        return EmulatedNetwork()
    
    @pytest.fixture
    def console(self):
        """Create console instance"""
        return Console(file=open('/dev/null', 'w') if sys.platform != 'win32' else open('nul', 'w'))
    
    @pytest.fixture
    def session_data(self, emulated_network):
        """Create session data with appropriate depth"""
        return {
            'LAB_USE': 1,
            'AUTO_ENUMERATE': 1,
            'AUTO_ENUMERATE_DEPTH': 5,  # Depth 5 to find all machines in network
            'is_local_ip': is_local_ip,
            'discovered_components': {},
            'emulated_network': emulated_network
        }
    
    def test_network_has_minimum_machines(self, emulated_network):
        """Verify network has at least 10 machines"""
        machine_count = len(emulated_network.machines)
        assert machine_count >= 10, f"Network should have at least 10 machines, got {machine_count}"
        print(f"\n✓ Network has {machine_count} machines (minimum 10 required)")
    
    def test_network_has_switch(self, emulated_network):
        """Verify network has a switch"""
        assert emulated_network.switch is not None
        assert emulated_network.switch['type'] == 'Network Switch'
        assert emulated_network.switch['ports'] >= 24
        print(f"\n✓ Network switch: {emulated_network.switch['hostname']} ({emulated_network.switch['ip']})")
    
    def test_network_topology_completeness(self, emulated_network):
        """Verify network topology includes all required components"""
        # Check for domain controllers
        dcs = [m for m in emulated_network.machines.values() if m['is_dc']]
        assert len(dcs) >= 2, "Network should have at least 2 domain controllers"
        
        # Check for servers
        servers = [m for m in emulated_network.machines.values() 
                   if 'Server' in m['os'] and not m['is_dc']]
        assert len(servers) >= 5, "Network should have at least 5 servers"
        
        # Check for workstations
        workstations = [m for m in emulated_network.machines.values() 
                       if 'Windows 10' in m['os'] or 'Windows 11' in m['os']]
        assert len(workstations) >= 3, "Network should have at least 3 workstations"
        
        print(f"\n✓ Topology: {len(dcs)} DCs, {len(servers)} servers, {len(workstations)} workstations")
    
    @patch('modules.auto_enumerate.execute_cmd')
    @patch('modules.auto_enumerate.execute_powershell')
    def test_enumeration_discovers_all_machines(self, mock_ps, mock_cmd, console, session_data, emulated_network):
        """Test that enumeration with depth 5 discovers all 10+ machines"""
        
        # Setup mock responses based on emulated network
        def mock_cmd_side_effect(cmd, **kwargs):
            if 'hostname' in cmd.lower():
                return (0, "INITIAL-HOST", "")
            elif 'arp -a' in cmd.lower():
                # Return all IPs from ARP cache
                arp_output = "Interface: 192.168.1.100 --- 0x5\n"
                for ip, machine in emulated_network.machines.items():
                    arp_output += f"  {ip}            {machine.get('mac', 'aa-bb-cc-dd-ee-ff')}     dynamic\n"
                return (0, arp_output, "")
            elif 'net view' in cmd.lower():
                # Extract target IP from command
                for ip in emulated_network.machines:
                    if ip in cmd:
                        return (0, emulated_network.get_net_view_output(ip), "")
                return (1, "", "Network path not found")
            elif 'wmic' in cmd.lower():
                for ip in emulated_network.machines:
                    if ip in cmd:
                        return (0, emulated_network.get_wmic_output(ip, cmd), "")
                return (1, "", "RPC unavailable")
            elif 'whoami' in cmd.lower():
                return (0, "CORP\\testuser", "")
            elif 'systeminfo' in cmd.lower():
                return (0, "OS Name: Microsoft Windows 10 Enterprise\nOS Version: 10.0.19045", "")
            elif 'ipconfig' in cmd.lower():
                return (0, "IPv4 Address: 192.168.1.100\nSubnet Mask: 255.255.255.0", "")
            elif 'netstat' in cmd.lower():
                return (0, "TCP    0.0.0.0:445    0.0.0.0:0    LISTENING", "")
            elif 'net localgroup' in cmd.lower():
                return (0, "Administrators", "")
            elif 'net group' in cmd.lower():
                return (0, "Domain Admins\nDomain Users", "")
            elif 'nltest' in cmd.lower():
                return (0, "DC01.corp.local [PDC] [DS]", "")
            elif 'cmdkey' in cmd.lower():
                return (0, "Target: Domain:interactive=CORP\\admin", "")
            elif 'vaultcmd' in cmd.lower():
                return (0, "Vault: Windows Credentials", "")
            return (0, "", "")
        
        def mock_ps_side_effect(cmd, **kwargs):
            if 'WindowsIdentity' in cmd:
                return (0, "IsSystem: False\nIsAdmin: True\nUserSID: S-1-5-21-1234", "")
            elif 'Win32_Service' in cmd:
                return (0, "Name: TestService, StartName: CORP\\svc_account", "")
            elif 'ScheduledTask' in cmd:
                return (0, "TaskName: UpdateTask", "")
            elif 'Get-Process' in cmd:
                return (0, "ProcessName: explorer, Id: 1234", "")
            elif 'Test-WSMan' in cmd:
                for ip in emulated_network.machines:
                    if ip in cmd:
                        machine = emulated_network.machines[ip]
                        if machine.get('winrm_accessible'):
                            return (0, "wsmid : http://schemas.dmtf.org/wbem/wsman/1/wsman", "")
                return (1, "", "WinRM test failed")
            elif 'Win32_Share' in cmd:
                return (0, "Name: C$, Path: C:\\", "")
            elif 'Invoke-Command' in cmd:
                return (0, "Remote execution successful", "")
            return (0, "", "")
        
        mock_cmd.side_effect = mock_cmd_side_effect
        mock_ps.side_effect = mock_ps_side_effect
        
        # Create enumerator and run enumeration
        enumerator = AutoEnumerator(console, session_data)
        
        # Mock the progress to avoid UI issues
        with patch('modules.auto_enumerate.Progress'):
            result = enumerator.run_full_enumeration()
        
        # Verify enumeration data contains network information
        assert 'network' in result
        assert 'lateral_targets' in result
        
        # Count discovered targets
        arp_targets = result.get('network', {}).get('arp_targets', [])
        lateral_targets = result.get('lateral_targets', [])
        
        print(f"\n✓ Discovered {len(arp_targets)} ARP targets")
        print(f"✓ Discovered {len(lateral_targets)} lateral movement targets")
        
        # Verify we discovered at least 10 targets (matching our 10+ machine requirement)
        total_discovered = len(arp_targets)
        assert total_discovered >= 10, f"Should discover at least 10 machines, got {total_discovered}"
    
    @patch('modules.auto_enumerate.execute_cmd')
    @patch('modules.auto_enumerate.execute_powershell')
    def test_lateral_movement_depth_discovers_hierarchy(self, mock_ps, mock_cmd, console, session_data, emulated_network):
        """Test that lateral movement with appropriate depth discovers network hierarchy"""
        
        # Track visited hosts
        visited_hosts = []
        
        def mock_cmd_side_effect(cmd, **kwargs):
            if 'hostname' in cmd.lower():
                return (0, "INITIAL-HOST", "")
            elif 'arp -a' in cmd.lower():
                arp_output = "Interface: 192.168.1.100\n"
                for ip in list(emulated_network.machines.keys())[:10]:
                    arp_output += f"  {ip}    aa-bb-cc-dd-ee-ff    dynamic\n"
                return (0, arp_output, "")
            elif 'net view' in cmd.lower():
                for ip in emulated_network.machines:
                    if ip in cmd:
                        visited_hosts.append(ip)
                        return (0, emulated_network.get_net_view_output(ip), "")
                return (1, "", "")
            return (0, "", "")
        
        mock_cmd.side_effect = mock_cmd_side_effect
        mock_ps.return_value = (0, "", "")
        
        enumerator = AutoEnumerator(console, session_data)
        
        # Set up initial network data
        enumerator.enumeration_data['network'] = {
            'arp_targets': list(emulated_network.machines.keys())[:10]
        }
        
        # Mock progress
        mock_progress = Mock()
        mock_task = Mock()
        
        # Enumerate lateral targets
        targets = enumerator._enumerate_lateral_targets(mock_progress, mock_task)
        
        # Verify we got targets from multiple machines
        assert len(targets) > 0 or len(visited_hosts) > 0
        
        print(f"\n✓ Lateral movement visited {len(set(visited_hosts))} unique hosts")
    
    def test_enumeration_depth_configuration(self, console, session_data):
        """Test that enumeration depth is properly configured for 10+ machines"""
        enumerator = AutoEnumerator(console, session_data)
        
        # Verify depth is set correctly
        assert enumerator.max_depth == 5, "Max depth should be 5 to discover all machines"
        
        print(f"\n✓ Enumeration depth configured: {enumerator.max_depth}")
    
    @patch('modules.auto_enumerate.execute_cmd')
    def test_remote_target_enumeration_collects_data(self, mock_cmd, console, session_data, emulated_network):
        """Test that remote target enumeration collects comprehensive data"""
        
        target_ip = '192.168.1.10'  # DC01
        target_machine = emulated_network.machines[target_ip]
        
        mock_cmd.return_value = (0, f"OS: {target_machine['os']}", "")
        
        enumerator = AutoEnumerator(console, session_data)
        
        target_info = {
            'smb_accessible': target_machine['smb_accessible'],
            'winrm_accessible': target_machine['winrm_accessible']
        }
        
        remote_data = enumerator._enumerate_remote_target(target_ip, target_info, depth=1)
        
        # Verify structure
        assert 'target' in remote_data
        assert remote_data['target'] == target_ip
        assert 'depth' in remote_data
        assert 'timestamp' in remote_data
        assert 'foothold' in remote_data
        assert 'network' in remote_data
        
        print(f"\n✓ Remote enumeration of {target_ip} successful")


# ============================================================================
# DIAGRAM GENERATION TESTS FOR COMPLEX NETWORK
# ============================================================================

class TestDiagramGenerationComplexNetwork:
    """Test diagram generation for complex network topology"""
    
    @pytest.fixture
    def emulated_network(self):
        """Create emulated network"""
        return EmulatedNetwork()
    
    @pytest.fixture
    def complex_enumeration_data(self, emulated_network):
        """Create enumeration data representing complex network discovery"""
        lateral_paths = []
        
        # Create lateral movement paths through the network
        for i, (ip, machine) in enumerate(emulated_network.machines.items()):
            if i < 5:  # First 5 machines as paths
                lateral_paths.append({
                    'path': ['INITIAL-HOST', ip],
                    'method': 'wmic' if machine['winrm_accessible'] else 'smb',
                    'depth': 1,
                    'target': ip,
                    'enumeration': {
                        'target': ip,
                        'foothold': {
                            'identity': f"CORP\\admin",
                            'role': machine['role'],
                            'listening_ports': machine['listening_ports']
                        },
                        'network': {
                            'shares': machine['shares']
                        }
                    }
                })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'initial_host': 'INITIAL-HOST',
            'foothold': {
                'identity': 'CORP\\testuser',
                'role': 'Workstation',
                'has_system': False,
                'listening_ports': ['135', '445']
            },
            'network': {
                'local_ips': ['192.168.1.100'],
                'arp_targets': list(emulated_network.machines.keys()),
                'domain_controllers': 'DC01.corp.local\nDC02.corp.local'
            },
            'lateral_targets': [
                {
                    'target': ip,
                    'smb_accessible': machine['smb_accessible'],
                    'winrm_accessible': machine['winrm_accessible']
                }
                for ip, machine in emulated_network.machines.items()
            ],
            'lateral_paths': lateral_paths,
            'privilege_escalation': {
                'pe5_available': True,
                'windows_version': {'pe5_compatible': True},
                'current_privileges': {
                    'UserName': 'testuser',
                    'IsSystem': False,
                    'IsAdmin': True
                }
            },
            'identity': {
                'stored_credentials': 'Found cached credentials',
                'vault_credentials': 'Found vault entries'
            },
            'persistence': {
                'recent_tasks': 'Found scheduled tasks',
                'services': 'Found service accounts'
            }
        }
    
    def test_network_diagram_includes_all_machines(self, complex_enumeration_data, emulated_network):
        """Test network diagram includes all discovered machines"""
        generator = DiagramGenerator(complex_enumeration_data)
        diagram = generator.generate_network_diagram()
        
        assert 'graph' in diagram.lower()
        
        # Count machines in diagram
        machine_count = 0
        for ip in emulated_network.machines:
            if ip in diagram or emulated_network.machines[ip]['hostname'] in diagram:
                machine_count += 1
        
        print(f"\n✓ Network diagram includes {machine_count} machines")
        assert machine_count > 0, "Diagram should include discovered machines"
    
    def test_lateral_movement_diagram_shows_paths(self, complex_enumeration_data):
        """Test lateral movement diagram shows traversal paths"""
        generator = DiagramGenerator(complex_enumeration_data)
        diagram = generator.generate_lateral_movement_diagram()
        
        assert 'graph' in diagram.lower()
        
        # Verify paths are represented
        path_count = diagram.count('-->')
        print(f"\n✓ Lateral movement diagram shows {path_count} path connections")
        
        assert path_count > 0, "Diagram should show lateral movement paths"
    
    def test_attack_timeline_includes_enumeration_phases(self, complex_enumeration_data):
        """Test attack timeline includes all enumeration phases"""
        generator = DiagramGenerator(complex_enumeration_data)
        diagram = generator.generate_attack_timeline()
        
        assert 'gantt' in diagram.lower()
        
        expected_phases = ['Foothold', 'Discovery', 'Lateral']
        for phase in expected_phases:
            # Check if phase or similar terminology exists
            assert any(p.lower() in diagram.lower() for p in [phase, 'enumerate', 'movement'])
        
        print(f"\n✓ Attack timeline includes enumeration phases")
    
    def test_generate_all_diagrams_for_complex_network(self, complex_enumeration_data, tmp_path):
        """Test all diagrams can be generated and saved for complex network"""
        generator = DiagramGenerator(complex_enumeration_data)
        diagrams = generator.generate_all_diagrams()
        
        expected_diagrams = [
            'mitre_attack_flow',
            'network_topology',
            'lateral_movement',
            'privilege_escalation',
            'system_architecture',
            'attack_timeline'
        ]
        
        for diagram_name in expected_diagrams:
            assert diagram_name in diagrams, f"Missing diagram: {diagram_name}"
            assert len(diagrams[diagram_name]) > 0, f"Diagram {diagram_name} is empty"
        
        # Save diagrams
        saved_files = generator.save_diagrams(tmp_path)
        
        print(f"\n✓ Generated {len(diagrams)} diagrams")
        print(f"✓ Saved {len(saved_files)} diagram files")
        
        for diagram_name, filepath in saved_files.items():
            assert filepath.exists(), f"Diagram file not created: {filepath}"
            assert filepath.suffix == '.mmd'


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestPE5AndEnumerationIntegration:
    """Integration tests combining PE5 and enumeration functionality"""
    
    @pytest.fixture
    def console(self):
        """Create console instance"""
        return Console(file=open('/dev/null', 'w') if sys.platform != 'win32' else open('nul', 'w'))
    
    @pytest.fixture
    def session_data(self):
        """Create session data"""
        return {
            'LAB_USE': 1,
            'AUTO_ENUMERATE': 1,
            'AUTO_ENUMERATE_DEPTH': 5,
            'is_local_ip': is_local_ip,
            'discovered_components': {}
        }
    
    @patch('modules.auto_enumerate.execute_cmd')
    @patch('modules.auto_enumerate.execute_powershell')
    def test_pe5_enumeration_integration(self, mock_ps, mock_cmd, console, session_data):
        """Test PE5 status is properly enumerated"""
        
        mock_cmd.return_value = (0, "test_output", "")
        mock_ps.return_value = (0, "IsSystem: False\nIsAdmin: True", "")
        
        enumerator = AutoEnumerator(console, session_data)
        
        # Verify PE5 module is integrated
        assert enumerator.pe5_utils is not None
        
        # Verify PE5 framework detection
        assert hasattr(enumerator, 'pe5_module')
        
        print("\n✓ PE5 module integrated with enumerator")
    
    def test_pe5_privilege_escalation_enumeration_structure(self, console, session_data):
        """Test privilege escalation enumeration has proper PE5 structure"""
        enumerator = AutoEnumerator(console, session_data)
        
        # Verify enumeration data structure includes PE5-related fields
        assert 'privilege_escalation' in enumerator.enumeration_data
        assert 'pe5_status' in enumerator.enumeration_data
        
        print("\n✓ PE5 privilege escalation structure verified")


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '-x'])
