#!/usr/bin/env python3
"""Medium-Sized Company Network Simulation Test

Simulates a realistic medium-sized company (~500 employees) with:
- 6 VLANs (Management, Servers, Users, DMZ, IoT, Guest)
- 45+ machines across segments
- Multiple departments (IT, Finance, HR, Engineering, Sales)
- Network infrastructure (routers, L3 switches, firewalls)
- IoT devices (cameras, printers, HVAC, badge readers)
- Security infrastructure (SIEM, backup, AV server)

Tests:
1. Full auto-enumeration with VLAN bypass
2. Credential looting at each phase
3. Lateral movement across VLANs
4. Report and diagram generation
"""

import sys
import os
import json
import shutil
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import Dict, List, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


# ============================================================================
# COMPANY NETWORK DEFINITION
# ============================================================================

class AcmeCorp:
    """Simulated medium-sized company: Acme Corporation
    
    ~500 employees, technology/manufacturing sector
    Headquarters with single campus network
    """
    
    COMPANY_NAME = "Acme Corporation"
    DOMAIN = "ACMECORP"
    DNS_SUFFIX = "acmecorp.local"
    
    # VLAN Definitions
    VLANS = {
        1: {"name": "Native", "subnet": "10.0.1.0/24", "gateway": "10.0.1.1"},
        10: {"name": "Management", "subnet": "10.0.10.0/24", "gateway": "10.0.10.1"},
        20: {"name": "Servers", "subnet": "10.0.20.0/24", "gateway": "10.0.20.1"},
        30: {"name": "Users-IT", "subnet": "10.0.30.0/24", "gateway": "10.0.30.1"},
        31: {"name": "Users-Finance", "subnet": "10.0.31.0/24", "gateway": "10.0.31.1"},
        32: {"name": "Users-HR", "subnet": "10.0.32.0/24", "gateway": "10.0.32.1"},
        33: {"name": "Users-Engineering", "subnet": "10.0.33.0/24", "gateway": "10.0.33.1"},
        34: {"name": "Users-Sales", "subnet": "10.0.34.0/24", "gateway": "10.0.34.1"},
        50: {"name": "DMZ", "subnet": "10.0.50.0/24", "gateway": "10.0.50.1"},
        60: {"name": "IoT", "subnet": "10.0.60.0/24", "gateway": "10.0.60.1"},
        70: {"name": "VoIP", "subnet": "10.0.70.0/24", "gateway": "10.0.70.1"},
        100: {"name": "Security", "subnet": "10.0.100.0/24", "gateway": "10.0.100.1"},
        200: {"name": "Guest", "subnet": "10.0.200.0/24", "gateway": "10.0.200.1"},
    }
    
    # Network Infrastructure
    NETWORK_DEVICES = [
        # Core Infrastructure
        {"ip": "10.0.10.1", "hostname": "CORE-RTR01", "type": "Router", "vendor": "Cisco", "model": "ISR 4451", "vlan": 10, "role": "Core Router"},
        {"ip": "10.0.10.2", "hostname": "CORE-SW01", "type": "L3 Switch", "vendor": "Cisco", "model": "Catalyst 9500", "vlan": 10, "role": "Core Switch"},
        {"ip": "10.0.10.3", "hostname": "CORE-SW02", "type": "L3 Switch", "vendor": "Cisco", "model": "Catalyst 9500", "vlan": 10, "role": "Core Switch"},
        {"ip": "10.0.10.5", "hostname": "FW-EXTERNAL", "type": "Firewall", "vendor": "Palo Alto", "model": "PA-3260", "vlan": 10, "role": "Perimeter Firewall"},
        {"ip": "10.0.10.6", "hostname": "FW-INTERNAL", "type": "Firewall", "vendor": "Fortinet", "model": "FortiGate 200F", "vlan": 10, "role": "Internal Firewall"},
        
        # Distribution Switches
        {"ip": "10.0.10.11", "hostname": "DIST-SW01", "type": "L2 Switch", "vendor": "Cisco", "model": "Catalyst 9300", "vlan": 10, "role": "Distribution"},
        {"ip": "10.0.10.12", "hostname": "DIST-SW02", "type": "L2 Switch", "vendor": "Cisco", "model": "Catalyst 9300", "vlan": 10, "role": "Distribution"},
        {"ip": "10.0.10.13", "hostname": "DIST-SW03", "type": "L2 Switch", "vendor": "Cisco", "model": "Catalyst 9300", "vlan": 10, "role": "Distribution"},
        
        # Wireless
        {"ip": "10.0.10.20", "hostname": "WLC01", "type": "Wireless Controller", "vendor": "Cisco", "model": "C9800-40", "vlan": 10, "role": "Wireless Controller"},
    ]
    
    # Servers
    SERVERS = [
        # Domain Controllers
        {"ip": "10.0.20.10", "hostname": "DC01", "os": "Windows Server 2022", "role": "Primary Domain Controller", "vlan": 20, "services": ["AD DS", "DNS", "DHCP"]},
        {"ip": "10.0.20.11", "hostname": "DC02", "os": "Windows Server 2022", "role": "Secondary Domain Controller", "vlan": 20, "services": ["AD DS", "DNS"]},
        
        # File Servers
        {"ip": "10.0.20.20", "hostname": "FS01", "os": "Windows Server 2022", "role": "Primary File Server", "vlan": 20, "services": ["SMB", "DFS"], "shares": ["Users$", "Departments$", "Software$"]},
        {"ip": "10.0.20.21", "hostname": "FS02", "os": "Windows Server 2022", "role": "Secondary File Server", "vlan": 20, "services": ["SMB", "DFS"]},
        
        # Database Servers
        {"ip": "10.0.20.30", "hostname": "SQL01", "os": "Windows Server 2022", "role": "SQL Server (Production)", "vlan": 20, "services": ["MSSQL"], "databases": ["ERP", "CRM", "HR"]},
        {"ip": "10.0.20.31", "hostname": "SQL02", "os": "Windows Server 2022", "role": "SQL Server (Reporting)", "vlan": 20, "services": ["MSSQL", "SSRS"]},
        
        # Application Servers
        {"ip": "10.0.20.40", "hostname": "APP01", "os": "Windows Server 2022", "role": "ERP Application Server", "vlan": 20, "services": ["IIS", "ERP"]},
        {"ip": "10.0.20.41", "hostname": "APP02", "os": "Windows Server 2022", "role": "CRM Application Server", "vlan": 20, "services": ["IIS", "CRM"]},
        {"ip": "10.0.20.42", "hostname": "APP03", "os": "Windows Server 2019", "role": "Legacy Application Server", "vlan": 20, "services": ["IIS"]},
        
        # Email
        {"ip": "10.0.20.50", "hostname": "EXCH01", "os": "Windows Server 2019", "role": "Exchange Server", "vlan": 20, "services": ["Exchange", "SMTP", "IMAP"]},
        
        # Print Server
        {"ip": "10.0.20.60", "hostname": "PRINT01", "os": "Windows Server 2022", "role": "Print Server", "vlan": 20, "services": ["Print Spooler"]},
        
        # WSUS/SCCM
        {"ip": "10.0.20.70", "hostname": "WSUS01", "os": "Windows Server 2022", "role": "WSUS Server", "vlan": 20, "services": ["WSUS"]},
        {"ip": "10.0.20.71", "hostname": "SCCM01", "os": "Windows Server 2022", "role": "SCCM Server", "vlan": 20, "services": ["SCCM"]},
        
        # Virtualization
        {"ip": "10.0.20.80", "hostname": "VCENTER01", "os": "VMware vCenter", "role": "vCenter Server", "vlan": 20, "services": ["vCenter"]},
        {"ip": "10.0.20.81", "hostname": "ESX01", "os": "VMware ESXi 8.0", "role": "ESXi Host", "vlan": 20, "services": ["ESXi"]},
        {"ip": "10.0.20.82", "hostname": "ESX02", "os": "VMware ESXi 8.0", "role": "ESXi Host", "vlan": 20, "services": ["ESXi"]},
        {"ip": "10.0.20.83", "hostname": "ESX03", "os": "VMware ESXi 8.0", "role": "ESXi Host", "vlan": 20, "services": ["ESXi"]},
    ]
    
    # DMZ Servers
    DMZ_SERVERS = [
        {"ip": "10.0.50.10", "hostname": "WEB01", "os": "Ubuntu 22.04", "role": "Public Web Server", "vlan": 50, "services": ["nginx", "PHP"]},
        {"ip": "10.0.50.11", "hostname": "WEB02", "os": "Ubuntu 22.04", "role": "Public Web Server", "vlan": 50, "services": ["nginx", "PHP"]},
        {"ip": "10.0.50.20", "hostname": "MAIL-GW01", "os": "Linux", "role": "Mail Gateway", "vlan": 50, "services": ["Postfix", "SpamAssassin"]},
        {"ip": "10.0.50.30", "hostname": "VPN01", "os": "Linux", "role": "VPN Gateway", "vlan": 50, "services": ["OpenVPN"]},
        {"ip": "10.0.50.40", "hostname": "PROXY01", "os": "Linux", "role": "Reverse Proxy", "vlan": 50, "services": ["HAProxy"]},
    ]
    
    # Security Infrastructure
    SECURITY_SERVERS = [
        {"ip": "10.0.100.10", "hostname": "SIEM01", "os": "Linux", "role": "SIEM Server", "vlan": 100, "services": ["Splunk"]},
        {"ip": "10.0.100.11", "hostname": "SIEM-IDX01", "os": "Linux", "role": "SIEM Indexer", "vlan": 100, "services": ["Splunk Indexer"]},
        {"ip": "10.0.100.20", "hostname": "AV-MGR01", "os": "Windows Server 2022", "role": "Antivirus Management", "vlan": 100, "services": ["Defender ATP"]},
        {"ip": "10.0.100.30", "hostname": "BACKUP01", "os": "Windows Server 2022", "role": "Backup Server", "vlan": 100, "services": ["Veeam"]},
        {"ip": "10.0.100.31", "hostname": "BACKUP02", "os": "Linux", "role": "Backup Storage", "vlan": 100, "services": ["NFS", "iSCSI"]},
        {"ip": "10.0.100.40", "hostname": "PKI01", "os": "Windows Server 2022", "role": "Certificate Authority", "vlan": 100, "services": ["AD CS"]},
        {"ip": "10.0.100.50", "hostname": "JUMP01", "os": "Windows Server 2022", "role": "Jump Server / PAW", "vlan": 100, "services": ["RDP Gateway"]},
    ]
    
    # User Workstations (sample per department)
    WORKSTATIONS = [
        # IT Department (VLAN 30)
        {"ip": "10.0.30.10", "hostname": "WS-IT-ADMIN01", "os": "Windows 11", "user": "it_admin", "dept": "IT", "vlan": 30, "admin": True},
        {"ip": "10.0.30.11", "hostname": "WS-IT-ADMIN02", "os": "Windows 11", "user": "it_admin2", "dept": "IT", "vlan": 30, "admin": True},
        {"ip": "10.0.30.20", "hostname": "WS-IT-HELPDESK01", "os": "Windows 11", "user": "helpdesk1", "dept": "IT", "vlan": 30, "admin": False},
        {"ip": "10.0.30.21", "hostname": "WS-IT-HELPDESK02", "os": "Windows 11", "user": "helpdesk2", "dept": "IT", "vlan": 30, "admin": False},
        
        # Finance Department (VLAN 31)
        {"ip": "10.0.31.10", "hostname": "WS-FIN-CFO", "os": "Windows 11", "user": "cfo", "dept": "Finance", "vlan": 31, "admin": False},
        {"ip": "10.0.31.11", "hostname": "WS-FIN-ACCT01", "os": "Windows 11", "user": "accountant1", "dept": "Finance", "vlan": 31, "admin": False},
        {"ip": "10.0.31.12", "hostname": "WS-FIN-ACCT02", "os": "Windows 11", "user": "accountant2", "dept": "Finance", "vlan": 31, "admin": False},
        
        # HR Department (VLAN 32)
        {"ip": "10.0.32.10", "hostname": "WS-HR-DIR", "os": "Windows 11", "user": "hr_director", "dept": "HR", "vlan": 32, "admin": False},
        {"ip": "10.0.32.11", "hostname": "WS-HR-REC01", "os": "Windows 11", "user": "recruiter1", "dept": "HR", "vlan": 32, "admin": False},
        
        # Engineering Department (VLAN 33)
        {"ip": "10.0.33.10", "hostname": "WS-ENG-LEAD01", "os": "Windows 11", "user": "eng_lead", "dept": "Engineering", "vlan": 33, "admin": False},
        {"ip": "10.0.33.11", "hostname": "WS-ENG-DEV01", "os": "Ubuntu 22.04", "user": "developer1", "dept": "Engineering", "vlan": 33, "admin": False},
        {"ip": "10.0.33.12", "hostname": "WS-ENG-DEV02", "os": "macOS", "user": "developer2", "dept": "Engineering", "vlan": 33, "admin": False},
        
        # Sales Department (VLAN 34)
        {"ip": "10.0.34.10", "hostname": "WS-SALES-DIR", "os": "Windows 11", "user": "sales_director", "dept": "Sales", "vlan": 34, "admin": False},
        {"ip": "10.0.34.11", "hostname": "WS-SALES-REP01", "os": "Windows 11", "user": "sales_rep1", "dept": "Sales", "vlan": 34, "admin": False},
    ]
    
    # IoT Devices
    IOT_DEVICES = [
        # Cameras
        {"ip": "10.0.60.10", "hostname": "CAM-LOBBY01", "type": "IP Camera", "vendor": "Hikvision", "model": "DS-2CD2143G2", "vlan": 60, "location": "Lobby"},
        {"ip": "10.0.60.11", "hostname": "CAM-PARKING01", "type": "IP Camera", "vendor": "Hikvision", "model": "DS-2CD2143G2", "vlan": 60, "location": "Parking"},
        {"ip": "10.0.60.12", "hostname": "CAM-DATACENTER", "type": "IP Camera", "vendor": "Axis", "model": "P3245-V", "vlan": 60, "location": "Datacenter"},
        {"ip": "10.0.60.13", "hostname": "CAM-WAREHOUSE01", "type": "IP Camera", "vendor": "Dahua", "model": "IPC-HDBW2431E", "vlan": 60, "location": "Warehouse"},
        
        # Printers
        {"ip": "10.0.60.20", "hostname": "PRN-IT01", "type": "Network Printer", "vendor": "HP", "model": "LaserJet Enterprise M507", "vlan": 60, "location": "IT Floor"},
        {"ip": "10.0.60.21", "hostname": "PRN-FIN01", "type": "Network Printer", "vendor": "Xerox", "model": "VersaLink C7025", "vlan": 60, "location": "Finance"},
        {"ip": "10.0.60.22", "hostname": "PRN-LOBBY01", "type": "Network Printer", "vendor": "Canon", "model": "imageRUNNER", "vlan": 60, "location": "Lobby"},
        
        # Building Automation
        {"ip": "10.0.60.30", "hostname": "HVAC-CTRL01", "type": "HVAC Controller", "vendor": "Honeywell", "model": "WEB-8000", "vlan": 60, "location": "Building"},
        {"ip": "10.0.60.31", "hostname": "BMS-CTRL01", "type": "Building Management", "vendor": "Siemens", "model": "Desigo CC", "vlan": 60, "location": "Building"},
        
        # Access Control
        {"ip": "10.0.60.40", "hostname": "BADGE-CTRL01", "type": "Badge Reader Controller", "vendor": "HID", "model": "VertX V1000", "vlan": 60, "location": "Main Entrance"},
        {"ip": "10.0.60.41", "hostname": "BADGE-CTRL02", "type": "Badge Reader Controller", "vendor": "HID", "model": "VertX V1000", "vlan": 60, "location": "Datacenter"},
    ]
    
    # Service Accounts
    SERVICE_ACCOUNTS = [
        {"username": "svc_backup", "domain": "ACMECORP", "description": "Veeam Backup Service", "password": "B@ckup2024!Secure"},
        {"username": "svc_sql", "domain": "ACMECORP", "description": "SQL Server Service", "password": "SQL$3rv1c3!2024"},
        {"username": "svc_sccm", "domain": "ACMECORP", "description": "SCCM Service Account", "password": "SCCM@ccount2024"},
        {"username": "svc_exchange", "domain": "ACMECORP", "description": "Exchange Service", "password": "Exch@ng32024!"},
        {"username": "svc_web", "domain": "ACMECORP", "description": "Web Application Pool", "password": "W3bApp2024!"},
        {"username": "svc_scan", "domain": "ACMECORP", "description": "Vulnerability Scanner", "password": "Sc@n2024!Vuln"},
    ]
    
    # Privileged Accounts
    PRIVILEGED_ACCOUNTS = [
        {"username": "Administrator", "domain": "ACMECORP", "type": "Domain Admin", "hash": "aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff"},
        {"username": "DA_Admin", "domain": "ACMECORP", "type": "Domain Admin", "hash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"},
        {"username": "krbtgt", "domain": "ACMECORP", "type": "Kerberos TGT", "hash": "aad3b435b51404eeaad3b435b51404ee:b21c99fc068e3ab2ca789bccbef67de4"},
    ]
    
    # Default Credentials (misconfigurations)
    DEFAULT_CREDS = [
        {"target": "10.0.10.11", "hostname": "DIST-SW01", "username": "cisco", "password": "cisco", "protocol": "ssh"},
        {"target": "10.0.60.10", "hostname": "CAM-LOBBY01", "username": "admin", "password": "12345", "protocol": "http"},
        {"target": "10.0.60.30", "hostname": "HVAC-CTRL01", "username": "admin", "password": "admin", "protocol": "http"},
        {"target": "10.0.100.50", "hostname": "JUMP01", "username": "test", "password": "test", "protocol": "ssh"},
    ]
    
    @classmethod
    def get_all_machines(cls) -> List[Dict]:
        """Get all machines in the network"""
        machines = []
        machines.extend(cls.NETWORK_DEVICES)
        machines.extend(cls.SERVERS)
        machines.extend(cls.DMZ_SERVERS)
        machines.extend(cls.SECURITY_SERVERS)
        machines.extend(cls.WORKSTATIONS)
        machines.extend(cls.IOT_DEVICES)
        return machines
    
    @classmethod
    def get_machine_count(cls) -> Dict[str, int]:
        """Get count of machines by category"""
        return {
            "Network Devices": len(cls.NETWORK_DEVICES),
            "Servers": len(cls.SERVERS),
            "DMZ Servers": len(cls.DMZ_SERVERS),
            "Security Infrastructure": len(cls.SECURITY_SERVERS),
            "Workstations": len(cls.WORKSTATIONS),
            "IoT Devices": len(cls.IOT_DEVICES),
            "Total": len(cls.get_all_machines()),
        }
    
    @classmethod
    def get_vlan_routing(cls) -> Dict[int, List[int]]:
        """Get inter-VLAN routing rules"""
        return {
            10: [20, 30, 31, 32, 33, 34, 50, 60, 70, 100, 200],  # Management can reach all
            20: [10, 30, 31, 32, 33, 34, 100],  # Servers can reach users and security
            30: [10, 20, 31, 32, 33, 34, 50],  # IT can reach most VLANs
            31: [20, 30],  # Finance limited access
            32: [20, 30],  # HR limited access
            33: [20, 30, 50],  # Engineering can reach DMZ
            34: [20, 30],  # Sales limited access
            50: [10],  # DMZ very limited
            60: [10],  # IoT isolated (management only)
            70: [10],  # VoIP isolated
            100: [10, 20],  # Security can reach management and servers
            200: [],  # Guest isolated
        }


# ============================================================================
# SIMULATION ENGINE
# ============================================================================

class NetworkSimulator:
    """Simulates network responses for enumeration"""
    
    def __init__(self, company: type = AcmeCorp):
        self.company = company
        self.current_host = "10.0.30.10"  # Start from IT admin workstation
        self.current_vlan = 30
        self.discovered_hosts = set()
        self.looted_credentials = []
    
    def get_command_response(self, command: str) -> tuple:
        """Simulate command execution"""
        cmd_lower = command.lower()
        
        # Hostname
        if cmd_lower == "hostname":
            return (0, "WS-IT-ADMIN01\n", "")
        
        # Whoami
        if "whoami" in cmd_lower:
            if "/groups" in cmd_lower:
                return (0, self._get_groups_output(), "")
            elif "/priv" in cmd_lower:
                return (0, self._get_privs_output(), "")
            return (0, f"{self.company.DOMAIN}\\it_admin\n", "")
        
        # Network commands
        if "ipconfig" in cmd_lower:
            return (0, self._get_ipconfig_output(), "")
        
        if "arp -a" in cmd_lower:
            return (0, self._get_arp_output(), "")
        
        if "route print" in cmd_lower:
            return (0, self._get_route_output(), "")
        
        # Credential commands
        if "cmdkey /list" in cmd_lower:
            return (0, self._get_cmdkey_output(), "")
        
        if "vaultcmd" in cmd_lower:
            return (0, "Vault: Windows Credentials\nScheme: Domain Password\n", "")
        
        # Domain commands
        if "net group" in cmd_lower and "domain" in cmd_lower:
            if "domain admins" in cmd_lower.lower():
                return (0, self._get_domain_admins_output(), "")
            return (0, self._get_domain_groups_output(), "")
        
        if "net localgroup" in cmd_lower:
            return (0, self._get_local_groups_output(), "")
        
        if "net view" in cmd_lower:
            return (0, self._get_net_view_output(), "")
        
        if "nltest" in cmd_lower:
            return (0, f"List of domain controllers:\n  DC01.{self.company.DNS_SUFFIX}\n  DC02.{self.company.DNS_SUFFIX}\n", "")
        
        # System info
        if "systeminfo" in cmd_lower:
            return (0, self._get_systeminfo_output(), "")
        
        if "netstat" in cmd_lower:
            return (0, self._get_netstat_output(), "")
        
        # Default
        return (0, "", "")
    
    def get_powershell_response(self, command: str) -> tuple:
        """Simulate PowerShell execution"""
        cmd_lower = command.lower()
        
        if "get-process" in cmd_lower:
            if "lsass" in cmd_lower:
                return (0, "Id: 732\nProcessName: lsass\n", "")
            return (0, self._get_process_output(), "")
        
        if "get-service" in cmd_lower:
            return (0, self._get_services_output(), "")
        
        if "get-scheduledtask" in cmd_lower:
            return (0, self._get_scheduled_tasks_output(), "")
        
        if "win32_service" in cmd_lower:
            return (0, self._get_win32_services_output(), "")
        
        if "test-wsman" in cmd_lower:
            return (0, "wsmid: http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd\n", "")
        
        if "windowsidentity" in cmd_lower:
            return (0, "IsSystem: False\nIsAdmin: True\nUserSID: S-1-5-21-xxx\n", "")
        
        return (0, "", "")
    
    def _get_groups_output(self) -> str:
        return """GROUP INFORMATION
-----------------

Group Name                           Type             SID
==================================== ================ ========
ACMECORP\\Domain Users                Group            S-1-5-21-xxx-513
ACMECORP\\IT Admins                   Group            S-1-5-21-xxx-1108
ACMECORP\\Workstation Admins          Group            S-1-5-21-xxx-1109
BUILTIN\\Administrators               Alias            S-1-5-32-544
NT AUTHORITY\\Authenticated Users      Well-known group S-1-5-11
"""
    
    def _get_privs_output(self) -> str:
        return """PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                     State
============================== =============================== ========
SeDebugPrivilege                Debug programs                   Enabled
SeBackupPrivilege               Back up files and directories    Enabled
SeRestorePrivilege              Restore files and directories    Enabled
SeShutdownPrivilege             Shut down the system            Enabled
SeChangeNotifyPrivilege         Bypass traverse checking        Enabled
SeImpersonatePrivilege          Impersonate a client            Enabled
"""
    
    def _get_ipconfig_output(self) -> str:
        return f"""Windows IP Configuration

Ethernet adapter Ethernet0:
   Connection-specific DNS Suffix  . : {self.company.DNS_SUFFIX}
   IPv4 Address. . . . . . . . . . . : {self.current_host}
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.30.1
   DNS Servers . . . . . . . . . . . : 10.0.20.10
                                       10.0.20.11
"""
    
    def _get_arp_output(self) -> str:
        arp_entries = []
        # Add gateway and nearby hosts
        machines = self.company.get_all_machines()
        for m in machines[:20]:  # Limit ARP entries
            arp_entries.append(f"  {m['ip']}          00-50-56-xx-xx-xx     dynamic")
        return "Interface: 10.0.30.10\n" + "\n".join(arp_entries)
    
    def _get_route_output(self) -> str:
        return """IPv4 Route Table
===========================================================================
Network Destination    Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      10.0.30.1     10.0.30.10     10
       10.0.20.0    255.255.255.0      10.0.30.1     10.0.30.10     10
       10.0.30.0    255.255.255.0         On-link     10.0.30.10    266
      10.0.100.0    255.255.255.0      10.0.30.1     10.0.30.10     10
"""
    
    def _get_cmdkey_output(self) -> str:
        return f"""Currently stored credentials:

    Target: Domain:target=FS01
    Type: Domain Password
    User: {self.company.DOMAIN}\\svc_fileaccess

    Target: Domain:target=SQL01
    Type: Domain Password
    User: {self.company.DOMAIN}\\svc_sql

    Target: Domain:target=BACKUP01
    Type: Domain Password
    User: {self.company.DOMAIN}\\svc_backup
"""
    
    def _get_domain_admins_output(self) -> str:
        return f"""Group name     Domain Admins
Members
-------------------------------------------------------------------------------
Administrator
DA_Admin
it_admin
The command completed successfully.
"""
    
    def _get_domain_groups_output(self) -> str:
        return """Group Accounts for \\\\ACMECORP
-------------------------------------------------------------------------------
*Backup Operators
*Domain Admins
*Domain Users
*Enterprise Admins
*IT Admins
*Schema Admins
*SQL Admins
*Workstation Admins
The command completed successfully.
"""
    
    def _get_local_groups_output(self) -> str:
        return """Aliases for \\\\WS-IT-ADMIN01
-------------------------------------------------------------------------------
*Administrators
*Backup Operators
*Remote Desktop Users
*Users
The command completed successfully.
"""
    
    def _get_net_view_output(self) -> str:
        output = "Shared resources at \\\\FS01\n\n"
        output += "Share name   Type  Used as  Comment\n"
        output += "-------------------------------------------------------------------------------\n"
        output += "Users$       Disk           User home directories\n"
        output += "Departments$ Disk           Department shares\n"
        output += "Software$    Disk           Software distribution\n"
        return output
    
    def _get_systeminfo_output(self) -> str:
        return f"""Host Name:                 WS-IT-ADMIN01
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22631 N/A Build 22631
System Type:               x64-based PC
Domain:                    {self.company.DNS_SUFFIX}
Logon Server:              \\\\DC01
"""
    
    def _get_netstat_output(self) -> str:
        return """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1012
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1456
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5986           0.0.0.0:0              LISTENING       4
  TCP    10.0.30.10:49152       10.0.20.10:389         ESTABLISHED     1284
"""
    
    def _get_process_output(self) -> str:
        return """ProcessName                  Id
-----------                  --
lsass                       732
svchost                    1012
explorer                   4568
powershell                 8824
defender                   2156
"""
    
    def _get_services_output(self) -> str:
        return """Name                 DisplayName                           Status
----                 -----------                           ------
WinRM                Windows Remote Management             Running
RemoteRegistry       Remote Registry                       Running
Spooler              Print Spooler                         Running
MSSQLSERVER          SQL Server                            Running
W3SVC                World Wide Web Publishing Service     Running
"""
    
    def _get_scheduled_tasks_output(self) -> str:
        return """TaskName                     State    LastRunTime
--------                     -----    -----------
BackupTask                   Ready    12/4/2025 2:00:00 AM
UpdateScanner                Ready    12/4/2025 3:00:00 AM
CacheCleanup                 Ready    12/4/2025 1:00:00 AM
"""
    
    def _get_win32_services_output(self) -> str:
        output = ""
        for svc in self.company.SERVICE_ACCOUNTS[:5]:
            output += f"Name: {svc['description']}\nStartName: {svc['domain']}\\{svc['username']}\nState: Running\n\n"
        return output


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_medium_company_simulation():
    """Run the medium company network simulation"""
    console = Console()
    
    # Header
    console.print("\n")
    console.print(Panel.fit(
        f"[bold cyan]{AcmeCorp.COMPANY_NAME} Network Simulation[/bold cyan]\n\n"
        f"Domain: [yellow]{AcmeCorp.DOMAIN}[/yellow]\n"
        f"DNS: [yellow]{AcmeCorp.DNS_SUFFIX}[/yellow]\n\n"
        f"Simulating auto-enumeration with VLAN bypass\n"
        f"and credential looting across the enterprise network.",
        title="🏢 Enterprise Network Test",
        border_style="cyan"
    ))
    
    # Show network statistics
    console.print("\n[bold]Network Composition:[/bold]")
    counts = AcmeCorp.get_machine_count()
    
    stats_table = Table(box=box.SIMPLE)
    stats_table.add_column("Category", style="cyan")
    stats_table.add_column("Count", style="green", justify="right")
    
    for category, count in counts.items():
        if category == "Total":
            stats_table.add_row(f"[bold]{category}[/bold]", f"[bold]{count}[/bold]")
        else:
            stats_table.add_row(category, str(count))
    
    console.print(stats_table)
    
    # Show VLAN structure
    console.print("\n[bold]VLAN Structure:[/bold]")
    vlan_table = Table(box=box.SIMPLE)
    vlan_table.add_column("VLAN", style="cyan", justify="right")
    vlan_table.add_column("Name", style="white")
    vlan_table.add_column("Subnet", style="yellow")
    
    for vlan_id, info in list(AcmeCorp.VLANS.items())[:8]:
        vlan_table.add_row(str(vlan_id), info["name"], info["subnet"])
    
    console.print(vlan_table)
    console.print(f"[dim]... and {len(AcmeCorp.VLANS) - 8} more VLANs[/dim]")
    
    # Initialize simulator
    simulator = NetworkSimulator(AcmeCorp)
    
    # Patch execute functions
    with patch('modules.auto_enumerate.execute_cmd') as mock_cmd, \
         patch('modules.auto_enumerate.execute_powershell') as mock_ps:
        
        mock_cmd.side_effect = lambda cmd, **kwargs: simulator.get_command_response(cmd)
        mock_ps.side_effect = lambda cmd, **kwargs: simulator.get_powershell_response(cmd)
        
        # Import and run auto enumeration
        from modules.auto_enumerate import AutoEnumerator
        from modules.credential_manager import get_credential_manager
        
        # Reset credential manager for clean test
        import modules.credential_manager as cm
        cm._credential_manager = None
        
        session_data = {
            'LAB_USE': 1,
            'AUTO_ENUMERATE_DEPTH': 4,
            'is_local_ip': lambda x: x.startswith('10.0.'),
        }
        
        console.print("\n[bold cyan]Starting Auto-Enumeration...[/bold cyan]\n")
        
        # Run enumeration
        enumerator = AutoEnumerator(console, session_data)
        start_time = time.time()
        
        try:
            results = enumerator.run_full_enumeration()
            elapsed = time.time() - start_time
        except Exception as e:
            console.print(f"[red]Enumeration error: {e}[/red]")
            import traceback
            traceback.print_exc()
            return
        
        console.print(f"\n[green]✓ Enumeration completed in {elapsed:.2f} seconds[/green]\n")
        
        # Show enumeration results
        console.print(Panel("[bold]Enumeration Results[/bold]", border_style="green"))
        
        # Foothold
        foothold = results.get('foothold', {})
        console.print(f"\n[bold]Foothold:[/bold]")
        console.print(f"  Identity: {foothold.get('identity', 'Unknown')}")
        console.print(f"  Role: {foothold.get('role', 'Unknown')}")
        console.print(f"  SYSTEM: {foothold.get('has_system', False)}")
        
        # Network discovery
        network = results.get('network', {})
        console.print(f"\n[bold]Network Discovery:[/bold]")
        console.print(f"  Local IPs: {len(network.get('local_ips', []))}")
        console.print(f"  ARP targets: {len(network.get('arp_targets', []))}")
        
        # Lateral targets
        lateral = results.get('lateral_targets', [])
        console.print(f"\n[bold]Lateral Movement:[/bold]")
        console.print(f"  Targets discovered: {len(lateral)}")
        
        # VLAN bypass
        vlan_bypass = results.get('vlan_bypass', {})
        console.print(f"\n[bold]VLAN Bypass:[/bold]")
        console.print(f"  VLANs discovered: {len(vlan_bypass.get('discovered_vlans', []))}")
        console.print(f"  Network devices: {len(vlan_bypass.get('network_devices', []))}")
        console.print(f"  Default creds found: {len(vlan_bypass.get('default_credentials_found', []))}")
        console.print(f"  Vulnerable CVEs: {len(vlan_bypass.get('vulnerable_cves', []))}")
        console.print(f"  Bypass techniques: {len(vlan_bypass.get('bypass_techniques', []))}")
        
        # Show bypass techniques
        if vlan_bypass.get('bypass_techniques'):
            console.print("\n  [yellow]Bypass Opportunities:[/yellow]")
            for tech in vlan_bypass.get('bypass_techniques', [])[:5]:
                console.print(f"    • {tech.get('technique', 'Unknown')}: {tech.get('target', 'N/A')} ({tech.get('likelihood', 'N/A')})")
        
        # Credential store
        cred_store = results.get('credential_store', {})
        console.print(f"\n[bold]Credential Store:[/bold]")
        console.print(f"  Total credentials: {cred_store.get('total', 0)}")
        console.print(f"  Valid/Tested: {cred_store.get('valid', 0)}/{cred_store.get('tested', 0)}")
        
        if cred_store.get('by_type'):
            console.print("  By type:")
            for cred_type, count in list(cred_store.get('by_type', {}).items())[:5]:
                console.print(f"    • {cred_type}: {count}")
        
        # Get credential manager and show details
        cred_manager = get_credential_manager()
        
        console.print("\n[bold]Looted Credentials (Sample):[/bold]")
        creds_table = Table(box=box.ROUNDED)
        creds_table.add_column("Type", style="cyan")
        creds_table.add_column("Username", style="white")
        creds_table.add_column("Domain", style="yellow")
        creds_table.add_column("Target", style="dim")
        creds_table.add_column("Source", style="green")
        
        for cred in list(cred_manager.credentials.values())[:10]:
            creds_table.add_row(
                cred.cred_type[:15],
                cred.username[:20],
                cred.domain[:15] if cred.domain else "-",
                cred.target[:20] if cred.target else "-",
                cred.source[:15]
            )
        
        console.print(creds_table)
        
        if len(cred_manager.credentials) > 10:
            console.print(f"[dim]... and {len(cred_manager.credentials) - 10} more credentials[/dim]")
        
        # Check for loot directory
        loot_dir = Path("loot")
        if loot_dir.exists():
            console.print(f"\n[bold]Loot Directory:[/bold]")
            cred_file = loot_dir / "credentials" / "credentials.json"
            if cred_file.exists():
                console.print(f"  [green]✓[/green] {cred_file}")
                console.print(f"    Size: {cred_file.stat().st_size} bytes")
        
        # Export credentials
        console.print("\n[bold]Exporting Credentials:[/bold]")
        try:
            csv_path = cred_manager.export_credentials_csv()
            console.print(f"  [green]✓[/green] CSV: {csv_path}")
            
            hash_path = cred_manager.export_hashcat()
            console.print(f"  [green]✓[/green] Hashcat: {hash_path}")
        except Exception as e:
            console.print(f"  [yellow]Export error: {e}[/yellow]")
        
        # Summary
        console.print("\n" + "=" * 60)
        console.print("[bold green]SIMULATION COMPLETE[/bold green]")
        console.print("=" * 60)
        
        summary = f"""
[bold]Summary:[/bold]
• Network: {AcmeCorp.COMPANY_NAME} ({counts['Total']} machines)
• VLANs: {len(AcmeCorp.VLANS)} segments
• Enumeration time: {elapsed:.2f}s
• Credentials looted: {len(cred_manager.credentials)}
• Lateral targets: {len(lateral)}
• VLAN bypass opportunities: {len(vlan_bypass.get('bypass_techniques', []))}
"""
        console.print(summary)
        
        # Return results for testing
        return {
            'results': results,
            'credentials': len(cred_manager.credentials),
            'elapsed': elapsed,
            'company': AcmeCorp,
        }


if __name__ == '__main__':
    run_medium_company_simulation()
