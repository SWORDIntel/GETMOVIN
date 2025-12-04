"""Diagram Generation Module for Auto Enumeration

Generates Mermaid diagrams for:
- MITRE ATT&CK attack flow maps
- Network topology diagrams
- Lateral movement path diagrams
- Privilege escalation flow diagrams
- System architecture diagrams
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path


class DiagramGenerator:
    """Generate Mermaid diagrams from enumeration data"""
    
    def __init__(self, enumeration_data: Dict[str, Any]):
        self.data = enumeration_data
        self.diagrams = {}
    
    def generate_all_diagrams(self) -> Dict[str, str]:
        """Generate all available diagrams"""
        self.diagrams['mitre_attack_flow'] = self.generate_mitre_attack_flow()
        self.diagrams['network_topology'] = self.generate_network_diagram()
        self.diagrams['lateral_movement'] = self.generate_lateral_movement_diagram()
        self.diagrams['privilege_escalation'] = self.generate_privilege_escalation_diagram()
        self.diagrams['system_architecture'] = self.generate_system_architecture_diagram()
        self.diagrams['attack_timeline'] = self.generate_attack_timeline()
        return self.diagrams
    
    def generate_mitre_attack_flow(self) -> str:
        """Generate MITRE ATT&CK attack flow diagram"""
        mermaid = ["graph TD"]
        
        # Initial Access
        mermaid.append("    A[Initial Access<br/>T1190, T1078] --> B[Foothold Establishment]")
        
        # Foothold
        foothold = self.data.get('foothold', {})
        if foothold.get('has_system'):
            mermaid.append("    B --> C[SYSTEM Privileges<br/>T1068, T1134]")
        elif foothold.get('identity'):
            mermaid.append("    B --> C[User Context<br/>" + foothold.get('identity', 'Unknown')[:20] + "]")
        else:
            mermaid.append("    B --> C[Foothold Context]")
        
        # Discovery
        mermaid.append("    C --> D[Discovery<br/>T1082, T1018, T1087]")
        
        # Network Discovery
        network = self.data.get('network', {})
        if network.get('local_ips') or network.get('arp_targets'):
            mermaid.append("    D --> E[Network Discovery<br/>T1018, T1049]")
            mermaid.append("    E --> F[Target Identification]")
        else:
            mermaid.append("    D --> F[Target Identification]")
        
        # Credential Access
        identity = self.data.get('identity', {})
        if identity.get('stored_credentials') or identity.get('vault_credentials'):
            mermaid.append("    F --> G[Credential Access<br/>T1003, T1555, T1556]")
            mermaid.append("    G --> H[Lateral Movement]")
        else:
            mermaid.append("    F --> H[Lateral Movement<br/>T1021, T1072]")
        
        # Lateral Movement Paths
        lateral_paths = self.data.get('lateral_paths', [])
        if lateral_paths:
            for i, path_info in enumerate(lateral_paths[:5], 1):
                path = path_info.get('path', [])
                method = path_info.get('method', 'unknown')
                if len(path) >= 2:
                    mermaid.append(f"    H --> I{i}[Lateral Path {i}<br/>{method}<br/>{' -> '.join(path[-2:])}]")
        
        # Privilege Escalation
        pe = self.data.get('privilege_escalation', {})
        if pe.get('pe5_available'):
            mermaid.append("    H --> J[Privilege Escalation<br/>PE5 Framework<br/>T1068, T1134]")
        elif pe.get('pe_techniques'):
            mermaid.append("    H --> J[Privilege Escalation<br/>T1068, T1134]")
        else:
            mermaid.append("    H --> J[Privilege Escalation]")
        
        if pe.get('escalation_successful'):
            mermaid.append("    J --> K[SYSTEM Access<br/>T1134.001]")
        else:
            mermaid.append("    J --> K[Current Privileges]")
        
        # Persistence
        persistence = self.data.get('persistence', {})
        if persistence.get('recent_tasks') or persistence.get('services'):
            mermaid.append("    K --> L[Persistence<br/>T1053, T1543, T1112]")
        else:
            mermaid.append("    K --> L[Persistence]")
        
        # Command & Control
        relay = self.data.get('relay_connectivity', {})
        if relay.get('relay_configured'):
            mermaid.append("    L --> M[C2 Channel<br/>Relay Service<br/>T1071, T1105]")
        else:
            mermaid.append("    L --> M[C2 Channel]")
        
        # Defense Evasion
        moonwalk = self.data.get('moonwalk', {})
        if moonwalk:
            mermaid.append("    M --> N[Defense Evasion<br/>Moonwalk<br/>T1070, T1562]")
        else:
            mermaid.append("    M --> N[Defense Evasion<br/>T1070, T1562]")
        
        # Collection & Exfiltration
        mermaid.append("    N --> O[Collection<br/>T1005, T1039]")
        mermaid.append("    O --> P[Exfiltration<br/>T1041, T1048]")
        
        # Styling
        mermaid.append("    style A fill:#ff6b6b")
        mermaid.append("    style C fill:#4ecdc4")
        mermaid.append("    style J fill:#ffe66d")
        mermaid.append("    style K fill:#95e1d3")
        mermaid.append("    style P fill:#f38181")
        
        return "\n".join(mermaid)
    
    def generate_network_diagram(self) -> str:
        """Generate network topology diagram"""
        mermaid = ["graph LR"]
        
        # Initial host
        initial_host = self.data.get('initial_host', 'Unknown')
        mermaid.append(f"    A[{initial_host}<br/>Initial Host]")
        
        # Network information
        network = self.data.get('network', {})
        local_ips = network.get('local_ips', [])
        arp_targets = network.get('arp_targets', [])
        
        # Domain controllers
        dc_info = network.get('domain_controllers', '')
        if dc_info:
            mermaid.append("    A --> B[Domain Controller<br/>T1018]")
            mermaid.append("    style B fill:#ff6b6b")
        
        # Lateral targets
        lateral_targets = self.data.get('lateral_targets', [])
        if isinstance(lateral_targets, list):
            for i, target_info in enumerate(lateral_targets[:10], 1):
                if isinstance(target_info, dict):
                    target = target_info.get('target', f'Target{i}')
                    smb = target_info.get('smb_accessible', False)
                    winrm = target_info.get('winrm_accessible', False)
                    
                    methods = []
                    if smb:
                        methods.append('SMB')
                    if winrm:
                        methods.append('WinRM')
                    
                    method_str = '/'.join(methods) if methods else 'Unknown'
                    mermaid.append(f"    A --> T{i}[{target}<br/>{method_str}]")
                    mermaid.append(f"    style T{i} fill:#4ecdc4")
        
        # ARP targets (if not already in lateral_targets)
        if arp_targets:
            for i, ip in enumerate(arp_targets[:5], 1):
                # Check if already added as lateral target
                already_added = False
                if isinstance(lateral_targets, list):
                    for target_info in lateral_targets:
                        if isinstance(target_info, dict) and target_info.get('target') == ip:
                            already_added = True
                            break
                
                if not already_added:
                    mermaid.append(f"    A -.-> N{i}[{ip}<br/>Discovered]")
                    mermaid.append(f"    style N{i} fill:#ffe66d")
        
        # Lateral movement paths
        lateral_paths = self.data.get('lateral_paths', [])
        if lateral_paths:
            for path_info in lateral_paths[:5]:
                path = path_info.get('path', [])
                if len(path) >= 2:
                    for j in range(len(path) - 1):
                        src = path[j].replace('-', '_').replace('.', '_')
                        dst = path[j + 1].replace('-', '_').replace('.', '_')
                        method = path_info.get('method', 'unknown')
                        mermaid.append(f"    {src} -->|{method}| {dst}")
        
        # Styling
        mermaid.append("    style A fill:#95e1d3")
        
        return "\n".join(mermaid)
    
    def generate_lateral_movement_diagram(self) -> str:
        """Generate lateral movement path diagram"""
        mermaid = ["graph TD"]
        
        lateral_paths = self.data.get('lateral_paths', [])
        if not lateral_paths:
            mermaid.append("    A[No Lateral Movement<br/>Performed]")
            mermaid.append("    style A fill:#ffe66d")
            return "\n".join(mermaid)
        
        # Create nodes for each unique host
        hosts = set()
        for path_info in lateral_paths:
            path = path_info.get('path', [])
            hosts.update(path)
        
        # Initial host
        initial_host = self.data.get('initial_host', 'Unknown')
        if initial_host in hosts:
            mermaid.append(f"    START[{initial_host}<br/>START]")
            mermaid.append("    style START fill:#95e1d3")
        
        # Create nodes for each host
        for host in hosts:
            if host != initial_host:
                node_id = host.replace('-', '_').replace('.', '_')
                mermaid.append(f"    {node_id}[{host}]")
        
        # Create edges for paths
        for path_info in lateral_paths:
            path = path_info.get('path', [])
            method = path_info.get('method', 'unknown')
            depth = path_info.get('depth', 0)
            
            if len(path) >= 2:
                for i in range(len(path) - 1):
                    src = path[i].replace('-', '_').replace('.', '_')
                    dst = path[i + 1].replace('-', '_').replace('.', '_')
                    
                    if i == 0 and path[i] == initial_host:
                        src = 'START'
                    
                    label = f"{method}<br/>Depth: {depth}" if i == 0 else method
                    mermaid.append(f"    {src} -->|{label}| {dst}")
        
        # Add depth information
        max_depth = max([p.get('depth', 0) for p in lateral_paths] + [0])
        mermaid.append(f"    DEPTH[Maximum Depth: {max_depth}]")
        mermaid.append("    style DEPTH fill:#ffe66d")
        
        return "\n".join(mermaid)
    
    def generate_privilege_escalation_diagram(self) -> str:
        """Generate privilege escalation flow diagram"""
        mermaid = ["graph TD"]
        
        pe = self.data.get('privilege_escalation', {})
        current_privs = pe.get('current_privileges', {})
        
        # Current state
        username = current_privs.get('UserName', 'Unknown')
        is_system = current_privs.get('IsSystem', False)
        is_admin = current_privs.get('IsAdmin', False)
        
        if is_system:
            mermaid.append("    A[Current: SYSTEM<br/>T1134.001]")
            mermaid.append("    style A fill:#95e1d3")
        elif is_admin:
            mermaid.append("    A[Current: Administrator<br/>Elevated]")
            mermaid.append("    style A fill:#4ecdc4")
        else:
            mermaid.append(f"    A[Current: {username}<br/>Standard User]")
            mermaid.append("    style A fill:#ffe66d")
        
        # PE5 availability
        if pe.get('pe5_available'):
            mermaid.append("    A --> B[PE5 Framework<br/>Available<br/>T1068, T1134]")
            
            if pe.get('windows_version', {}).get('pe5_compatible'):
                mermaid.append("    B --> C[Windows Compatible<br/>Token Offset Available]")
                mermaid.append("    C --> D[Kernel-Level<br/>Token Manipulation<br/>T1134.001]")
                mermaid.append("    D --> E[SYSTEM Privileges<br/>T1068]")
                mermaid.append("    style E fill:#95e1d3")
            else:
                mermaid.append("    B --> C[Windows Version<br/>Not Compatible]")
        else:
            mermaid.append("    A --> B[PE5 Framework<br/>Not Available]")
        
        # Other PE techniques
        pe_techniques = pe.get('pe_techniques', {})
        if pe_techniques:
            mermaid.append("    A --> F[Other PE Techniques]")
            
            if pe_techniques.get('print_spooler', {}).get('vulnerable'):
                mermaid.append("    F --> G[Print Spooler<br/>CVE-2020-1337<br/>T1068]")
            
            uac = pe_techniques.get('uac', {})
            if uac.get('enabled'):
                mermaid.append("    F --> H[UAC Bypass<br/>T1548]")
            else:
                mermaid.append("    F --> H[UAC Disabled<br/>Direct Elevation]")
            
            token_manip = pe_techniques.get('token_manipulation', {})
            if token_manip.get('CanAccessLSASS'):
                mermaid.append("    F --> I[Token Manipulation<br/>LSASS Access<br/>T1134]")
        
        # Escalation result
        if pe.get('escalation_successful'):
            mermaid.append("    E --> RESULT[Escalation Successful<br/>SYSTEM Access]")
            mermaid.append("    style RESULT fill:#95e1d3")
        elif pe.get('escalation_attempted'):
            mermaid.append("    E --> RESULT[Escalation Attempted]")
            mermaid.append("    style RESULT fill:#ffe66d")
        else:
            mermaid.append("    A --> RESULT[No Escalation<br/>Attempted]")
            mermaid.append("    style RESULT fill:#ffe66d")
        
        return "\n".join(mermaid)
    
    def generate_system_architecture_diagram(self) -> str:
        """Generate system architecture diagram"""
        mermaid = ["graph TB"]
        
        # Host information
        foothold = self.data.get('foothold', {})
        role = foothold.get('role', 'Unknown')
        identity = foothold.get('identity', 'Unknown')
        
        mermaid.append(f"    HOST[Host: {role}<br/>User: {identity}]")
        
        # Network interfaces
        network = self.data.get('network', {})
        local_ips = network.get('local_ips', [])
        if local_ips:
            ip_str = ', '.join(local_ips[:3])
            mermaid.append(f"    HOST --> NET[Network Interfaces<br/>{ip_str}]")
        
        # Services
        listening_ports = foothold.get('listening_ports', [])
        if listening_ports:
            ports_str = ', '.join(listening_ports[:10])
            mermaid.append(f"    HOST --> SVC[Services<br/>Ports: {ports_str}]")
        
        # Shares
        local_shares = network.get('local_shares', '')
        if local_shares:
            mermaid.append("    HOST --> SHARES[Network Shares<br/>T1135]")
        
        # Domain context
        orientation = self.data.get('orientation', {})
        domain_groups = orientation.get('domain_groups', [])
        if domain_groups:
            mermaid.append("    HOST --> DOMAIN[Domain Joined<br/>T1087.002]")
        
        # Credentials
        identity_data = self.data.get('identity', {})
        if identity_data.get('stored_credentials') or identity_data.get('vault_credentials'):
            mermaid.append("    HOST --> CREDS[Stored Credentials<br/>T1555, T1556]")
        
        # Persistence mechanisms
        persistence = self.data.get('persistence', {})
        if persistence.get('recent_tasks') or persistence.get('services'):
            mermaid.append("    HOST --> PERSIST[Persistence<br/>T1053, T1543]")
        
        # Tooling integration
        tooling = self.data.get('tooling_integration', {})
        if tooling.get('integration_summary', {}).get('pe5_ready'):
            mermaid.append("    HOST --> PE5[PE5 Framework<br/>Available]")
        
        if tooling.get('integration_summary', {}).get('relay_ready'):
            mermaid.append("    HOST --> RELAY[Relay Client<br/>Available]")
        
        # Styling
        mermaid.append("    style HOST fill:#95e1d3")
        mermaid.append("    style NET fill:#4ecdc4")
        mermaid.append("    style SVC fill:#ffe66d")
        
        return "\n".join(mermaid)
    
    def generate_attack_timeline(self) -> str:
        """Generate attack timeline diagram"""
        mermaid = ["gantt"]
        mermaid.append("    title Attack Timeline")
        mermaid.append("    dateFormat X")
        mermaid.append("    axisFormat %s")
        
        timestamp = self.data.get('timestamp', datetime.now().isoformat())
        
        # Phases
        mermaid.append("    section Initial Access")
        mermaid.append("    Foothold Establishment    :done, foothold, 0, 1")
        
        mermaid.append("    section Discovery")
        mermaid.append("    Local Orientation         :done, orient, 1, 2")
        mermaid.append("    Network Discovery         :done, network, 2, 3")
        
        mermaid.append("    section Credential Access")
        identity = self.data.get('identity', {})
        if identity.get('stored_credentials') or identity.get('vault_credentials'):
            mermaid.append("    Credential Harvesting    :done, creds, 3, 4")
        else:
            mermaid.append("    Credential Harvesting    :crit, creds, 3, 4")
        
        mermaid.append("    section Lateral Movement")
        lateral_paths = self.data.get('lateral_paths', [])
        if lateral_paths:
            mermaid.append("    Lateral Movement         :done, lateral, 4, 6")
        else:
            mermaid.append("    Lateral Movement         :active, lateral, 4, 5")
        
        mermaid.append("    section Privilege Escalation")
        pe = self.data.get('privilege_escalation', {})
        if pe.get('escalation_successful'):
            mermaid.append("    PE5 Escalation          :done, pe, 6, 7")
        elif pe.get('pe5_available'):
            mermaid.append("    PE5 Escalation          :active, pe, 6, 7")
        else:
            mermaid.append("    PE5 Escalation          :crit, pe, 6, 7")
        
        mermaid.append("    section Persistence")
        persistence = self.data.get('persistence', {})
        if persistence.get('recent_tasks') or persistence.get('services'):
            mermaid.append("    Persistence Setup        :done, persist, 7, 8")
        else:
            mermaid.append("    Persistence Setup        :active, persist, 7, 8")
        
        mermaid.append("    section Defense Evasion")
        moonwalk = self.data.get('moonwalk', {})
        if moonwalk:
            mermaid.append("    Log Clearing            :done, cleanup, 8, 9")
        else:
            mermaid.append("    Log Clearing            :active, cleanup, 8, 9")
        
        return "\n".join(mermaid)
    
    def save_diagrams(self, output_dir: Path) -> Dict[str, Path]:
        """Save all diagrams to files"""
        saved_files = {}
        
        for diagram_name, diagram_content in self.diagrams.items():
            filename = output_dir / f"{diagram_name}.mmd"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(diagram_content)
            saved_files[diagram_name] = filename
        
        return saved_files
