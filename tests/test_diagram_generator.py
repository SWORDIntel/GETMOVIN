"""Additional tests for diagram generator to improve coverage"""

import pytest
from datetime import datetime
from pathlib import Path
from modules.diagram_generator import DiagramGenerator


class TestDiagramGeneratorCoverage:
    """Additional tests for diagram generator coverage"""
    
    def test_generate_system_architecture_diagram(self):
        """Test system architecture diagram generation"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'foothold': {
                'role': 'Domain Controller',
                'identity': 'SYSTEM',
                'listening_ports': ['389', '88', '445']
            },
            'network': {
                'local_ips': ['192.168.1.1'],
                'local_shares': 'C$'
            },
            'orientation': {
                'domain_groups': ['Domain Admins', 'Domain Users']
            },
            'identity': {
                'stored_credentials': 'Found',
                'vault_credentials': 'Found'
            },
            'persistence': {
                'recent_tasks': 'Found',
                'services': 'Found'
            },
            'tooling_integration': {
                'integration_summary': {
                    'pe5_ready': True,
                    'relay_ready': True
                }
            }
        }
        generator = DiagramGenerator(data)
        diagram = generator.generate_system_architecture_diagram()
        assert isinstance(diagram, str)
        assert 'graph TB' in diagram
        assert 'Domain Controller' in diagram
    
    def test_generate_attack_timeline(self):
        """Test attack timeline generation"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'foothold': {'identity': 'test_user'},
            'network': {'local_ips': ['192.168.1.1']},
            'identity': {'stored_credentials': 'Found'},
            'lateral_paths': [{'path': ['host1', 'host2'], 'depth': 1}],
            'privilege_escalation': {
                'pe5_available': True,
                'escalation_successful': True
            },
            'persistence': {'recent_tasks': 'Found'},
            'moonwalk': {'event_logs': {'cleared': ['Security']}}
        }
        generator = DiagramGenerator(data)
        diagram = generator.generate_attack_timeline()
        assert isinstance(diagram, str)
        assert 'gantt' in diagram
        assert 'Attack Timeline' in diagram
    
    def test_save_diagrams_empty(self, tmp_path):
        """Test saving empty diagrams"""
        data = {'timestamp': datetime.now().isoformat()}
        generator = DiagramGenerator(data)
        # Don't generate diagrams first
        generator.diagrams = {}
        saved_files = generator.save_diagrams(tmp_path)
        assert isinstance(saved_files, dict)
        assert len(saved_files) == 0
    
    def test_network_diagram_with_domain_controllers(self):
        """Test network diagram with domain controllers"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'initial_host': 'workstation1',
            'network': {
                'domain_controllers': 'DC1.domain.local',
                'local_ips': ['192.168.1.10'],
                'arp_targets': ['192.168.1.100', '192.168.1.101']
            },
            'lateral_targets': [
                {'target': '192.168.1.100', 'smb_accessible': True, 'winrm_accessible': False}
            ]
        }
        generator = DiagramGenerator(data)
        diagram = generator.generate_network_diagram()
        assert isinstance(diagram, str)
        assert 'Domain Controller' in diagram
    
    def test_lateral_movement_diagram_no_paths(self):
        """Test lateral movement diagram with no paths"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'initial_host': 'host1',
            'lateral_paths': []
        }
        generator = DiagramGenerator(data)
        diagram = generator.generate_lateral_movement_diagram()
        assert isinstance(diagram, str)
        assert 'No Lateral Movement' in diagram
    
    def test_privilege_escalation_no_pe5(self):
        """Test privilege escalation diagram without PE5"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'privilege_escalation': {
                'current_privileges': {
                    'UserName': 'test_user',
                    'IsSystem': False,
                    'IsAdmin': False
                },
                'pe5_available': False,
                'pe_techniques': {
                    'uac': {'enabled': True}
                }
            }
        }
        generator = DiagramGenerator(data)
        diagram = generator.generate_privilege_escalation_diagram()
        assert isinstance(diagram, str)
        assert 'graph TD' in diagram
    
    def test_mitre_attack_flow_comprehensive(self):
        """Test MITRE attack flow with all features"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'foothold': {
                'has_system': True,
                'identity': 'SYSTEM'
            },
            'network': {
                'local_ips': ['192.168.1.1'],
                'arp_targets': ['192.168.1.100']
            },
            'identity': {
                'stored_credentials': 'Found',
                'vault_credentials': 'Found'
            },
            'lateral_paths': [
                {'path': ['host1', 'host2', 'host3'], 'method': 'wmic', 'depth': 2},
                {'path': ['host1', 'host4'], 'method': 'smb', 'depth': 1}
            ],
            'privilege_escalation': {
                'pe5_available': True,
                'windows_version': {'pe5_compatible': True},
                'escalation_successful': True,
                'pe_techniques': {
                    'print_spooler': {'vulnerable': True}
                }
            },
            'persistence': {
                'recent_tasks': 'Found',
                'services': 'Found'
            },
            'relay_connectivity': {
                'relay_configured': True
            },
            'moonwalk': {
                'event_logs': {'cleared': ['Security', 'System']}
            }
        }
        generator = DiagramGenerator(data)
        diagram = generator.generate_mitre_attack_flow()
        assert isinstance(diagram, str)
        assert 'graph TD' in diagram
        assert 'SYSTEM' in diagram
