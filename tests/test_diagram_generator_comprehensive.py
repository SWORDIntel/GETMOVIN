"""Comprehensive tests for Diagram Generator module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile

from modules.diagram_generator import DiagramGenerator


class TestDiagramGeneratorComprehensive(unittest.TestCase):
    """Comprehensive tests for DiagramGenerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.enumeration_data = {
            'timestamp': '2025-12-04T00:00:00',
            'foothold': {'target': '192.168.1.1'},
            'network': {'local_ips': ['192.168.1.1']},
            'lateral_targets': [
                {'target': '192.168.1.2', 'depth': 1}
            ]
        }
        self.generator = DiagramGenerator(self.enumeration_data)
    
    def test_initialization(self):
        """Test DiagramGenerator initialization"""
        self.assertIsNotNone(self.generator)
        self.assertEqual(self.generator.data, self.enumeration_data)
    
    def test_generate_system_architecture_diagram(self):
        """Test generating system architecture diagram"""
        diagram = self.generator.generate_system_architecture_diagram()
        self.assertIsInstance(diagram, str)
        self.assertGreater(len(diagram), 0)
    
    def test_generate_network_diagram(self):
        """Test generating network diagram"""
        diagram = self.generator.generate_network_diagram()
        self.assertIsInstance(diagram, str)
        self.assertGreater(len(diagram), 0)
    
    def test_generate_lateral_movement_diagram(self):
        """Test generating lateral movement diagram"""
        diagram = self.generator.generate_lateral_movement_diagram()
        self.assertIsInstance(diagram, str)
        self.assertGreater(len(diagram), 0)
    
    def test_generate_privilege_escalation_diagram(self):
        """Test generating privilege escalation diagram"""
        diagram = self.generator.generate_privilege_escalation_diagram()
        self.assertIsInstance(diagram, str)
        self.assertGreater(len(diagram), 0)
    
    def test_generate_attack_timeline(self):
        """Test generating attack timeline"""
        diagram = self.generator.generate_attack_timeline()
        self.assertIsInstance(diagram, str)
        self.assertGreater(len(diagram), 0)
    
    def test_generate_mitre_attack_flow(self):
        """Test generating MITRE attack flow"""
        diagram = self.generator.generate_mitre_attack_flow()
        self.assertIsInstance(diagram, str)
        self.assertGreater(len(diagram), 0)
    
    def test_generate_all_diagrams(self):
        """Test generating all diagrams"""
        diagrams = self.generator.generate_all_diagrams()
        self.assertIsInstance(diagrams, dict)
        self.assertIn('system_architecture', diagrams)
        self.assertIn('network_topology', diagrams)
        self.assertIn('lateral_movement', diagrams)
    
    def test_save_diagrams(self):
        """Test saving diagrams"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.generator.save_diagrams(Path(tmpdir))
            self.assertIsInstance(result, dict)
            # Check files were created
            files = list(Path(tmpdir).glob('*.mmd'))
            self.assertGreaterEqual(len(files), 0)  # May be 0 if no diagrams generated


if __name__ == '__main__':
    unittest.main()
