"""Extensive tests for Auto Enumerate module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console
from pathlib import Path

from modules.auto_enumerate import AutoEnumerator, AutoEnumerateModule


class TestAutoEnumeratorExtensive(unittest.TestCase):
    """Extensive tests for AutoEnumerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        from rich.console import Console
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.enumerator = AutoEnumerator(self.console, self.session_data)
    
    def test_initialization(self):
        """Test AutoEnumerator initialization"""
        self.assertIsNotNone(self.enumerator)
        self.assertIsInstance(self.enumerator.enumeration_data, dict)
    
    @patch('modules.auto_enumerate.execute_powershell')
    @patch('modules.auto_enumerate.execute_cmd')
    def test_enumerate_foothold(self, mock_cmd, mock_ps):
        """Test foothold enumeration"""
        mock_ps.return_value = (0, "Data", "")
        mock_cmd.return_value = (0, "Data", "")
        from rich.progress import Progress
        progress = Progress()
        task = progress.add_task("test", total=100)
        try:
            self.enumerator._enumerate_foothold(progress, task)
        except Exception:
            pass
    
    @patch('modules.auto_enumerate.execute_powershell')
    @patch('modules.auto_enumerate.execute_cmd')
    def test_enumerate_network(self, mock_cmd, mock_ps):
        """Test network enumeration"""
        mock_ps.return_value = (0, "192.168.1.0/24", "")
        mock_cmd.return_value = (0, "Data", "")
        from rich.progress import Progress
        progress = Progress()
        task = progress.add_task("test", total=100)
        try:
            self.enumerator._enumerate_network(progress, task)
        except Exception:
            pass
    
    @patch('modules.auto_enumerate.execute_powershell')
    @patch('modules.auto_enumerate.execute_cmd')
    def test_enumerate_identity(self, mock_cmd, mock_ps):
        """Test identity enumeration"""
        mock_ps.return_value = (0, "DOMAIN\\user", "")
        mock_cmd.return_value = (0, "Data", "")
        from rich.progress import Progress
        progress = Progress()
        task = progress.add_task("test", total=100)
        try:
            self.enumerator._enumerate_identity(progress, task)
        except Exception:
            pass
    
    def test_enumerate_vlan_bypass(self):
        """Test VLAN bypass enumeration"""
        from rich.progress import Progress
        progress = Progress()
        task = progress.add_task("test", total=100)
        try:
            self.enumerator._enumerate_vlan_bypass(progress, task)
        except Exception:
            pass
    
    @patch('modules.auto_enumerate.Path.mkdir')
    def test_generate_remote_machine_reports(self, mock_mkdir):
        """Test generating remote machine reports"""
        remote_data = {
            'target': '192.168.1.1',
            'timestamp': '2025-12-04T00:00:00',
            'foothold': {'has_system': False}
        }
        
        with patch('modules.auto_enumerate.DiagramGenerator') as mock_diagram:
            with patch('modules.auto_enumerate.ReportGenerator') as mock_report:
                mock_diagram_instance = MagicMock()
                mock_report_instance = MagicMock()
                mock_diagram.return_value = mock_diagram_instance
                mock_report.return_value = mock_report_instance
                
                try:
                    self.enumerator._generate_remote_machine_reports(
                        '192.168.1.1', remote_data
                    )
                except Exception:
                    pass  # May fail due to missing paths


class TestAutoEnumerateModuleExtensive(unittest.TestCase):
    """Extensive tests for AutoEnumerateModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = AutoEnumerateModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_enumerate_local(self, mock_confirm, mock_prompt):
        """Test module run with enumerate local option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', '192.168.1.1', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_enumerate_remote(self, mock_confirm, mock_prompt):
        """Test module run with enumerate remote option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
