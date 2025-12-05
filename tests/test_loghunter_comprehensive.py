"""Comprehensive tests for LogHunter Integration module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.loghunter_integration import LogHunter, WindowsMoonwalk


class TestLogHunter(unittest.TestCase):
    """Test LogHunter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.loghunter = LogHunter(self.console, self.session_data)
    
    def test_initialization(self):
        """Test LogHunter initialization"""
        self.assertIsNotNone(self.loghunter)
    
    @patch('modules.loghunter_integration.subprocess.run')
    def test_hunt_credential_access(self, mock_run):
        """Test hunting credential access"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Event data"
        mock_run.return_value = mock_result
        result = self.loghunter.hunt_credential_access()
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
    
    @patch('modules.loghunter_integration.subprocess.run')
    def test_hunt_privilege_escalation(self, mock_run):
        """Test hunting privilege escalation"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Event data"
        mock_run.return_value = mock_result
        result = self.loghunter.hunt_privilege_escalation()
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
    
    @patch('modules.loghunter_integration.subprocess.run')
    def test_hunt_lateral_movement(self, mock_run):
        """Test hunting lateral movement"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Event data"
        mock_run.return_value = mock_result
        result = self.loghunter.hunt_lateral_movement()
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)


class TestWindowsMoonwalk(unittest.TestCase):
    """Test WindowsMoonwalk class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.moonwalk = WindowsMoonwalk(self.console, self.session_data)
    
    def test_initialization(self):
        """Test WindowsMoonwalk initialization"""
        self.assertIsNotNone(self.moonwalk)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_clear_event_logs(self, mock_ps):
        """Test clearing event logs"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.clear_event_logs(["Security", "System"])
        self.assertIsInstance(result, dict)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_powershell_history(self, mock_cmd):
        """Test clearing PowerShell history"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_powershell_history()
        self.assertIsInstance(result, bool)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_command_history(self, mock_cmd):
        """Test clearing command history"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_command_history()
        self.assertIsInstance(result, bool)


if __name__ == '__main__':
    unittest.main()
