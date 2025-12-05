"""Extensive tests for Orientation module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.orientation import OrientationModule


class TestOrientationModuleExtensive(unittest.TestCase):
    """Extensive tests for OrientationModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = OrientationModule()
    
    @patch('modules.orientation.execute_powershell')
    def test_identity_mapping(self, mock_ps):
        """Test identity mapping"""
        mock_ps.return_value = (0, "User data", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['1', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.orientation.execute_cmd')
    def test_host_classification(self, mock_cmd):
        """Test host classification"""
        mock_cmd.return_value = (0, "Server data", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['2', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.orientation.execute_powershell')
    def test_network_visibility(self, mock_ps):
        """Test network visibility assessment"""
        mock_ps.return_value = (0, "Network data", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['3', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.orientation.execute_powershell')
    def test_service_accounts(self, mock_ps):
        """Test service account discovery"""
        mock_ps.return_value = (0, "Service data", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['4', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.orientation.execute_powershell')
    def test_scheduled_tasks(self, mock_ps):
        """Test scheduled task analysis"""
        mock_ps.return_value = (0, "Task data", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['5', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.orientation.execute_powershell')
    def test_security_software_discovery(self, mock_ps):
        """Test security software discovery"""
        mock_ps.return_value = (0, "Security data", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['6', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass


if __name__ == '__main__':
    unittest.main()
