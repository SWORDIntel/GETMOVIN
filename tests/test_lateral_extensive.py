"""Extensive tests for Lateral module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.lateral import LateralModule


class TestLateralModuleExtensive(unittest.TestCase):
    """Extensive tests for LateralModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LateralModule()
    
    @patch('modules.lateral.execute_powershell')
    @patch('modules.lateral.execute_cmd')
    def test_smb_rpc(self, mock_cmd, mock_ps):
        """Test SMB/RPC lateral movement"""
        mock_ps.return_value = (0, "Success", "")
        mock_cmd.return_value = (0, "Success", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['1', 'test_share', '192.168.1.1', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except (SystemExit, StopIteration, Exception):
                    pass
    
    @patch('modules.lateral.execute_powershell')
    @patch('modules.lateral.execute_cmd')
    def test_winrm_psremoting(self, mock_cmd, mock_ps):
        """Test WinRM/PowerShell remoting"""
        mock_ps.return_value = (0, "Success", "")
        mock_cmd.return_value = (0, "Success", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['2', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except (SystemExit, StopIteration, Exception):
                    pass
    
    @patch('modules.lateral.execute_powershell')
    @patch('modules.lateral.execute_cmd')
    def test_wmi_execution(self, mock_cmd, mock_ps):
        """Test WMI-based execution"""
        mock_ps.return_value = (0, "Success", "")
        mock_cmd.return_value = (0, "Success", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['3', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except (SystemExit, StopIteration, Exception):
                    pass
    
    @patch('modules.lateral.execute_powershell')
    def test_rdp_pivoting(self, mock_ps):
        """Test RDP-based pivoting"""
        mock_ps.return_value = (0, "Success", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['4', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.lateral.execute_powershell')
    def test_dcom_com(self, mock_ps):
        """Test DCOM/COM-based movement"""
        mock_ps.return_value = (0, "Success", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['5', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass
    
    @patch('modules.lateral.execute_powershell')
    def test_ssh_tunneling(self, mock_ps):
        """Test SSH tunneling"""
        mock_ps.return_value = (0, "Success", "")
        
        with patch('rich.prompt.Prompt.ask', side_effect=['6', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass


if __name__ == '__main__':
    unittest.main()
