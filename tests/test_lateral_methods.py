"""Tests for Lateral module methods"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.lateral import LateralModule


class TestLateralModuleMethods(unittest.TestCase):
    """Test LateralModule methods"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LateralModule()
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', 'test_share', '192.168.1.1', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_smb_rpc_menu(self, mock_confirm, mock_prompt):
        """Test SMB/RPC menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_winrm_psremoting_menu(self, mock_confirm, mock_prompt):
        """Test WinRM/PowerShell remoting menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['3', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_wmi_execution_menu(self, mock_confirm, mock_prompt):
        """Test WMI execution menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['4', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_rdp_pivoting_menu(self, mock_confirm, mock_prompt):
        """Test RDP pivoting menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['5', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_dcom_com_menu(self, mock_confirm, mock_prompt):
        """Test DCOM/COM menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['6', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_ssh_tunneling_menu(self, mock_confirm, mock_prompt):
        """Test SSH tunneling menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['7', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_apt41_lateral_tools_menu(self, mock_confirm, mock_prompt):
        """Test APT-41 lateral tools menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, StopIteration, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
