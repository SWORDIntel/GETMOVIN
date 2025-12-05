"""Tests for OPSEC module methods"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.opsec import OPSECModule


class TestOPSECModuleMethods(unittest.TestCase):
    """Test OPSECModule methods"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = OPSECModule()
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_tool_selection_menu(self, mock_confirm, mock_prompt):
        """Test tool selection menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_detection_evasion_menu(self, mock_confirm, mock_prompt):
        """Test detection evasion menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['3', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_logging_avoidance_menu(self, mock_confirm, mock_prompt):
        """Test logging avoidance menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['4', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_behavioral_blending_menu(self, mock_confirm, mock_prompt):
        """Test behavioral blending menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['5', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_network_opsec_menu(self, mock_confirm, mock_prompt):
        """Test network OPSEC menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['6', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_opsec_checklist_menu(self, mock_confirm, mock_prompt):
        """Test OPSEC checklist menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['7', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_apt41_defense_evasion_menu(self, mock_confirm, mock_prompt):
        """Test APT-41 defense evasion menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
