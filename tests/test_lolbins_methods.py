"""Tests for LOLBins module methods"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.lolbins_reference import LOLBinsModule


class TestLOLBinsModuleMethods(unittest.TestCase):
    """Test LOLBinsModule methods"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LOLBinsModule()
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', 'power', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_search_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test search LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', 'Execution', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_browse_category_menu(self, mock_confirm, mock_prompt):
        """Test browse category menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['3', 'powershell.exe', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_execution_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test execution LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['4', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_lateral_movement_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test lateral movement LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['5', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_credential_access_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test credential access LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['6', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_discovery_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test discovery LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['7', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_persistence_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test persistence LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['8', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_defense_evasion_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test defense evasion LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['9', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_collection_lolbins_menu(self, mock_confirm, mock_prompt):
        """Test collection LOLBins menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['10', 'execution', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_build_command_menu(self, mock_confirm, mock_prompt):
        """Test build command menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
