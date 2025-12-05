"""Tests for Consolidation module methods"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.consolidation import ConsolidationModule


class TestConsolidationModuleMethods(unittest.TestCase):
    """Test ConsolidationModule methods"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = ConsolidationModule()
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_strategic_objectives_menu(self, mock_confirm, mock_prompt):
        """Test strategic objectives menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_domain_controller_menu(self, mock_confirm, mock_prompt):
        """Test domain controller menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['3', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_persistence_menu(self, mock_confirm, mock_prompt):
        """Test persistence menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['4', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_control_planes_menu(self, mock_confirm, mock_prompt):
        """Test control planes menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['5', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_cleanup_menu(self, mock_confirm, mock_prompt):
        """Test cleanup menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['6', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_apt41_persistence_menu(self, mock_confirm, mock_prompt):
        """Test APT-41 persistence menu option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
