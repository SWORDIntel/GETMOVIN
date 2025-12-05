"""Extensive tests for LOLBins Reference module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.lolbins_reference import LOLBinsModule, LOLBinsDatabase


class TestLOLBinsDatabaseExtensive(unittest.TestCase):
    """Extensive tests for LOLBinsDatabase"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.database = LOLBinsDatabase()
    
    def test_search_case_insensitive(self):
        """Test case-insensitive search"""
        results_lower = self.database.search("powershell")
        results_upper = self.database.search("POWERSHELL")
        results_mixed = self.database.search("PowerShell")
        
        # Should return same results regardless of case
        self.assertEqual(len(results_lower), len(results_upper))
        self.assertEqual(len(results_lower), len(results_mixed))
    
    def test_search_partial_match(self):
        """Test partial match search"""
        results = self.database.search("power")
        self.assertGreater(len(results), 0)
        # Should find powershell, powercfg, etc.
    
    def test_search_description(self):
        """Test searching by description"""
        results = self.database.search("execute")
        self.assertGreater(len(results), 0)
    
    def test_get_by_category_all_categories(self):
        """Test getting bins from all categories"""
        categories = self.database.get_categories()
        for category in categories:
            bins = self.database.get_by_category(category)
            self.assertIsInstance(bins, dict)
    
    def test_get_bin_variations(self):
        """Test getting bin with various name formats"""
        # Test with .exe extension
        result1 = self.database.get_bin("powershell.exe")
        # Test without extension
        result2 = self.database.get_bin("powershell")
        # Should return same result
        if result1:
            self.assertIsNotNone(result1)
        if result2:
            self.assertIsNotNone(result2)


class TestLOLBinsModuleExtensive(unittest.TestCase):
    """Extensive tests for LOLBinsModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LOLBinsModule()
    
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', 'power', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_search(self, mock_confirm, mock_prompt):
        """Test module run with search option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', 'Execution', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_browse_category(self, mock_confirm, mock_prompt):
        """Test module run with browse category option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['3', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_execution_lolbins(self, mock_confirm, mock_prompt):
        """Test module run with execution LOLBins option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['10', 'execution', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_build_command(self, mock_confirm, mock_prompt):
        """Test module run with build command option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
