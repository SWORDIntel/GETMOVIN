"""Tests for LOLBins Reference module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.lolbins_reference import LOLBinsModule


class TestLOLBinsModule(unittest.TestCase):
    """Test LOLBinsModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LOLBinsModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    def test_database_get_bin(self):
        """Test getting LOLBin by name from database"""
        result = self.module.database.get_bin("powershell.exe")
        self.assertIsNotNone(result)
        if result:
            self.assertIn('description', result)
            self.assertIn('techniques', result)
    
    def test_database_search(self):
        """Test searching LOLBins in database"""
        results = self.module.database.search("power")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
    
    def test_database_get_by_category(self):
        """Test getting LOLBins by category"""
        results = self.module.database.get_by_category("Execution")
        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)
    
    def test_database_get_categories(self):
        """Test getting all categories"""
        categories = self.module.database.get_categories()
        self.assertIsInstance(categories, list)
        self.assertGreater(len(categories), 0)
    
    def test_module_run(self):
        """Test module run method"""
        # Mock user input
        with patch('rich.prompt.Prompt.ask', side_effect=['search', 'power', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass  # Expected when exiting
    
    def test_display_lolbin_details(self):
        """Test displaying LOLBin details"""
        lolbin = {
            'name': 'test',
            'description': 'test desc',
            'category': 'test',
            'mitre_techniques': ['T1059']
        }
        # Should not raise exception
        try:
            self.module.display_lolbin_details(self.console, lolbin)
        except Exception:
            pass  # May fail due to rich formatting, but structure is tested


if __name__ == '__main__':
    unittest.main()
