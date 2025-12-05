"""Tests for LOLBins Database class"""

import unittest
from modules.lolbins_reference import LOLBinsDatabase


class TestLOLBinsDatabase(unittest.TestCase):
    """Test LOLBinsDatabase class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.database = LOLBinsDatabase()
    
    def test_initialization(self):
        """Test database initialization"""
        self.assertIsNotNone(self.database)
        self.assertIsInstance(self.database.lolbins, dict)
        self.assertGreater(len(self.database.lolbins), 0)
    
    def test_search_powershell(self):
        """Test searching for PowerShell"""
        results = self.database.search("powershell")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        # Check structure
        if results:
            self.assertIn('category', results[0])
            self.assertIn('name', results[0])
            self.assertIn('info', results[0])
    
    def test_search_wmic(self):
        """Test searching for wmic"""
        results = self.database.search("wmic")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
    
    def test_get_by_category_execution(self):
        """Test getting Execution category"""
        results = self.database.get_by_category("Execution")
        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)
    
    def test_get_by_category_invalid(self):
        """Test getting invalid category"""
        results = self.database.get_by_category("InvalidCategory")
        self.assertIsInstance(results, dict)
        self.assertEqual(len(results), 0)
    
    def test_get_bin_powershell(self):
        """Test getting PowerShell bin"""
        result = self.database.get_bin("powershell.exe")
        self.assertIsNotNone(result)
        self.assertIn('description', result)
        self.assertIn('techniques', result)
        self.assertIn('examples', result)
    
    def test_get_bin_invalid(self):
        """Test getting invalid bin"""
        result = self.database.get_bin("nonexistent.exe")
        self.assertIsNone(result)
    
    def test_get_categories(self):
        """Test getting all categories"""
        categories = self.database.get_categories()
        self.assertIsInstance(categories, list)
        self.assertGreater(len(categories), 0)
        self.assertIn("Execution", categories)


if __name__ == '__main__':
    unittest.main()
