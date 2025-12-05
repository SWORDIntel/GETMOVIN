"""Comprehensive tests for Consolidation module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.consolidation import ConsolidationModule


class TestConsolidationModule(unittest.TestCase):
    """Test ConsolidationModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0, 'is_local_ip': lambda x: True}
        self.module = ConsolidationModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except SystemExit:
            pass  # Expected when exiting


if __name__ == '__main__':
    unittest.main()
