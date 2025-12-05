"""Comprehensive tests for Lateral module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.lateral import LateralModule


class TestLateralModule(unittest.TestCase):
    """Test LateralModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0, 'is_local_ip': lambda x: True}
        self.module = LateralModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    @patch('modules.lateral.execute_powershell')
    @patch('modules.lateral.execute_cmd')
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt, mock_cmd, mock_ps):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except SystemExit:
            pass  # Expected when exiting


if __name__ == '__main__':
    unittest.main()
