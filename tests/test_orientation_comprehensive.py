"""Comprehensive tests for Orientation module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.orientation import OrientationModule


class TestOrientationModule(unittest.TestCase):
    """Test OrientationModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0, 'is_local_ip': lambda x: True}
        self.module = OrientationModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    @patch('modules.orientation.execute_powershell')
    @patch('modules.orientation.execute_cmd')
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt, mock_cmd, mock_ps):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except SystemExit:
            pass  # Expected when exiting


if __name__ == '__main__':
    unittest.main()
