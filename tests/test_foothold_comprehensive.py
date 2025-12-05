"""Comprehensive tests for Foothold module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.foothold import FootholdModule


class TestFootholdModule(unittest.TestCase):
    """Test FootholdModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0, 'is_local_ip': lambda x: True}
        self.module = FootholdModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    @patch('modules.foothold.execute_cmd')
    @patch('modules.foothold.execute_powershell')
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt, mock_ps, mock_cmd):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except SystemExit:
            pass  # Expected when exiting
    
    @patch('modules.foothold.execute_cmd')
    def test_assess_identity(self, mock_cmd):
        """Test identity assessment"""
        mock_cmd.return_value = (0, "DOMAIN\\user", "")
        # Test the private method via run
        with patch('rich.prompt.Prompt.ask', side_effect=['1', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except SystemExit:
                    pass


if __name__ == '__main__':
    unittest.main()
