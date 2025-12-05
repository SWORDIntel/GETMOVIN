"""Comprehensive tests for MADCert Integration module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.madcert_integration import MADCertModule


class TestMADCertModule(unittest.TestCase):
    """Test MADCertModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0, 'is_local_ip': lambda x: True}
        self.module = MADCertModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    def test_madcert_generator_find_madcert(self):
        """Test finding MADCert executable"""
        from modules.madcert_integration import MADCertGenerator
        generator = MADCertGenerator(self.console, self.session_data)
        result = generator.find_madcert()
        # May be None if not found, which is OK for testing
        self.assertIsInstance(result, (str, type(None)))
    
    @patch('os.path.exists', return_value=False)
    @patch('subprocess.run')
    def test_madcert_generator_list_certificates(self, mock_run, mock_exists):
        """Test listing certificates"""
        from modules.madcert_integration import MADCertGenerator
        generator = MADCertGenerator(self.console, self.session_data)
        result = generator.list_certificates()
        self.assertIsInstance(result, list)
    
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except SystemExit:
            pass  # Expected when exiting


if __name__ == '__main__':
    unittest.main()
