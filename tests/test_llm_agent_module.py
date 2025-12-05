"""Comprehensive tests for LLM Agent Module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.llm_agent import LLMAgentModule, CodeGenerator, NonceTracker


class TestNonceTracker(unittest.TestCase):
    """Test NonceTracker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.tracker = NonceTracker()
    
    def test_initialization(self):
        """Test NonceTracker initialization"""
        self.assertIsNotNone(self.tracker)
        self.assertEqual(self.tracker.window_size, 1000)
    
    def test_check_and_add_valid_nonce(self):
        """Test checking and adding valid nonce"""
        import struct
        app_id = b'\x00' * 16
        nonce = struct.pack('!Q', 12345)
        result = self.tracker.check_and_add(app_id, nonce)
        self.assertTrue(result)
    
    def test_check_and_add_replay_nonce(self):
        """Test detecting replay nonce"""
        import struct
        app_id = b'\x00' * 16
        nonce = struct.pack('!Q', 12345)
        # Add first time
        self.tracker.check_and_add(app_id, nonce)
        # Try to add again (replay)
        result = self.tracker.check_and_add(app_id, nonce)
        self.assertFalse(result)


class TestCodeGeneratorComprehensive(unittest.TestCase):
    """Comprehensive tests for CodeGenerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.generator = CodeGenerator(self.console, self.session_data)
    
    def test_initialization(self):
        """Test CodeGenerator initialization"""
        self.assertIsNotNone(self.generator)
        self.assertIsNotNone(self.generator.temp_dir)
    
    def test_generate_code_python(self):
        """Test generating Python code"""
        spec = {
            'language': 'python',
            'description': 'Test script',
            'requirements': ['os'],
            'imports': ['import os']
        }
        code, file_path = self.generator.generate_code(spec)
        self.assertIsInstance(code, str)
        self.assertIn('.py', file_path)
        self.assertIn('Test script', code)
    
    def test_generate_code_powershell(self):
        """Test generating PowerShell code"""
        spec = {
            'language': 'powershell',
            'description': 'Test script',
            'requirements': [],
            'imports': []
        }
        code, file_path = self.generator.generate_code(spec)
        self.assertIsInstance(code, str)
        self.assertIn('ps1', file_path)
    
    def test_generate_code_batch(self):
        """Test generating batch code"""
        spec = {
            'language': 'batch',
            'description': 'Test script',
            'requirements': [],
            'imports': []
        }
        code, file_path = self.generator.generate_code(spec)
        self.assertIsInstance(code, str)
        self.assertIn('bat', file_path)
    
    @patch('subprocess.run')
    def test_execute_code_python(self, mock_run):
        """Test executing Python code"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        code, file_path = self.generator.generate_code({
            'language': 'python',
            'description': 'test'
        })
        exit_code, stdout, stderr = self.generator.execute_code(file_path, 'python')
        self.assertEqual(exit_code, 0)
    
    def test_cleanup(self):
        """Test cleanup"""
        self.generator.cleanup()
        # Should not raise exception


class TestLLMAgentModule(unittest.TestCase):
    """Test LLMAgentModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LLMAgentModule()
    
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
