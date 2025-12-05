"""Extensive tests for LLM Agent module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import socket
import struct
import json
import tempfile
from rich.console import Console

try:
    from modules.llm_agent import (
        NonceTracker, CodeGenerator, LLMAgentModule, BinaryProtocol
    )
    LLM_AGENT_AVAILABLE = True
except ImportError:
    LLM_AGENT_AVAILABLE = False


@unittest.skipIf(not LLM_AGENT_AVAILABLE, "LLM Agent not available")
class TestNonceTrackerExtensive(unittest.TestCase):
    """Extensive tests for NonceTracker"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.tracker = NonceTracker(window_size=100)
    
    def test_check_and_add_new_nonce(self):
        """Test checking and adding a new nonce"""
        app_id = b'\x00' * 16
        nonce = struct.pack('!Q', 12345)
        
        result = self.tracker.check_and_add(app_id, nonce)
        self.assertTrue(result)
        self.assertIn(12345, self.tracker.nonces[app_id])
    
    def test_check_and_add_replay_nonce(self):
        """Test detecting replay nonce"""
        app_id = b'\x00' * 16
        nonce = struct.pack('!Q', 12345)
        
        # Add first time
        self.tracker.check_and_add(app_id, nonce)
        
        # Try to add again (replay)
        result = self.tracker.check_and_add(app_id, nonce)
        self.assertFalse(result)
    
    def test_window_size_limit(self):
        """Test window size limit"""
        tracker = NonceTracker(window_size=5)
        app_id = b'\x00' * 16
        
        # Add 6 nonces
        for i in range(6):
            nonce = struct.pack('!Q', i)
            tracker.check_and_add(app_id, nonce)
        
        # Should only have 5 nonces
        self.assertLessEqual(len(tracker.nonces[app_id]), 5)


@unittest.skipIf(not LLM_AGENT_AVAILABLE, "LLM Agent not available")
class TestCodeGeneratorExtensive(unittest.TestCase):
    """Extensive tests for CodeGenerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.generator = CodeGenerator(self.console, self.session_data)
    
    def test_generate_code_python(self):
        """Test generating Python code"""
        spec = {
            'language': 'python',
            'description': 'Test script',
            'requirements': ['os', 'sys'],
            'imports': ['import os', 'import sys']
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
        self.assertIn('.ps1', file_path)
    
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
        self.assertIn('.bat', file_path)
    
    def test_execute_code_python(self):
        """Test executing Python code"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "output"
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            exit_code, stdout, stderr = self.generator.execute_code(
                '/tmp/test.py', 'python'
            )
            self.assertEqual(exit_code, 0)
    
    def test_execute_code_powershell(self):
        """Test executing PowerShell code"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "output"
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            exit_code, stdout, stderr = self.generator.execute_code(
                '/tmp/test.ps1', 'powershell'
            )
            self.assertEqual(exit_code, 0)
    
    def test_cleanup(self):
        """Test cleanup"""
        self.generator.cleanup()
        # Should not raise exception


@unittest.skipIf(not LLM_AGENT_AVAILABLE, "LLM Agent not available")
class TestLLMAgentModuleExtensive(unittest.TestCase):
    """Extensive tests for LLMAgentModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LLMAgentModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    def test_module_run(self):
        """Test module run method"""
        with patch('rich.prompt.Prompt.ask', side_effect=['0']):
            try:
                self.module.run(self.console, self.session_data)
            except (SystemExit, Exception):
                pass  # Expected to exit or raise


@unittest.skipIf(not LLM_AGENT_AVAILABLE, "LLM Agent not available")
class TestBinaryProtocolExtensive(unittest.TestCase):
    """Extensive tests for BinaryProtocol"""
    
    def test_pack_message(self):
        """Test packing a message"""
        payload = b"test payload"
        msg_type = BinaryProtocol.MSG_COMMAND
        packed = BinaryProtocol.pack_message(msg_type, payload)
        
        self.assertIsInstance(packed, bytes)
        self.assertGreater(len(packed), len(payload))
        self.assertEqual(packed[:4], BinaryProtocol.MAGIC)
    
    def test_unpack_message_valid(self):
        """Test unpacking a valid message"""
        payload = b"test payload"
        packed = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, payload)
        
        msg_type, unpacked_payload = BinaryProtocol.unpack_message(packed)
        self.assertEqual(msg_type, BinaryProtocol.MSG_COMMAND)
        self.assertEqual(unpacked_payload, payload)
    
    def test_encode_json(self):
        """Test encoding JSON data"""
        data = {"key": "value", "number": 123}
        encoded = BinaryProtocol.encode_json(data)
        
        self.assertIsInstance(encoded, bytes)
        decoded = json.loads(encoded.decode('utf-8'))
        self.assertEqual(decoded, data)
    
    def test_decode_json(self):
        """Test decoding JSON data"""
        data = {"key": "value", "number": 123}
        encoded = json.dumps(data).encode('utf-8')
        decoded = BinaryProtocol.decode_json(encoded)
        
        self.assertEqual(decoded, data)


if __name__ == '__main__':
    unittest.main()
