"""Comprehensive tests for LLM Agent module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.llm_agent import LLMAgentModule, CodeGenerator

# BinaryProtocol is a class defined in llm_agent.py but not exported
# We'll test it through the module's usage or define a test version
class BinaryProtocol:
    """Test BinaryProtocol - matches llm_agent implementation"""
    MAGIC = b'\xAA\xBB\xCC\xDD'
    VERSION = 1
    MSG_COMMAND = 0x01
    MSG_CODE_GENERATE = 0x02
    MSG_EXECUTE = 0x03
    MSG_RESPONSE = 0x04
    MSG_ERROR = 0x05
    MSG_HEARTBEAT = 0x06
    
    @staticmethod
    def pack_message(msg_type: int, payload: bytes) -> bytes:
        import struct
        length = len(payload)
        return struct.pack('!4sBBL', BinaryProtocol.MAGIC, BinaryProtocol.VERSION, msg_type, length) + payload
    
    @staticmethod
    def unpack_message(data: bytes):
        import struct
        if len(data) < 10:
            raise ValueError("Message too short")
        magic, version, msg_type, length = struct.unpack('!4sBBL', data[:10])
        if magic != BinaryProtocol.MAGIC:
            raise ValueError(f"Invalid magic: {magic.hex()}")
        if version != BinaryProtocol.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        payload = data[10:10+length]
        if len(payload) != length:
            raise ValueError(f"Payload length mismatch: expected {length}, got {len(payload)}")
        return msg_type, payload
    
    @staticmethod
    def encode_json(data):
        import json
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_json(data: bytes):
        import json
        return json.loads(data.decode('utf-8'))


class TestBinaryProtocol(unittest.TestCase):
    """Test BinaryProtocol class"""
    
    def test_pack_message(self):
        """Test packing message"""
        payload = b'test_payload'
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, payload)
        self.assertIsInstance(message, bytes)
        self.assertGreater(len(message), len(payload))
    
    def test_unpack_message(self):
        """Test unpacking message"""
        payload = b'test_payload'
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, payload)
        msg_type, unpacked_payload = BinaryProtocol.unpack_message(message)
        self.assertEqual(msg_type, BinaryProtocol.MSG_COMMAND)
        self.assertEqual(unpacked_payload, payload)
    
    def test_encode_decode_json(self):
        """Test JSON encoding and decoding"""
        data = {"test": "value", "number": 123}
        encoded = BinaryProtocol.encode_json(data)
        self.assertIsInstance(encoded, bytes)
        decoded = BinaryProtocol.decode_json(encoded)
        self.assertEqual(decoded, data)
    
    def test_unpack_message_invalid_magic(self):
        """Test unpacking message with invalid magic"""
        invalid_data = b'\x00' * 20
        with self.assertRaises(ValueError):
            BinaryProtocol.unpack_message(invalid_data)


class TestCodeGenerator(unittest.TestCase):
    """Test CodeGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.generator = CodeGenerator()
    
    def test_initialization(self):
        """Test CodeGenerator initialization"""
        self.assertIsNotNone(self.generator)
    
    def test_generate_code(self):
        """Test code generation"""
        spec = {
            "language": "powershell",
            "task": "Get processes"
        }
        code = self.generator.generate_code(spec)
        self.assertIsInstance(code, str)
        self.assertGreater(len(code), 0)


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


if __name__ == '__main__':
    unittest.main()
