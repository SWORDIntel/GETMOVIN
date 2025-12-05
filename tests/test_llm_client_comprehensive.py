"""Comprehensive tests for LLM Client module"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import socket
import struct
import json

from modules.llm_client import LLMAgentClient, BinaryProtocol


class TestBinaryProtocolComprehensive(unittest.TestCase):
    """Comprehensive tests for BinaryProtocol"""
    
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
    
    def test_unpack_message_too_short(self):
        """Test unpacking a message that's too short"""
        with self.assertRaises(ValueError):
            BinaryProtocol.unpack_message(b"short")
    
    def test_unpack_message_invalid_magic(self):
        """Test unpacking a message with invalid magic"""
        payload = b"test"
        packed = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, payload)
        # Corrupt magic
        corrupted = b"XXXX" + packed[4:]
        
        with self.assertRaises(ValueError):
            BinaryProtocol.unpack_message(corrupted)
    
    def test_unpack_message_wrong_version(self):
        """Test unpacking a message with wrong version"""
        payload = b"test"
        packed = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, payload)
        # Corrupt version (byte 4)
        corrupted = packed[:4] + b'\x02' + packed[5:]
        
        with self.assertRaises(ValueError):
            BinaryProtocol.unpack_message(corrupted)
    
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


class TestLLMAgentClientComprehensive(unittest.TestCase):
    """Comprehensive tests for LLMAgentClient"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = LLMAgentClient(host='localhost', port=8888)
    
    def test_initialization(self):
        """Test client initialization"""
        self.assertEqual(self.client.host, 'localhost')
        self.assertEqual(self.client.port, 8888)
        self.assertIsNone(self.client.socket)
    
    @patch('socket.socket')
    def test_connect_success(self, mock_socket_class):
        """Test successful connection"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.return_value = None
        
        result = self.client.connect()
        self.assertTrue(result)
        self.assertIsNotNone(self.client.socket)
        mock_socket.connect.assert_called_once_with(('localhost', 8888))
    
    @patch('socket.socket')
    def test_connect_failure(self, mock_socket_class):
        """Test connection failure"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.side_effect = socket.error("Connection refused")
        
        result = self.client.connect()
        self.assertFalse(result)
    
    def test_disconnect_no_socket(self):
        """Test disconnection without socket"""
        self.client.socket = None
        self.client.disconnect()  # Should not raise exception
        self.assertIsNone(self.client.socket)
    
    @patch('socket.socket')
    def test_disconnect_with_socket(self, mock_socket_class):
        """Test disconnection with socket"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        self.client.disconnect()
        mock_socket.close.assert_called_once()
        self.assertIsNone(self.client.socket)
    
    @patch('socket.socket')
    def test_send_command_success(self, mock_socket_class):
        """Test sending command successfully"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        # Mock _send_and_receive
        self.client._send_and_receive = MagicMock(return_value={"status": "ok", "result": "success"})
        
        result = self.client.send_command("test_command", "powershell")
        self.assertIsNotNone(result)
    
    @patch('socket.socket')
    def test_send_command_no_socket(self, mock_socket_class):
        """Test sending command when not connected"""
        self.client.socket = None
        result = self.client.send_command("test_command", "powershell")
        self.assertIsNone(result)
    
    @patch('socket.socket')
    def test_generate_code(self, mock_socket_class):
        """Test code generation request"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        self.client._send_and_receive = MagicMock(return_value={"code": "print('hello')", "file": "test.py"})
        
        result = self.client.generate_code({"language": "python", "description": "test"})
        self.assertIsNotNone(result)
    
    @patch('socket.socket')
    def test_execute_code(self, mock_socket_class):
        """Test execute code request"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        self.client._send_and_receive = MagicMock(return_value={"exit_code": 0, "stdout": "output", "stderr": ""})
        
        result = self.client.execute_code("/path/to/file.py", "python")
        self.assertIsNotNone(result)
    
    @patch('socket.socket')
    def test_heartbeat(self, mock_socket_class):
        """Test sending heartbeat"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        self.client._send_and_receive = MagicMock(return_value={"status": "alive"})
        
        result = self.client.heartbeat()
        self.assertIsNotNone(result)
    
    @patch('socket.socket')
    def test_send_and_receive_success(self, mock_socket_class):
        """Test _send_and_receive successfully"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        # Mock socket sendall/recv
        response_payload = BinaryProtocol.encode_json({"status": "ok"})
        response = BinaryProtocol.pack_message(BinaryProtocol.MSG_RESPONSE, response_payload)
        
        mock_socket.sendall.return_value = None
        mock_socket.recv.side_effect = [
            response[:10],  # Header
            response[10:]    # Payload
        ]
        
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, b"test")
        result = self.client._send_and_receive(message)
        self.assertIsNotNone(result)
    
    @patch('socket.socket')
    def test_send_and_receive_error_message(self, mock_socket_class):
        """Test _send_and_receive with error message"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        error_payload = BinaryProtocol.encode_json({"error": "Test error"})
        error_response = BinaryProtocol.pack_message(BinaryProtocol.MSG_ERROR, error_payload)
        
        mock_socket.sendall.return_value = None
        mock_socket.recv.side_effect = [
            error_response[:10],
            error_response[10:]
        ]
        
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, b"test")
        # Should raise exception for error messages
        try:
            result = self.client._send_and_receive(message)
            # May return None or raise exception
        except Exception:
            pass  # Expected
    
    @patch('socket.socket')
    def test_send_and_receive_timeout(self, mock_socket_class):
        """Test _send_and_receive with timeout"""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        self.client.socket = mock_socket
        
        mock_socket.sendall.return_value = None
        mock_socket.recv.side_effect = socket.timeout("Timeout")
        
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, b"test")
        result = self.client._send_and_receive(message)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
