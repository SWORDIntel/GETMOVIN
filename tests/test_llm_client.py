"""Tests for LLM Client module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import socket
import struct

from modules.llm_client import LLMAgentClient, BinaryProtocol


class TestLLMAgentClient(unittest.TestCase):
    """Test LLMAgentClient class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = LLMAgentClient(host='localhost', port=8888)
    
    def test_initialization(self):
        """Test LLMAgentClient initialization"""
        self.assertIsNotNone(self.client)
        self.assertEqual(self.client.host, 'localhost')
        self.assertEqual(self.client.port, 8888)
        self.assertIsNone(self.client.socket)
    
    @patch('socket.socket')
    def test_connect_success(self, mock_socket):
        """Test successful connection"""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect.return_value = None
        
        result = self.client.connect()
        self.assertTrue(result)
        self.assertIsNotNone(self.client.socket)
    
    @patch('socket.socket')
    def test_connect_failure(self, mock_socket):
        """Test connection failure"""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect.side_effect = Exception("Connection refused")
        
        result = self.client.connect()
        self.assertFalse(result)
    
    def test_disconnect(self):
        """Test disconnection"""
        mock_socket = MagicMock()
        self.client.socket = mock_socket
        
        self.client.disconnect()
        mock_socket.close.assert_called_once()
        self.assertIsNone(self.client.socket)
    
    def test_disconnect_no_socket(self):
        """Test disconnection when no socket exists"""
        self.client.socket = None
        self.client.disconnect()  # Should not raise exception
        self.assertIsNone(self.client.socket)
    
    def test_send_command(self):
        """Test sending command"""
        mock_socket = MagicMock()
        self.client.socket = mock_socket
        
        # Mock _send_and_receive
        self.client._send_and_receive = MagicMock(return_value={"result": "ok"})
        
        result = self.client.send_command("test command", "powershell")
        self.assertIsNotNone(result)
    
    def test_heartbeat(self):
        """Test heartbeat"""
        mock_socket = MagicMock()
        self.client.socket = mock_socket
        
        # Mock _send_and_receive
        self.client._send_and_receive = MagicMock(return_value={"status": "ok"})
        
        result = self.client.heartbeat()
        self.assertIsNotNone(result)
    
    def test_send_and_receive_no_socket(self):
        """Test _send_and_receive with no socket"""
        self.client.socket = None
        result = self.client._send_and_receive(b'test')
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
