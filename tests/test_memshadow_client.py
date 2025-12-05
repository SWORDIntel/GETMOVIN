"""Tests for MEMSHADOW Client module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import socket
import uuid

from modules.memshadow_client import MRACClient


class TestMRACClient(unittest.TestCase):
    """Test MRACClient class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = MRACClient(host='localhost', port=8888)
    
    def test_initialization(self):
        """Test MRACClient initialization"""
        self.assertIsNotNone(self.client)
        self.assertEqual(self.client.host, 'localhost')
        self.assertEqual(self.client.port, 8888)
        self.assertIsNone(self.client.socket)
        self.assertIsNotNone(self.client.app_id)
        self.assertEqual(self.client.sequence_num, 0)
        self.assertFalse(self.client.registered)
    
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
    
    def test_next_sequence(self):
        """Test sequence number increment"""
        initial = self.client.sequence_num
        seq = self.client._next_sequence()
        self.assertEqual(seq, initial + 1)
        self.assertEqual(self.client.sequence_num, initial + 1)
    
    def test_register_no_socket(self):
        """Test registration without socket"""
        self.client.socket = None
        result = self.client.register("test_app", {})
        self.assertFalse(result)
    
    def test_send_command_no_socket(self):
        """Test send_command without socket"""
        self.client.socket = None
        result = self.client.send_command(1, {})
        self.assertIsNone(result)
    
    def test_receive_message_no_socket(self):
        """Test receive_message without socket"""
        self.client.socket = None
        result = self.client._receive_message()
        self.assertIsNone(result)
