"""Tests for Relay Client module"""

import unittest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import asyncio

try:
    from modules.relay_client import RelayClient
    RELAY_CLIENT_AVAILABLE = True
except ImportError:
    RELAY_CLIENT_AVAILABLE = False


@unittest.skipIf(not RELAY_CLIENT_AVAILABLE, "Relay client not available")
class TestRelayClient(unittest.TestCase):
    """Test RelayClient class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = RelayClient(relay_host='localhost', relay_port=8889)
    
    def test_initialization(self):
        """Test RelayClient initialization"""
        self.assertIsNotNone(self.client)
        self.assertEqual(self.client.relay_host, 'localhost')
        self.assertEqual(self.client.relay_port, 8889)
        self.assertTrue(self.client.use_tls)
        self.assertFalse(self.client.connected)
    
    def test_build_ws_url_tls(self):
        """Test WebSocket URL building with TLS"""
        url = self.client._build_ws_url()
        self.assertEqual(url, "wss://localhost:8889")
    
    def test_build_ws_url_no_tls(self):
        """Test WebSocket URL building without TLS"""
        self.client.use_tls = False
        url = self.client._build_ws_url()
        self.assertEqual(url, "ws://localhost:8889")
    
    def test_build_ws_url_onion(self):
        """Test WebSocket URL building for .onion address"""
        self.client.relay_host = "test.onion"
        url = self.client._build_ws_url()
        self.assertEqual(url, "ws://test.onion:8889")
    
    def test_get_ssl_context_no_tls(self):
        """Test SSL context when TLS disabled"""
        self.client.use_tls = False
        context = self.client._get_ssl_context()
        self.assertIsNone(context)
    
    def test_get_ssl_context_onion(self):
        """Test SSL context for .onion address"""
        self.client.relay_host = "test.onion"
        context = self.client._get_ssl_context()
        self.assertIsNone(context)
    
    @patch('ssl.create_default_context')
    def test_get_ssl_context_tls(self, mock_ssl):
        """Test SSL context creation with TLS"""
        mock_context = MagicMock()
        mock_ssl.return_value = mock_context
        context = self.client._get_ssl_context()
        self.assertIsNotNone(context)
        mock_ssl.assert_called_once()
