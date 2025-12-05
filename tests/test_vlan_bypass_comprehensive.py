"""Comprehensive tests for VLAN Bypass module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.vlan_bypass import VLANBypassModule


class TestVLANBypassModule(unittest.TestCase):
    """Test VLANBypassModule class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = VLANBypassModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    def test_get_credentials_for_target(self):
        """Test getting credentials for target"""
        creds = self.module.get_credentials_for_target("192.168.1.1")
        self.assertIsInstance(creds, list)
    
    def test_get_cves_for_device(self):
        """Test getting CVEs for device"""
        cves = self.module.get_cves_for_device("Cisco", "Router")
        self.assertIsInstance(cves, list)
    
    def test_get_cves_for_device_no_product(self):
        """Test getting CVEs for device without product"""
        cves = self.module.get_cves_for_device("Cisco")
        self.assertIsInstance(cves, list)
    
    def test_auto_enumerate_vlans(self):
        """Test auto enumeration of VLANs"""
        result = self.module.auto_enumerate_vlans(self.session_data)
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('discovered_vlans', result)
        self.assertIn('network_devices', result)


if __name__ == '__main__':
    unittest.main()
