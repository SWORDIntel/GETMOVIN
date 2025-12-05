"""Extensive tests for Credential Manager module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
from pathlib import Path

from modules.credential_manager import (
    CredentialManager, Credential, CredentialType, CredentialSource,
    get_credential_manager
)


class TestCredentialManagerExtensive(unittest.TestCase):
    """Extensive tests for CredentialManager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = CredentialManager(loot_dir=Path(self.temp_dir))
    
    def tearDown(self):
        """Clean up"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_add_ticket(self):
        """Test adding Kerberos ticket"""
        ticket_data = b'fake_ticket_data'
        cred_id = self.manager.add_ticket("user1", ticket_data, "tgt", domain="TESTDOMAIN")
        self.assertIsNotNone(cred_id)
    
    def test_add_token(self):
        """Test adding access token"""
        cred_id = self.manager.add_token("user1", "token_data", "access")
        self.assertIsNotNone(cred_id)
    
    def test_add_default_credential(self):
        """Test adding default credential"""
        cred_id = self.manager.add_default_credential("admin", "password", "Cisco", target="192.168.1.1")
        self.assertIsNotNone(cred_id)
    
    def test_add_ssh_key(self):
        """Test adding SSH key"""
        key_data = "ssh-rsa AAAAB3NzaC1yc2E..."
        cred_id = self.manager.add_ssh_key("user1", key_data, "rsa", target="192.168.1.1")
        self.assertIsNotNone(cred_id)
    
    def test_add_certificate(self):
        """Test adding certificate"""
        cert_data = "-----BEGIN CERTIFICATE-----..."
        cred_id = self.manager.add_certificate("CN=test", cert_data, key_data="key_data")
        self.assertIsNotNone(cred_id)
    
    def test_add_snmp_community(self):
        """Test adding SNMP community"""
        cred_id = self.manager.add_snmp_community("public", "192.168.1.1", "2c")
        self.assertIsNotNone(cred_id)
    
    def test_get_credential(self):
        """Test getting credential by ID"""
        cred_id = self.manager.add_password("user1", "pass1", target="192.168.1.1")
        cred = self.manager.get_credential(cred_id)
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "user1")
    
    def test_get_credential_not_found(self):
        """Test getting non-existent credential"""
        cred = self.manager.get_credential("nonexistent_id")
        self.assertIsNone(cred)
    
    def test_get_all(self):
        """Test getting all credentials"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        self.manager.add_hash("user2", "hash_value", target="192.168.1.2")
        
        all_creds = self.manager.get_all()
        self.assertIsInstance(all_creds, list)
        self.assertGreaterEqual(len(all_creds), 2)
    
    def test_get_credentials_by_target(self):
        """Test getting credentials by target"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        self.manager.add_password("user1", "pass2", target="192.168.1.1")
        
        creds = self.manager.get_credentials_by_target("192.168.1.1")
        self.assertIsInstance(creds, list)
        self.assertGreaterEqual(len(creds), 2)
    
    def test_get_credentials_by_domain(self):
        """Test getting credentials by domain"""
        self.manager.add_password("user1", "pass1", domain="DOMAIN1", target="192.168.1.1")
        self.manager.add_password("user2", "pass2", domain="DOMAIN2", target="192.168.1.2")
        
        creds = self.manager.get_credentials_by_domain("DOMAIN1")
        self.assertIsInstance(creds, list)
        self.assertGreaterEqual(len(creds), 1)
    
    def test_mark_as_valid(self):
        """Test marking credential as valid"""
        cred_id = self.manager.add_password("user1", "pass1", target="192.168.1.1")
        self.manager.mark_as_valid(cred_id, True)
        
        cred = self.manager.get_credential(cred_id)
        self.assertTrue(cred.valid)
        self.assertTrue(cred.tested)
    
    def test_export_hashcat_with_hashes(self):
        """Test exporting to hashcat format with hashes"""
        self.manager.add_hash("user1", "aad3b435b51404eeaad3b435b51404ee", target="192.168.1.1")
        output_path = self.manager.export_hashcat()
        self.assertIsNotNone(output_path)
        # Should return Path object
        self.assertIsInstance(output_path, Path)
    
    def test_get_summary(self):
        """Test getting summary"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        self.manager.add_hash("user2", "hash_value", target="192.168.1.2")
        self.manager.add_password("user3", "pass3", domain="DOMAIN1", target="192.168.1.3")
        
        summary = self.manager.get_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('total', summary)
        self.assertIn('by_type', summary)
        self.assertIn('by_source', summary)
        self.assertGreater(summary['total'], 0)


if __name__ == '__main__':
    unittest.main()
