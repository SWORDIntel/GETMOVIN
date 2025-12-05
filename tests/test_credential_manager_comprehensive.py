"""Comprehensive tests for Credential Manager module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os

from modules.credential_manager import (
    CredentialManager, Credential, CredentialType, CredentialSource,
    get_credential_manager
)


class TestCredentialManagerComprehensive(unittest.TestCase):
    """Comprehensive tests for CredentialManager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = CredentialManager(loot_dir=Path(self.temp_dir))
    
    def tearDown(self):
        """Clean up"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_add_password(self):
        """Test adding password credential"""
        cred_id = self.manager.add_password(
            username="test_user",
            password="test_pass",
            domain="TESTDOMAIN",
            target="192.168.1.1"
        )
        self.assertIsNotNone(cred_id)
        self.assertIsInstance(cred_id, str)
    
    def test_add_hash(self):
        """Test adding hash credential"""
        cred_id = self.manager.add_hash(
            username="test_user",
            hash_value="aad3b435b51404eeaad3b435b51404ee",
            domain="TESTDOMAIN",
            target="192.168.1.1"
        )
        self.assertIsNotNone(cred_id)
        self.assertIsInstance(cred_id, str)
    
    def test_get_credentials_by_type(self):
        """Test getting credentials by type"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        creds = self.manager.get_credentials_by_type(CredentialType.PASSWORD.value)
        self.assertIsInstance(creds, list)
        self.assertGreater(len(creds), 0)
    
    def test_get_credentials_by_target(self):
        """Test getting credentials by target"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        creds = self.manager.get_credentials_by_target("192.168.1.1")
        self.assertIsInstance(creds, list)
        self.assertGreater(len(creds), 0)
    
    def test_export_hashcat(self):
        """Test exporting to hashcat format"""
        self.manager.add_hash("user1", "aad3b435b51404eeaad3b435b51404ee", target="192.168.1.1")
        output = self.manager.export_hashcat()
        self.assertIsInstance(output, str)
    
    def test_export_csv(self):
        """Test exporting to CSV format"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        output = self.manager.export_csv()
        self.assertIsInstance(output, str)
        self.assertIn("username", output.lower())
    
    def test_summary(self):
        """Test getting summary"""
        self.manager.add_password("user1", "pass1", target="192.168.1.1")
        summary = self.manager.summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('total', summary)
        self.assertIn('by_type', summary)
    
    def test_mark_as_valid(self):
        """Test marking credential as valid"""
        cred_id = self.manager.add_password("user1", "pass1", target="192.168.1.1")
        result = self.manager.mark_as_valid(cred_id)
        self.assertTrue(result)
    
    def test_remove_credential(self):
        """Test removing credential"""
        cred_id = self.manager.add_password("user1", "pass1", target="192.168.1.1")
        result = self.manager.remove_credential(cred_id)
        self.assertTrue(result)


class TestCredentialDataclassComprehensive(unittest.TestCase):
    """Comprehensive tests for Credential dataclass"""
    
    def test_credential_creation_all_fields(self):
        """Test creating credential with all fields"""
        cred = Credential(
            id="test_id",
            cred_type=CredentialType.PASSWORD.value,
            username="test_user",
            password="test_pass",
            target="192.168.1.1",
            domain="TESTDOMAIN",
            source=CredentialSource.USER_INPUT.value,
            notes="Test note"
        )
        self.assertEqual(cred.username, "test_user")
        self.assertEqual(cred.password, "test_pass")
    
    def test_credential_to_dict(self):
        """Test converting credential to dict"""
        cred = Credential(
            id="test_id",
            cred_type=CredentialType.PASSWORD.value,
            username="user",
            password="pass",
            target="192.168.1.1",
            source=CredentialSource.USER_INPUT.value
        )
        cred_dict = cred.to_dict()
        self.assertIsInstance(cred_dict, dict)
        self.assertEqual(cred_dict['username'], "user")
    
    def test_credential_from_dict(self):
        """Test creating credential from dict"""
        cred_dict = {
            'id': 'test_id',
            'cred_type': CredentialType.PASSWORD.value,
            'username': 'user',
            'password': 'pass',
            'target': '192.168.1.1',
            'source': CredentialSource.USER_INPUT.value
        }
        cred = Credential.from_dict(cred_dict)
        self.assertIsInstance(cred, Credential)
        self.assertEqual(cred.username, "user")
    
    def test_get_auth_string_password(self):
        """Test getting auth string for password"""
        cred = Credential(
            id="test_id",
            cred_type=CredentialType.PASSWORD.value,
            username="user",
            password="pass",
            target="192.168.1.1",
            source=CredentialSource.USER_INPUT.value
        )
        auth_str = cred.get_auth_string()
        self.assertIn("user", auth_str)
        self.assertIn("pass", auth_str)
    
    def test_get_auth_string_hash(self):
        """Test getting auth string for hash"""
        cred = Credential(
            id="test_id",
            cred_type=CredentialType.NTLM_HASH.value,
            username="user",
            hash_value="aad3b435b51404eeaad3b435b51404ee",
            target="192.168.1.1",
            source=CredentialSource.USER_INPUT.value
        )
        auth_str = cred.get_auth_string()
        self.assertIn("user", auth_str)
        self.assertIn("hash", auth_str.lower())


class TestGlobalFunctionsComprehensive(unittest.TestCase):
    """Comprehensive tests for global functions"""
    
    def test_get_credential_manager_singleton(self):
        """Test getting credential manager singleton"""
        manager1 = get_credential_manager()
        manager2 = get_credential_manager()
        # Should be same instance (singleton)
        self.assertIs(manager1, manager2)


if __name__ == '__main__':
    unittest.main()
