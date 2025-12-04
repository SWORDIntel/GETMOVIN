#!/usr/bin/env python3
"""Test Credential Manager

Tests credential storage, persistence, and retrieval.
"""

import sys
import os
import json
import shutil
import unittest
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.credential_manager import (
    CredentialManager,
    Credential,
    CredentialType,
    CredentialSource,
    get_credential_manager,
    save_credential,
    get_credentials_for_target,
)


class TestCredentialManager(unittest.TestCase):
    """Test Credential Manager core functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = Path("test_loot")
        self.manager = CredentialManager(self.test_dir)
    
    def tearDown(self):
        """Clean up test directory"""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_directory_creation(self):
        """Test that loot directory structure is created"""
        self.assertTrue(self.test_dir.exists())
        self.assertTrue((self.test_dir / "credentials").exists())
        self.assertTrue((self.test_dir / "tokens").exists())
        self.assertTrue((self.test_dir / "hashes").exists())
        self.assertTrue((self.test_dir / "certificates").exists())
        self.assertTrue((self.test_dir / "sessions").exists())
    
    def test_add_password(self):
        """Test adding a password credential"""
        cred_id = self.manager.add_password(
            username="admin",
            password="password123",
            domain="CORP",
            target="10.10.10.10",
            protocol="smb",
            port=445
        )
        
        self.assertIsNotNone(cred_id)
        self.assertEqual(len(self.manager.credentials), 1)
        
        cred = self.manager.get_credential(cred_id)
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "password123")
        self.assertEqual(cred.domain, "CORP")
    
    def test_add_hash(self):
        """Test adding an NTLM hash"""
        cred_id = self.manager.add_hash(
            username="administrator",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            domain="CORP",
            target="DC01"
        )
        
        self.assertIsNotNone(cred_id)
        
        cred = self.manager.get_credential(cred_id)
        self.assertEqual(cred.cred_type, CredentialType.NTLM_HASH.value)
        self.assertIn("31d6cfe0d16ae931b73c59d7e0c089c0", cred.hash_value)
    
    def test_add_default_credential(self):
        """Test adding a default credential from scanning"""
        cred_id = self.manager.add_default_credential(
            username="test",
            password="test",
            vendor="Generic",
            target="10.10.10.10",
            protocol="ssh",
            port=22,
            success=True
        )
        
        self.assertIsNotNone(cred_id)
        
        cred = self.manager.get_credential(cred_id)
        self.assertEqual(cred.cred_type, CredentialType.DEFAULT_CRED.value)
        self.assertTrue(cred.valid)
        self.assertTrue(cred.tested)
    
    def test_add_snmp_community(self):
        """Test adding SNMP community string"""
        cred_id = self.manager.add_snmp_community(
            community="public",
            target="10.10.10.2",
            version="2c",
            access="read-only"
        )
        
        self.assertIsNotNone(cred_id)
        
        cred = self.manager.get_credential(cred_id)
        self.assertEqual(cred.cred_type, CredentialType.SNMP_COMMUNITY.value)
        self.assertEqual(cred.username, "public")
    
    def test_persistence(self):
        """Test that credentials persist to disk"""
        # Add credentials
        self.manager.add_password("user1", "pass1", target="server1")
        self.manager.add_password("user2", "pass2", target="server2")
        
        # Create new manager instance
        new_manager = CredentialManager(self.test_dir)
        
        # Verify credentials were loaded
        self.assertEqual(len(new_manager.credentials), 2)
    
    def test_get_credentials_by_type(self):
        """Test filtering credentials by type"""
        self.manager.add_password("user1", "pass1")
        self.manager.add_password("user2", "pass2")
        self.manager.add_hash("user3", "hash123")
        
        passwords = self.manager.get_credentials_by_type(CredentialType.PASSWORD)
        hashes = self.manager.get_credentials_by_type(CredentialType.NTLM_HASH)
        
        self.assertEqual(len(passwords), 2)
        self.assertEqual(len(hashes), 1)
    
    def test_get_credentials_by_target(self):
        """Test filtering credentials by target"""
        self.manager.add_password("user1", "pass1", target="10.10.10.10")
        self.manager.add_password("user2", "pass2", target="10.10.20.20")
        self.manager.add_password("user3", "pass3", target="10.10.10.15")
        
        target_creds = self.manager.get_credentials_by_target("10.10.10")
        
        self.assertEqual(len(target_creds), 2)
    
    def test_get_credentials_by_domain(self):
        """Test filtering credentials by domain"""
        self.manager.add_password("user1", "pass1", domain="CORP")
        self.manager.add_password("user2", "pass2", domain="CORP")
        self.manager.add_password("user3", "pass3", domain="DEV")
        
        corp_creds = self.manager.get_credentials_by_domain("CORP")
        
        self.assertEqual(len(corp_creds), 2)
    
    def test_duplicate_detection(self):
        """Test that duplicate credentials are updated, not added"""
        cred_id1 = self.manager.add_password("admin", "oldpass", domain="CORP", target="server1")
        cred_id2 = self.manager.add_password("admin", "newpass", domain="CORP", target="server1")
        
        # Should be the same credential (updated)
        self.assertEqual(cred_id1, cred_id2)
        self.assertEqual(len(self.manager.credentials), 1)
    
    def test_export_hashcat(self):
        """Test exporting hashes in hashcat format"""
        self.manager.add_hash("user1", "aad3b435b51404eeaad3b435b51404ee:hash1")
        self.manager.add_hash("user2", "aad3b435b51404eeaad3b435b51404ee:hash2")
        
        output_path = self.manager.export_hashcat()
        
        self.assertTrue(output_path.exists())
        with open(output_path) as f:
            content = f.read()
            self.assertIn("user1", content)
            self.assertIn("user2", content)
    
    def test_export_csv(self):
        """Test exporting credentials as CSV"""
        self.manager.add_password("user1", "pass1", domain="CORP")
        self.manager.add_hash("user2", "hash123", domain="CORP")
        
        output_path = self.manager.export_credentials_csv()
        
        self.assertTrue(output_path.exists())
        with open(output_path) as f:
            content = f.read()
            self.assertIn("user1", content)
            self.assertIn("user2", content)
            self.assertIn("CORP", content)
    
    def test_summary(self):
        """Test getting credential summary"""
        self.manager.add_password("user1", "pass1", domain="CORP")
        self.manager.add_password("user2", "pass2", domain="DEV")
        self.manager.add_hash("user3", "hash123", domain="CORP")
        
        summary = self.manager.get_summary()
        
        self.assertEqual(summary['total'], 3)
        self.assertIn(CredentialType.PASSWORD.value, summary['by_type'])
        self.assertIn(CredentialType.NTLM_HASH.value, summary['by_type'])
        self.assertIn("CORP", summary['domains'])
        self.assertIn("DEV", summary['domains'])
    
    def test_mark_as_valid(self):
        """Test marking credentials as tested/valid"""
        cred_id = self.manager.add_password("user1", "pass1")
        
        self.manager.mark_as_valid(cred_id, valid=True)
        
        cred = self.manager.get_credential(cred_id)
        self.assertTrue(cred.tested)
        self.assertTrue(cred.valid)
    
    def test_remove_credential(self):
        """Test removing a credential"""
        cred_id = self.manager.add_password("user1", "pass1")
        
        self.assertEqual(len(self.manager.credentials), 1)
        
        result = self.manager.remove_credential(cred_id)
        
        self.assertTrue(result)
        self.assertEqual(len(self.manager.credentials), 0)


class TestCredentialDataclass(unittest.TestCase):
    """Test Credential dataclass"""
    
    def test_credential_creation(self):
        """Test creating a credential"""
        cred = Credential(
            id="",
            cred_type=CredentialType.PASSWORD.value,
            source=CredentialSource.USER_INPUT.value,
            username="admin",
            password="password123",
            domain="CORP"
        )
        
        self.assertIsNotNone(cred.id)
        self.assertIsNotNone(cred.discovered_at)
        self.assertTrue(cred.valid)
    
    def test_to_dict(self):
        """Test converting credential to dictionary"""
        cred = Credential(
            id="test123",
            cred_type=CredentialType.PASSWORD.value,
            source=CredentialSource.USER_INPUT.value,
            username="admin",
            password="password123"
        )
        
        d = cred.to_dict()
        
        self.assertEqual(d['id'], "test123")
        self.assertEqual(d['username'], "admin")
        self.assertEqual(d['password'], "password123")
    
    def test_from_dict(self):
        """Test creating credential from dictionary"""
        data = {
            'id': 'test123',
            'cred_type': 'password',
            'source': 'user_input',
            'username': 'admin',
            'password': 'password123',
            'domain': 'CORP',
            'hash_value': '',
            'ticket_data': '',
            'target': '',
            'port': 0,
            'protocol': '',
            'notes': '',
            'discovered_at': '2024-01-01T00:00:00',
            'last_used': '',
            'valid': True,
            'tested': False,
            'metadata': {}
        }
        
        cred = Credential.from_dict(data)
        
        self.assertEqual(cred.id, "test123")
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.domain, "CORP")
    
    def test_get_auth_string(self):
        """Test getting authentication string"""
        cred = Credential(
            id="test",
            cred_type=CredentialType.PASSWORD.value,
            source=CredentialSource.USER_INPUT.value,
            username="admin",
            password="password123",
            domain="CORP"
        )
        
        auth_string = cred.get_auth_string()
        
        self.assertEqual(auth_string, "CORP\\admin:password123")


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Reset global manager
        import modules.credential_manager as cm
        cm._credential_manager = None
        
        self.test_dir = Path("test_loot_global")
        self.test_dir.mkdir(exist_ok=True)
    
    def tearDown(self):
        """Clean up test directory"""
        import modules.credential_manager as cm
        cm._credential_manager = None
        
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
        
        # Clean up default loot dir if created
        default_loot = Path("loot")
        if default_loot.exists():
            shutil.rmtree(default_loot)
    
    def test_get_credential_manager_singleton(self):
        """Test that get_credential_manager returns singleton"""
        manager1 = get_credential_manager()
        manager2 = get_credential_manager()
        
        self.assertIs(manager1, manager2)


def run_credential_manager_demo():
    """Run a demonstration of credential manager"""
    from rich.console import Console
    
    console = Console()
    test_dir = Path("demo_loot")
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  Credential Manager Demo[/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]\n")
    
    try:
        # Initialize manager
        manager = CredentialManager(test_dir)
        console.print(f"[green]✓ Initialized credential store at: {test_dir}[/green]\n")
        
        # Add various credentials
        console.print("[bold]Adding credentials...[/bold]")
        
        manager.add_password("admin", "P@ssw0rd123", domain="CORP", target="DC01", protocol="smb")
        console.print("  ✓ Added password: CORP\\admin")
        
        manager.add_hash("administrator", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", domain="CORP")
        console.print("  ✓ Added NTLM hash: CORP\\administrator")
        
        manager.add_default_credential("test", "test", "Generic", "10.10.10.10", success=True)
        console.print("  ✓ Added default cred: test:test")
        
        manager.add_default_credential("cisco", "cisco", "Cisco", "10.10.10.2", success=True)
        console.print("  ✓ Added default cred: cisco:cisco")
        
        manager.add_snmp_community("public", "10.10.10.2")
        console.print("  ✓ Added SNMP community: public")
        
        # Show summary
        console.print("\n[bold]Credential Summary:[/bold]")
        manager.print_summary()
        
        # Export
        console.print("\n[bold]Exporting credentials...[/bold]")
        csv_path = manager.export_credentials_csv()
        console.print(f"  ✓ CSV exported to: {csv_path}")
        
        hash_path = manager.export_hashcat()
        console.print(f"  ✓ Hashcat format exported to: {hash_path}")
        
        # Show files created
        console.print(f"\n[bold]Files in {test_dir}:[/bold]")
        for path in test_dir.rglob("*"):
            if path.is_file():
                console.print(f"  • {path.relative_to(test_dir)}")
        
        console.print("\n[bold green]✓ Demo complete![/bold green]\n")
        
    finally:
        # Cleanup
        if test_dir.exists():
            shutil.rmtree(test_dir)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        run_credential_manager_demo()
    else:
        # Run tests
        unittest.main(verbosity=2)
