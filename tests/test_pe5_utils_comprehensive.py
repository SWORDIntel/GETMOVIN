"""Comprehensive tests for PE5 Utils module"""

import unittest
from unittest.mock import Mock, patch, MagicMock

from modules.pe5_utils import PE5Utils


class TestPE5Utils(unittest.TestCase):
    """Test PE5Utils class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.utils = PE5Utils()
    
    def test_initialization(self):
        """Test PE5Utils initialization"""
        self.assertIsNotNone(self.utils)
    
    def test_xor_key_derivation(self):
        """Test XOR key derivation"""
        header_bytes = b'\x00' * 16
        header_bytes = bytearray(header_bytes)
        header_bytes[3] = 0xA4
        header_bytes[7] = 0x00
        key = PE5Utils.derive_xor_key(bytes(header_bytes))
        self.assertIsNotNone(key)
        self.assertIsInstance(key, int)
    
    def test_decrypt_payload(self):
        """Test payload decryption"""
        # Create test encrypted payload
        xor_key = 0xA4
        encrypted = b'test_data' * 4
        decrypted = PE5Utils.decrypt_payload(encrypted, xor_key)
        self.assertIsInstance(decrypted, bytes)
        self.assertEqual(len(decrypted), len(encrypted))
    
    def test_get_windows_version_offsets(self):
        """Test getting Windows version offsets"""
        offsets = PE5Utils.get_windows_version_offsets("Windows 10 1909")
        self.assertIsNotNone(offsets)
        self.assertIsInstance(offsets, dict)
        self.assertIn('token', offsets)
    
    def test_get_windows_version_offsets_invalid(self):
        """Test getting Windows version offsets for invalid version"""
        offsets = PE5Utils.get_windows_version_offsets("Invalid Version")
        self.assertIsNone(offsets)
    
    def test_generate_token_modify_shellcode(self):
        """Test generating token modify shellcode"""
        shellcode = PE5Utils.generate_token_modify_shellcode()
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 0)
    
    def test_generate_token_modify_shellcode_custom_offset(self):
        """Test generating token modify shellcode with custom offset"""
        shellcode = PE5Utils.generate_token_modify_shellcode(token_offset=0x360)
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 0)
    
    def test_generate_token_steal_shellcode(self):
        """Test generating token steal shellcode"""
        shellcode = PE5Utils.generate_token_steal_shellcode()
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 0)
    
    def test_verify_syscall_location(self):
        """Test verifying syscall location"""
        # Create test data with syscall at offset
        data = bytearray(b'\x00' * (PE5Utils.PE5_SYSCALL_OFFSET + 10))
        data[PE5Utils.PE5_SYSCALL_OFFSET] = 0x0F
        data[PE5Utils.PE5_SYSCALL_OFFSET + 1] = 0x05
        result = PE5Utils.verify_syscall_location(bytes(data))
        self.assertTrue(result)
    
    def test_verify_syscall_location_invalid(self):
        """Test verifying syscall location with invalid data"""
        data = b'\x00' * 100
        result = PE5Utils.verify_syscall_location(data)
        self.assertFalse(result)
    
    def test_get_technique_info(self):
        """Test getting technique information"""
        info = PE5Utils.get_technique_info()
        self.assertIsInstance(info, dict)
        self.assertGreater(len(info), 0)
        # Check first technique
        first_key = list(info.keys())[0]
        self.assertIn('description', info[first_key])
    
    def test_generate_build_commands(self):
        """Test generating build commands"""
        commands = PE5Utils.generate_build_commands()
        self.assertIsInstance(commands, list)
        self.assertGreater(len(commands), 0)
    
    def test_generate_exploit_verification_script(self):
        """Test generating exploit verification script"""
        script = PE5Utils.generate_exploit_verification_script()
        self.assertIsInstance(script, str)
        self.assertGreater(len(script), 0)
        self.assertIn("SYSTEM", script)


if __name__ == '__main__':
    unittest.main()
