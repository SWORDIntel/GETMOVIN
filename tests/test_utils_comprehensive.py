"""Comprehensive tests for utils module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import ipaddress

from modules.utils import (
    is_local_ip, extract_ip_from_string, validate_target,
    execute_command, execute_powershell, execute_cmd, select_menu_option
)


class TestIsLocalIP(unittest.TestCase):
    """Test is_local_ip function"""
    
    def test_local_ip_10_range(self):
        """Test 10.x.x.x range"""
        self.assertTrue(is_local_ip("10.0.0.1"))
        self.assertTrue(is_local_ip("10.255.255.255"))
    
    def test_local_ip_172_range(self):
        """Test 172.16-31.x.x range"""
        self.assertTrue(is_local_ip("172.16.0.1"))
        self.assertTrue(is_local_ip("172.31.255.255"))
    
    def test_local_ip_192_range(self):
        """Test 192.168.x.x range"""
        self.assertTrue(is_local_ip("192.168.0.1"))
        self.assertTrue(is_local_ip("192.168.255.255"))
    
    def test_local_ip_127_range(self):
        """Test 127.x.x.x (loopback) range"""
        self.assertTrue(is_local_ip("127.0.0.1"))
        self.assertTrue(is_local_ip("127.255.255.255"))
    
    def test_public_ip(self):
        """Test public IP addresses"""
        self.assertFalse(is_local_ip("8.8.8.8"))
        self.assertFalse(is_local_ip("1.1.1.1"))
        self.assertFalse(is_local_ip("203.0.113.1"))
    
    def test_invalid_ip(self):
        """Test invalid IP addresses"""
        self.assertFalse(is_local_ip("invalid"))
        self.assertFalse(is_local_ip("999.999.999.999"))
        self.assertFalse(is_local_ip(""))


class TestExtractIPFromString(unittest.TestCase):
    """Test extract_ip_from_string function"""
    
    def test_extract_single_ip(self):
        """Test extracting single IP"""
        self.assertEqual(extract_ip_from_string("192.168.1.1"), "192.168.1.1")
        self.assertEqual(extract_ip_from_string("10.0.0.1"), "10.0.0.1")
    
    def test_extract_ip_from_text(self):
        """Test extracting IP from text"""
        self.assertEqual(extract_ip_from_string("Connect to 192.168.1.100"), "192.168.1.100")
        self.assertEqual(extract_ip_from_string("IP: 10.0.0.1 port 22"), "10.0.0.1")
    
    def test_extract_first_ip(self):
        """Test extracting first IP when multiple present"""
        result = extract_ip_from_string("192.168.1.1 and 10.0.0.1")
        self.assertEqual(result, "192.168.1.1")
    
    def test_no_ip_found(self):
        """Test when no IP found"""
        self.assertIsNone(extract_ip_from_string("no ip here"))
        self.assertIsNone(extract_ip_from_string(""))


class TestValidateTarget(unittest.TestCase):
    """Test validate_target function"""
    
    def test_validate_local_ip_lab_mode(self):
        """Test validation in lab mode with local IP"""
        valid, error = validate_target("192.168.1.1", lab_use=1)
        self.assertTrue(valid)
        self.assertIsNone(error)
    
    def test_validate_public_ip_lab_mode(self):
        """Test validation in lab mode with public IP"""
        valid, error = validate_target("8.8.8.8", lab_use=1)
        self.assertFalse(valid)
        self.assertIsNotNone(error)
    
    def test_validate_any_ip_no_lab_mode(self):
        """Test validation without lab mode"""
        valid, error = validate_target("8.8.8.8", lab_use=0)
        self.assertTrue(valid)
        self.assertIsNone(error)
    
    def test_validate_hostname_lab_mode(self):
        """Test validation with hostname in lab mode"""
        valid, error = validate_target("example.com", lab_use=1)
        self.assertTrue(valid)  # Hostnames allowed but warned


class TestExecuteCommand(unittest.TestCase):
    """Test execute_command function"""
    
    @patch('subprocess.run')
    def test_execute_command_success(self, mock_run):
        """Test successful command execution"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        code, stdout, stderr = execute_command("echo test", lab_use=0)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "success")
    
    @patch('subprocess.run')
    def test_execute_command_failure(self, mock_run):
        """Test failed command execution"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error"
        mock_run.return_value = mock_result
        
        code, stdout, stderr = execute_command("invalid_command", lab_use=0)
        self.assertEqual(code, 1)
        self.assertEqual(stderr, "error")
    
    def test_execute_command_lab_restriction(self):
        """Test command execution with lab restrictions"""
        code, stdout, stderr = execute_command("ping 8.8.8.8", lab_use=1)
        self.assertEqual(code, 1)
        self.assertIn("not in local range", stderr)
    
    @patch('subprocess.run')
    def test_execute_command_timeout(self, mock_run):
        """Test command timeout"""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 30)
        
        code, stdout, stderr = execute_command("sleep 100", lab_use=0)
        self.assertEqual(code, 1)
        self.assertIn("timed out", stderr)
    
    @patch('subprocess.run')
    def test_execute_command_exception(self, mock_run):
        """Test command execution exception"""
        mock_run.side_effect = Exception("Test error")
        
        code, stdout, stderr = execute_command("test", lab_use=0)
        self.assertEqual(code, 1)
        self.assertIn("ERROR", stderr)


class TestExecutePowershell(unittest.TestCase):
    """Test execute_powershell function"""
    
    @patch('modules.utils.execute_command')
    def test_execute_powershell(self, mock_exec):
        """Test PowerShell execution"""
        mock_exec.return_value = (0, "output", "")
        code, stdout, stderr = execute_powershell("Get-Process", lab_use=0)
        self.assertEqual(code, 0)
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0][0]
        self.assertIn("powershell.exe", call_args)


class TestExecuteCmd(unittest.TestCase):
    """Test execute_cmd function"""
    
    @patch('modules.utils.execute_command')
    def test_execute_cmd(self, mock_exec):
        """Test CMD execution"""
        mock_exec.return_value = (0, "output", "")
        code, stdout, stderr = execute_cmd("dir", lab_use=0)
        self.assertEqual(code, 0)
        mock_exec.assert_called_once()


class TestSelectMenuOption(unittest.TestCase):
    """Test select_menu_option function"""
    
    @patch('modules.utils.Prompt.ask')
    def test_select_menu_option(self, mock_prompt):
        """Test menu option selection"""
        mock_console = MagicMock()
        menu_options = [
            {'key': '1', 'label': 'Option 1'},
            {'key': '2', 'label': 'Option 2'},
            {'key': '0', 'label': 'Exit'}
        ]
        mock_prompt.return_value = '1'
        
        result = select_menu_option(mock_console, menu_options, "Select", default='0')
        self.assertEqual(result, '1')
        mock_console.print.assert_called()
        mock_prompt.assert_called_once()


if __name__ == '__main__':
    unittest.main()
