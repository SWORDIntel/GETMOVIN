"""Tests for MADCert Generator class"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.madcert_integration import MADCertGenerator


class TestMADCertGenerator(unittest.TestCase):
    """Test MADCertGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.generator = MADCertGenerator(self.console, self.session_data)
    
    def test_initialization(self):
        """Test generator initialization"""
        self.assertIsNotNone(self.generator)
        self.assertIsInstance(self.generator.cert_store, dict)
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_find_madcert_not_found(self, mock_run, mock_exists):
        """Test finding MADCert when not found"""
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=1)
        result = self.generator.find_madcert()
        self.assertIsNone(result)
    
    @patch('os.path.exists', return_value=True)
    def test_find_madcert_found(self, mock_exists):
        """Test finding MADCert when found"""
        result = self.generator.find_madcert()
        self.assertIsNotNone(result)
    
    def test_list_certificates_empty(self):
        """Test listing certificates when empty"""
        result = self.generator.list_certificates()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)
    
    def test_list_certificates_with_certs(self):
        """Test listing certificates with certs"""
        self.generator.cert_store['test_ca'] = {
            'name': 'test',
            'type': 'CA',
            'cert_file': '/tmp/test.crt'
        }
        result = self.generator.list_certificates()
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
    
    def test_get_certificate_info_not_found(self):
        """Test getting certificate info when not found"""
        result = self.generator.get_certificate_info("nonexistent")
        self.assertIsNone(result)
    
    def test_get_certificate_info_found(self):
        """Test getting certificate info when found"""
        self.generator.cert_store['test_ca'] = {
            'name': 'test',
            'type': 'CA',
            'cert_file': '/tmp/test.crt'
        }
        result = self.generator.get_certificate_info("test_ca")
        self.assertIsNotNone(result)
        self.assertEqual(result['name'], 'test')


if __name__ == '__main__':
    unittest.main()
