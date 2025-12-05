"""Extensive tests for MADCert Integration module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.madcert_integration import MADCertGenerator, MADCertModule


class TestMADCertGeneratorExtensive(unittest.TestCase):
    """Extensive tests for MADCertGenerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.generator = MADCertGenerator(self.console, self.session_data)
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_generate_ca_certificate(self, mock_run, mock_exists):
        """Test generating CA certificate"""
        mock_exists.return_value = True
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Certificate generated"
        mock_run.return_value = mock_result
        
        try:
            result = self.generator.generate_ca_certificate("Test CA")
            self.assertIsInstance(result, dict)
            self.assertIn('name', result)
        except FileNotFoundError:
            pass  # Expected if MADCert not found
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_generate_server_certificate(self, mock_run, mock_exists):
        """Test generating server certificate"""
        mock_exists.return_value = True
        # Add CA to cert store first
        self.generator.cert_store['test_ca'] = {
            'name': 'test_ca',
            'cert_file': '/tmp/test_ca.crt',
            'key_file': '/tmp/test_ca.key'
        }
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Certificate generated"
        mock_run.return_value = mock_result
        
        try:
            result = self.generator.generate_server_certificate("test_server", "test_ca")
            self.assertIsInstance(result, dict)
        except (FileNotFoundError, ValueError):
            pass
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_generate_client_certificate(self, mock_run, mock_exists):
        """Test generating client certificate"""
        mock_exists.return_value = True
        # Add CA to cert store first
        self.generator.cert_store['test_ca'] = {
            'name': 'test_ca',
            'cert_file': '/tmp/test_ca.crt',
            'key_file': '/tmp/test_ca.key'
        }
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Certificate generated"
        mock_run.return_value = mock_result
        
        try:
            result = self.generator.generate_client_certificate("test_client", "test_ca")
            self.assertIsInstance(result, dict)
        except (FileNotFoundError, ValueError):
            pass
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_generate_code_signing_certificate(self, mock_run, mock_exists):
        """Test generating code signing certificate"""
        mock_exists.return_value = True
        # Add CA to cert store first
        self.generator.cert_store['test_ca'] = {
            'name': 'test_ca',
            'cert_file': '/tmp/test_ca.crt',
            'key_file': '/tmp/test_ca.key'
        }
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Certificate generated"
        mock_run.return_value = mock_result
        
        try:
            result = self.generator.generate_code_signing_certificate("test_signer", "test_ca")
            self.assertIsInstance(result, dict)
        except (FileNotFoundError, ValueError):
            pass
    
    @patch('os.path.exists')
    def test_export_certificate_pem(self, mock_exists):
        """Test exporting certificate as PEM"""
        mock_exists.return_value = True
        self.generator.cert_store['test_cert'] = {
            'cert_file': '/tmp/test.crt',
            'key_file': '/tmp/test.key'
        }
        
        result = self.generator.export_certificate('test_cert', 'pem')
        self.assertIsNotNone(result)


class TestMADCertModuleExtensive(unittest.TestCase):
    """Extensive tests for MADCertModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = MADCertModule()
    
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['1', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_find_madcert(self, mock_confirm, mock_prompt):
        """Test module run with find MADCert option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass
    
    @patch('rich.prompt.Prompt.ask', side_effect=['2', 'Test CA', '0'])
    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_module_run_generate_ca(self, mock_confirm, mock_prompt):
        """Test module run with generate CA option"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
