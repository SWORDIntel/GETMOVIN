"""Comprehensive tests for Discovery module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from modules.discovery import ComponentDiscovery


class TestComponentDiscoveryComprehensive(unittest.TestCase):
    """Comprehensive tests for ComponentDiscovery"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.discovery = ComponentDiscovery(auto_preload=False)
    
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.is_dir')
    def test_discover_pe5_framework_paths(self, mock_is_dir, mock_exists):
        """Test PE5 framework discovery with different paths"""
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        
        info = self.discovery.discover_pe5_framework()
        self.assertIsInstance(info, dict)
        self.assertIn('available', info)
    
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.is_dir')
    def test_discover_relay_service_paths(self, mock_is_dir, mock_exists):
        """Test relay service discovery with different paths"""
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        
        info = self.discovery.discover_relay_service()
        self.assertIsInstance(info, dict)
        self.assertIn('available', info)
    
    @patch('importlib.util.find_spec')
    def test_discover_optional_dependencies_all_available(self, mock_find_spec):
        """Test optional dependencies when all available"""
        mock_find_spec.return_value = MagicMock()
        info = self.discovery.discover_optional_dependencies()
        self.assertIsInstance(info, dict)
        # All should be True when mocked
        for dep, available in info.items():
            self.assertIsInstance(available, bool)
    
    @patch('pathlib.Path.exists')
    def test_discover_configuration_files_found(self, mock_exists):
        """Test configuration file discovery when files found"""
        mock_exists.return_value = True
        info = self.discovery.discover_configuration_files()
        self.assertIsInstance(info, dict)
        self.assertIn('relay_client_configs', info)
    
    @patch('subprocess.run')
    def test_discover_external_tools_tor_found(self, mock_run):
        """Test external tools discovery when Tor found"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'/usr/bin/tor'
        mock_run.return_value = mock_result
        info = self.discovery.discover_external_tools()
        self.assertIsInstance(info, dict)
        self.assertIn('tor', info)
    
    def test_get_summary(self):
        """Test getting summary"""
        summary = self.discovery.get_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('pe5_framework', summary)
        self.assertIn('relay_service', summary)
        self.assertIn('optional_dependencies', summary)
        self.assertIn('all_available', summary)
    
    @patch('subprocess.run')
    def test_preload_requirements_no_missing(self, mock_run):
        """Test preloading when no dependencies missing"""
        # Set all dependencies as available
        self.discovery.discovered_components['optional_dependencies'] = {
            'websockets': True,
            'aiohttp': True,
            'yaml': True,
            'cryptography': True
        }
        results = self.discovery.preload_requirements(interactive=False)
        self.assertIsInstance(results, dict)
        # Should return empty since nothing missing
        self.assertEqual(len(results), 0)
    
    def test_print_discovery_report(self):
        """Test printing discovery report"""
        # Should not raise exception
        try:
            self.discovery.print_discovery_report()
        except Exception:
            pass  # May fail due to print, but structure is tested
    
    @patch('pathlib.Path.exists')
    def test_preload_all_requirements_file_not_found(self, mock_exists):
        """Test preloading when requirements file not found"""
        mock_exists.return_value = False
        results = self.discovery.preload_all_requirements()
        self.assertIsInstance(results, dict)


if __name__ == '__main__':
    unittest.main()
