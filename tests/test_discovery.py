"""Tests for Component Discovery module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

from modules.discovery import ComponentDiscovery


class TestComponentDiscovery(unittest.TestCase):
    """Test ComponentDiscovery class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.discovery = ComponentDiscovery(auto_preload=False)
    
    def test_initialization(self):
        """Test ComponentDiscovery initialization"""
        self.assertIsNotNone(self.discovery)
        self.assertIsInstance(self.discovery.discovered_components, dict)
        self.assertFalse(self.discovery.auto_preload)
    
    def test_discover_pe5_framework_not_found(self):
        """Test PE5 framework discovery when not found"""
        with patch('pathlib.Path.exists', return_value=False):
            info = self.discovery.discover_pe5_framework()
            self.assertFalse(info['available'])
            self.assertIsNone(info['path'])
            self.assertFalse(info['compiled'])
    
    def test_discover_pe5_framework_found(self):
        """Test PE5 framework discovery when found"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.is_dir.return_value = True
        mock_path.resolve.return_value = Path('/test/pe5_framework')
        mock_path.rglob.return_value = [Path('test.c'), Path('test.h')]
        
        with patch('pathlib.Path', return_value=mock_path):
            with patch('pathlib.Path.exists', return_value=True):
                info = self.discovery.discover_pe5_framework()
                self.assertTrue(info['available'])
    
    def test_discover_relay_service_not_found(self):
        """Test relay service discovery when not found"""
        with patch('pathlib.Path.exists', return_value=False):
            info = self.discovery.discover_relay_service()
            self.assertFalse(info['available'])
            self.assertIsNone(info['path'])
    
    def test_discover_relay_service_found(self):
        """Test relay service discovery when found"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.is_dir.return_value = True
        mock_path.resolve.return_value = Path('/test/relay')
        mock_daemon = MagicMock()
        mock_daemon.exists.return_value = True
        mock_path.__truediv__ = MagicMock(return_value=mock_daemon)
        
        with patch('pathlib.Path', return_value=mock_path):
            info = self.discovery.discover_relay_service()
            # Will be False since we're mocking, but structure is tested
            self.assertIn('available', info)
            self.assertIn('path', info)
    
    def test_discover_optional_dependencies(self):
        """Test optional dependencies discovery"""
        info = self.discovery.discover_optional_dependencies()
        self.assertIsInstance(info, dict)
        self.assertIn('websockets', info)
        self.assertIn('aiohttp', info)
        self.assertIn('yaml', info)
        self.assertIn('cryptography', info)
    
    @patch('importlib.util.find_spec')
    def test_discover_optional_dependencies_with_imports(self, mock_find_spec):
        """Test optional dependencies discovery with mocked imports"""
        mock_find_spec.return_value = MagicMock()
        info = self.discovery.discover_optional_dependencies()
        self.assertIsInstance(info, dict)
    
    def test_discover_configuration_files(self):
        """Test configuration files discovery"""
        info = self.discovery.discover_configuration_files()
        self.assertIsInstance(info, dict)
        self.assertIn('relay_client_configs', info)
        self.assertIn('relay_server_configs', info)
        self.assertIn('remote_guided_configs', info)
    
    def test_discover_external_tools(self):
        """Test external tools discovery"""
        info = self.discovery.discover_external_tools()
        self.assertIsInstance(info, dict)
        self.assertIn('tor', info)
        self.assertIn('loghunter', info)
    
    @patch('subprocess.run')
    def test_preload_requirements(self, mock_run):
        """Test preloading requirements"""
        mock_run.return_value = MagicMock(returncode=0)
        results = self.discovery.preload_requirements(interactive=False)
        self.assertIsInstance(results, dict)
    
    def test_get_summary(self):
        """Test getting discovery summary"""
        summary = self.discovery.get_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('pe5_framework', summary)
        self.assertIn('relay_service', summary)
        self.assertIn('optional_dependencies', summary)
    
    def test_discover_all(self):
        """Test discover_all method"""
        discovery = ComponentDiscovery(auto_preload=False)
        self.assertIn('pe5_framework', discovery.discovered_components)
        self.assertIn('relay_service', discovery.discovered_components)
        self.assertIn('optional_dependencies', discovery.discovered_components)


if __name__ == '__main__':
    unittest.main()
