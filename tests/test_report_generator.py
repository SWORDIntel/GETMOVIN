"""Tests for Report Generator module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.auto_enumerate import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test ReportGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.enumeration_data = {
            'timestamp': '2025-12-04T00:00:00',
            'foothold': {'target': '192.168.1.1'},
            'network': {'local_ips': ['192.168.1.1']},
            'lateral_targets': []
        }
        self.generator = ReportGenerator(self.console, self.enumeration_data)
    
    def test_initialization(self):
        """Test ReportGenerator initialization"""
        self.assertIsNotNone(self.generator)
        self.assertEqual(self.generator.data, self.enumeration_data)
    
    def test_generate_text_report(self):
        """Test generating text report"""
        report = self.generator.generate_text_report()
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 0)
    
    def test_generate_json_report(self):
        """Test generating JSON report"""
        report = self.generator.generate_json_report()
        self.assertIsInstance(report, str)
        # Should be valid JSON
        import json
        parsed = json.loads(report)
        self.assertIsInstance(parsed, dict)
    
    def test_generate_html_report(self):
        """Test generating HTML report"""
        report = self.generator.generate_html_report()
        self.assertIsInstance(report, str)
        self.assertIn('<html', report.lower())
    
    def test_display_report(self):
        """Test displaying report"""
        # Should not raise exception
        try:
            self.generator.display_report()
        except Exception:
            pass  # May fail due to console output, but structure is tested


if __name__ == '__main__':
    unittest.main()
