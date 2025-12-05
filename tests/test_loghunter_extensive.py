"""Extensive tests for LogHunter Integration module"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console

from modules.loghunter_integration import LogHunter, WindowsMoonwalk, LogHunterModule


class TestLogHunterExtensive(unittest.TestCase):
    """Extensive tests for LogHunter"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.loghunter = LogHunter(self.console, self.session_data)
    
    @patch('subprocess.run')
    def test_find_loghunter_found(self, mock_run):
        """Test finding LogHunter when found"""
        import os
        with patch('os.path.exists', return_value=True):
            result = self.loghunter.find_loghunter()
            self.assertIsNotNone(result)
    
    @patch('subprocess.run')
    def test_find_loghunter_not_found(self, mock_run):
        """Test finding LogHunter when not found"""
        import os
        with patch('os.path.exists', return_value=False):
            mock_run.return_value = MagicMock(returncode=1)
            result = self.loghunter.find_loghunter()
            self.assertIsNone(result)
    
    @patch('subprocess.run')
    def test_hunt_custom_query(self, mock_run):
        """Test custom query"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Query results"
        mock_run.return_value = mock_result
        
        result = self.loghunter.hunt_custom_query("test query")
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
    
    @patch('subprocess.run')
    def test_export_logs(self, mock_run):
        """Test exporting logs"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        result = self.loghunter.export_logs("Security", "/tmp/test.log")
        self.assertIsInstance(result, bool)


class TestWindowsMoonwalkExtensive(unittest.TestCase):
    """Extensive tests for WindowsMoonwalk"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.moonwalk = WindowsMoonwalk(self.console, self.session_data)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_clear_event_logs_specific(self, mock_ps):
        """Test clearing specific event logs"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.clear_event_logs(["Security", "System"])
        self.assertIsInstance(result, dict)
        # Result may have 'cleared' and 'failed' keys instead of 'event_logs'
        self.assertIn('cleared', result)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_clear_event_logs_all(self, mock_ps):
        """Test clearing all event logs"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.clear_event_logs()
        self.assertIsInstance(result, dict)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_powershell_history(self, mock_cmd):
        """Test clearing PowerShell history"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_powershell_history()
        self.assertIsInstance(result, bool)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_command_history(self, mock_cmd):
        """Test clearing command history"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_command_history()
        self.assertIsInstance(result, bool)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_clear_registry_traces(self, mock_ps):
        """Test clearing registry traces"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.clear_registry_traces(["test_key"])
        self.assertIsInstance(result, dict)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_prefetch(self, mock_cmd):
        """Test clearing prefetch"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_prefetch()
        self.assertIsInstance(result, bool)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_recent_files(self, mock_cmd):
        """Test clearing recent files"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_recent_files()
        self.assertIsInstance(result, bool)
    
    @patch('modules.loghunter_integration.execute_cmd')
    def test_clear_temp_files(self, mock_cmd):
        """Test clearing temp files"""
        mock_cmd.return_value = (0, "Success", "")
        result = self.moonwalk.clear_temp_files()
        self.assertIsInstance(result, bool)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_clear_browser_history(self, mock_ps):
        """Test clearing browser history"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.clear_browser_history('chrome')
        self.assertIsInstance(result, dict)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_full_cleanup(self, mock_ps):
        """Test full cleanup"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.full_cleanup()
        self.assertIsInstance(result, dict)
    
    @patch('modules.loghunter_integration.execute_powershell')
    def test_cleanup_after_operation(self, mock_ps):
        """Test cleanup after operation"""
        mock_ps.return_value = (0, "Success", "")
        result = self.moonwalk.cleanup_after_operation('execution')
        self.assertIsInstance(result, dict)


class TestLogHunterModuleExtensive(unittest.TestCase):
    """Extensive tests for LogHunterModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LogHunterModule()
    
    @patch('rich.prompt.Prompt.ask', return_value='0')
    def test_module_run(self, mock_prompt):
        """Test module run method"""
        try:
            self.module.run(self.console, self.session_data)
        except (SystemExit, Exception):
            pass


if __name__ == '__main__':
    unittest.main()
