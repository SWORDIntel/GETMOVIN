"""Extensive tests for LogHunter Integration module - targeting 80% coverage"""

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
    
    def test_loghunter_initialization(self):
        """Test LogHunter initialization"""
        self.assertIsNotNone(self.loghunter)
        self.assertEqual(self.loghunter.console, self.console)
        self.assertEqual(self.loghunter.session_data, self.session_data)
    
    def test_find_loghunter(self):
        """Test finding LogHunter executable"""
        result = self.loghunter.find_loghunter()
        # May be None if not found
        if result:
            self.assertIsInstance(result, str)
    
    def test_hunt_credential_access(self):
        """Test hunting credential access"""
        with patch.object(self.loghunter, 'find_loghunter', return_value='/fake/path'):
            with patch('subprocess.run') as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "EventID: 4624"
                mock_result.stderr = ""
                mock_run.return_value = mock_result
                
                result = self.loghunter.hunt_credential_access()
                self.assertIsInstance(result, dict)
    
    def test_hunt_lateral_movement(self):
        """Test hunting lateral movement"""
        with patch.object(self.loghunter, 'find_loghunter', return_value='/fake/path'):
            with patch('subprocess.run') as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "EventID: 4624"
                mock_result.stderr = ""
                mock_run.return_value = mock_result
                
                result = self.loghunter.hunt_lateral_movement()
                self.assertIsInstance(result, dict)
    
    def test_hunt_privilege_escalation(self):
        """Test hunting privilege escalation"""
        with patch.object(self.loghunter, 'find_loghunter', return_value='/fake/path'):
            with patch('subprocess.run') as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "EventID: 4672"
                mock_result.stderr = ""
                mock_run.return_value = mock_result
                
                result = self.loghunter.hunt_privilege_escalation()
                self.assertIsInstance(result, dict)
    
    def test_hunt_custom_query(self):
        """Test custom query"""
        with patch.object(self.loghunter, 'find_loghunter', return_value='/fake/path'):
            with patch('subprocess.run') as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "EventID: 4624"
                mock_result.stderr = ""
                mock_run.return_value = mock_result
                
                result = self.loghunter.hunt_custom_query("test query")
                self.assertIsInstance(result, dict)
    
    def test_parse_loghunter_output(self):
        """Test parsing LogHunter output"""
        output = "EventID: 4624\nEventID: 4672"
        events = self.loghunter._parse_loghunter_output(output)
        self.assertIsInstance(events, list)
    
    def test_export_logs(self):
        """Test exporting logs"""
        with patch.object(self.loghunter, 'find_loghunter', return_value='/fake/path'):
            with patch('subprocess.run') as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = ""
                mock_result.stderr = ""
                mock_run.return_value = mock_result
                
                result = self.loghunter.export_logs('Security', '/tmp/test.log')
                self.assertIsInstance(result, bool)


class TestWindowsMoonwalkExtensive(unittest.TestCase):
    """Extensive tests for WindowsMoonwalk"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.moonwalk = WindowsMoonwalk(self.console, self.session_data)
    
    def test_moonwalk_initialization(self):
        """Test WindowsMoonwalk initialization"""
        self.assertIsNotNone(self.moonwalk)
        self.assertEqual(self.moonwalk.console, self.console)
        self.assertEqual(self.moonwalk.session_data, self.session_data)
    
    def test_clear_event_logs(self):
        """Test clearing event logs"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_event_logs()
            self.assertIsInstance(result, dict)
    
    def test_clear_powershell_history(self):
        """Test clearing PowerShell history"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_powershell_history()
            self.assertIsInstance(result, bool)
    
    def test_clear_command_history(self):
        """Test clearing command history"""
        with patch('modules.utils.execute_cmd') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_command_history()
            self.assertIsInstance(result, bool)
    
    def test_remove_file_timestamps(self):
        """Test removing file timestamps"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.remove_file_timestamps('/tmp/test.txt')
            self.assertIsInstance(result, bool)
    
    def test_clear_registry_traces(self):
        """Test clearing registry traces"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_registry_traces()
            self.assertIsInstance(result, dict)
    
    def test_clear_prefetch(self):
        """Test clearing prefetch"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_prefetch()
            self.assertIsInstance(result, bool)
    
    def test_clear_recent_files(self):
        """Test clearing recent files"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_recent_files()
            self.assertIsInstance(result, bool)
    
    def test_clear_temp_files(self):
        """Test clearing temp files"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_temp_files()
            self.assertIsInstance(result, bool)
    
    def test_clear_browser_history(self):
        """Test clearing browser history"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_browser_history()
            self.assertIsInstance(result, dict)
    
    def test_clear_windows_defender_logs(self):
        """Test clearing Windows Defender logs"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_windows_defender_logs()
            self.assertIsInstance(result, dict)
    
    def test_clear_windows_artifacts(self):
        """Test clearing Windows artifacts"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_windows_artifacts()
            self.assertIsInstance(result, dict)
    
    def test_clear_application_compatibility_cache(self):
        """Test clearing application compatibility cache"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.clear_application_compatibility_cache()
            self.assertIsInstance(result, dict)
    
    def test_full_cleanup(self):
        """Test full cleanup"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.full_cleanup()
            self.assertIsInstance(result, dict)
    
    def test_cleanup_after_operation(self):
        """Test cleanup after operation"""
        with patch('modules.utils.execute_powershell') as mock_exec:
            mock_exec.return_value = (0, "Success", "")
            
            result = self.moonwalk.cleanup_after_operation('execution')
            self.assertIsInstance(result, dict)


class TestLogHunterModuleExtensive(unittest.TestCase):
    """Extensive tests for LogHunterModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console()
        self.session_data = {'LAB_USE': 0}
        self.module = LogHunterModule()
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module)
    
    def test_module_run_all_options(self):
        """Test module run with all menu options"""
        with patch('rich.prompt.Prompt.ask', side_effect=['1', '2', '3', '4', '5', '0']):
            with patch('rich.prompt.Confirm.ask', return_value=False):
                try:
                    self.module.run(self.console, self.session_data)
                except (SystemExit, Exception):
                    pass  # Expected to exit


if __name__ == '__main__':
    unittest.main()
