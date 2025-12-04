"""OPSEC Considerations Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console


class OPSECModule:
    """Module for OPSEC considerations"""
    
    def run(self, console: Console, session_data: dict):
        """Run OPSEC module"""
        while True:
            console.print(Panel(
                "[bold]OPSEC Considerations[/bold]\n\n"
                "Operational security best practices and evasion techniques.",
                title="Module 6",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Tool Selection & Native Binaries")
            table.add_row("2", "Detection Evasion")
            table.add_row("3", "Logging & Monitoring Avoidance")
            table.add_row("4", "Behavioral Blending")
            table.add_row("5", "Network OPSEC")
            table.add_row("6", "OPSEC Checklist")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._tool_selection(console, session_data)
            elif choice == '2':
                self._detection_evasion(console, session_data)
            elif choice == '3':
                self._logging_avoidance(console, session_data)
            elif choice == '4':
                self._behavioral_blending(console, session_data)
            elif choice == '5':
                self._network_opsec(console, session_data)
            elif choice == '6':
                self._opsec_checklist(console, session_data)
            
            console.print()
    
    def _tool_selection(self, console: Console, session_data: dict):
        """Tool selection and native binaries"""
        console.print("\n[bold cyan]Tool Selection & Native Binaries[/bold cyan]\n")
        
        console.print("[bold]Prefer Native Windows Tools:[/bold]")
        native_tools = {
            "Built-in Commands": [
                "sc, net, wmic, schtasks",
                "PowerShell cmdlets",
                "Windows Management APIs"
            ],
            "Why Native Tools": [
                "Already present on system",
                "Less suspicious in logs",
                "Resemble legitimate admin activity",
                "No file drops required"
            ],
            "Avoid When Possible": [
                "Custom malware/backdoors",
                "Third-party tools (Mimikatz, etc.)",
                "Dropped executables",
                "Suspicious file names"
            ]
        }
        
        for category, items in native_tools.items():
            console.print(f"[bold]{category}:[/bold]")
            for item in items:
                console.print(f"  • {item}")
            console.print()
        
        console.print("[bold]PowerShell Best Practices:[/bold]")
        ps_practices = [
            "Use PowerShell remoting (WinRM) over file drops",
            "Execute scripts from memory when possible",
            "Use -EncodedCommand for obfuscation",
            "Leverage existing PowerShell profiles",
            "Use legitimate PowerShell modules"
        ]
        
        for practice in ps_practices:
            console.print(f"  • {practice}")
    
    def _detection_evasion(self, console: Console, session_data: dict):
        """Detection evasion techniques"""
        console.print("\n[bold cyan]Detection Evasion[/bold cyan]\n")
        
        evasion_techniques = {
            "Process Execution": [
                "Use legitimate process names",
                "Execute from expected locations",
                "Avoid suspicious command-line arguments",
                "Use process hollowing sparingly"
            ],
            "File System": [
                "Avoid dropping files to suspicious locations",
                "Use temporary directories appropriately",
                "Clean up artifacts immediately",
                "Avoid suspicious file names"
            ],
            "Network": [
                "Use common ports (SMB, RDP, WinRM)",
                "Avoid unusual protocols",
                "Blend into existing traffic patterns",
                "Use encrypted channels when possible"
            ],
            "Timing": [
                "Operate during business hours",
                "Match existing admin patterns",
                "Avoid rapid-fire operations",
                "Space out activities"
            ]
        }
        
        for technique, methods in evasion_techniques.items():
            console.print(f"[bold]{technique}:[/bold]")
            for method in methods:
                console.print(f"  • {method}")
            console.print()
    
    def _logging_avoidance(self, console: Console, session_data: dict):
        """Logging and monitoring avoidance"""
        console.print("\n[bold cyan]Logging & Monitoring Avoidance[/bold cyan]\n")
        
        console.print("[bold]Event Logs to Consider:[/bold]")
        logs = {
            "Security Log": [
                "Logon events (4624, 4625)",
                "Account management (4720, 4728)",
                "Process creation (4688)",
                "Service creation (7045)"
            ],
            "System Log": [
                "Service start/stop (7034, 7035)",
                "Driver loading",
                "System errors"
            ],
            "Application Log": [
                "Application-specific events",
                "Service-specific logs"
            ],
            "PowerShell Logs": [
                "Module logging",
                "Script block logging",
                "Transcription logs"
            ]
        }
        
        for log_type, events in logs.items():
            console.print(f"[bold]{log_type}:[/bold]")
            for event in events:
                console.print(f"  • {event}")
            console.print()
        
        console.print("[bold]Mitigation Strategies:[/bold]")
        strategies = [
            "Use legitimate accounts when possible",
            "Operate during normal admin hours",
            "Minimize privileged operations",
            "Use built-in tools that generate expected logs",
            "Clear logs only when necessary and possible"
        ]
        
        for strategy in strategies:
            console.print(f"  • {strategy}")
    
    def _behavioral_blending(self, console: Console, session_data: dict):
        """Behavioral blending"""
        console.print("\n[bold cyan]Behavioral Blending[/bold cyan]\n")
        
        console.print("[bold]Blend Into Existing Patterns:[/bold]")
        patterns = {
            "Remote Admin Patterns": [
                "Use same tools admins use",
                "Follow same workflows",
                "Access same systems admins access",
                "Use same service accounts"
            ],
            "Automation Patterns": [
                "Use scheduled tasks like automation",
                "Use service accounts appropriately",
                "Follow existing script patterns",
                "Use existing deployment mechanisms"
            ],
            "Service Account Usage": [
                "Use service accounts for automation",
                "Follow existing service account patterns",
                "Avoid using service accounts interactively",
                "Match existing service account permissions"
            ]
        }
        
        for pattern, methods in patterns.items():
            console.print(f"[bold]{pattern}:[/bold]")
            for method in methods:
                console.print(f"  • {method}")
            console.print()
        
        console.print("[bold]Key Principle:[/bold]")
        console.print("  • Small numbers of high-value pivots")
        console.print("  • Over broad, noisy scanning")
        console.print("  • Quality over quantity")
    
    def _network_opsec(self, console: Console, session_data: dict):
        """Network OPSEC"""
        console.print("\n[bold cyan]Network OPSEC[/bold cyan]\n")
        
        console.print("[bold]Network Considerations:[/bold]")
        considerations = {
            "Port Usage": [
                "Use standard ports (SMB 445, RDP 3389, WinRM 5985/5986)",
                "Avoid unusual ports",
                "Use encrypted channels when possible"
            ],
            "Protocol Selection": [
                "Prefer encrypted protocols (WinRM HTTPS, RDP)",
                "Use standard Windows protocols",
                "Avoid custom protocols"
            ],
            "Traffic Patterns": [
                "Match existing admin traffic",
                "Avoid rapid scanning",
                "Space out network operations",
                "Use existing network paths"
            ],
            "SSH Tunneling": [
                "Use SSH for encrypted tunnels",
                "Leverage existing SSH access",
                "Port forward through jump hosts",
                "Use dynamic port forwarding for SOCKS"
            ]
        }
        
        for consideration, methods in considerations.items():
            console.print(f"[bold]{consideration}:[/bold]")
            for method in methods:
                console.print(f"  • {method}")
            console.print()
    
    def _opsec_checklist(self, console: Console, session_data: dict):
        """OPSEC checklist"""
        console.print("\n[bold cyan]OPSEC Checklist[/bold cyan]\n")
        
        checklist = {
            "Tool Selection": [
                "✓ Prefer native Windows binaries",
                "✓ Avoid custom malware when possible",
                "✓ Use built-in PowerShell cmdlets",
                "✓ Minimize file drops"
            ],
            "Execution": [
                "✓ Use short, scripted operations",
                "✓ Prefer in-memory execution",
                "✓ Use legitimate process names",
                "✓ Execute from expected locations"
            ],
            "Network": [
                "✓ Use common ports and protocols",
                "✓ Encrypt communications when possible",
                "✓ Blend into existing traffic",
                "✓ Avoid rapid scanning"
            ],
            "Persistence": [
                "✓ Prefer central control planes",
                "✓ Use legitimate persistence mechanisms",
                "✓ Avoid excessive endpoint modification",
                "✓ Clean up artifacts"
            ],
            "Behavior": [
                "✓ Operate during business hours",
                "✓ Match existing admin patterns",
                "✓ Use service accounts appropriately",
                "✓ Small number of high-value pivots"
            ]
        }
        
        for category, items in checklist.items():
            console.print(f"[bold]{category}:[/bold]")
            for item in items:
                console.print(f"  {item}")
            console.print()
        
        console.print("[bold]Overarching Themes:[/bold]")
        themes = [
            "Prefer native admin tools over custom malware",
            "Prefer short, scripted operations over long interactive sessions",
            "Prefer small numbers of high-value pivots over broad, noisy scanning",
            "Aim to blend into existing remote-admin patterns",
            "Use existing service accounts and automation appropriately"
        ]
        
        for theme in themes:
            console.print(f"  • {theme}")
