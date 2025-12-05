"""SSH Session Management UI Module

Manage SSH sessions for remote command execution.
Allows the toolkit to work over SSH connections.
"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.ssh_session import get_ssh_manager, SSHSession
from modules.credential_manager import get_credential_manager, CredentialType


class SSHSessionModule:
    """SSH Session Management Module"""
    
    def __init__(self):
        self.ssh_manager = get_ssh_manager()
        self.cred_manager = get_credential_manager()
    
    def run(self, console: Console, session_data: dict):
        """Run SSH session management"""
        while True:
            console.print(Panel(
                "[bold]SSH Session Management[/bold]\n\n"
                "Manage SSH connections for remote command execution.\n"
                "All commands will execute on the active SSH session.",
                title="SSH Sessions",
                border_style="cyan"
            ))
            console.print()
            
            # Show active session
            active = self.ssh_manager.get_active_session()
            if active:
                console.print(f"[green]Active Session:[/green] {active}")
            else:
                console.print("[yellow]No active SSH session (commands execute locally)[/yellow]")
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Create SSH Session")
            table.add_row("2", "Create from Stored Credentials")
            table.add_row("3", "List Sessions")
            table.add_row("4", "Activate Session")
            table.add_row("5", "Test Connection")
            table.add_row("6", "Remove Session")
            table.add_row("7", "Show Active Session Details")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._create_session(console)
            elif choice == '2':
                self._create_from_credentials(console)
            elif choice == '3':
                self._list_sessions(console)
            elif choice == '4':
                self._activate_session(console)
            elif choice == '5':
                self._test_connection(console)
            elif choice == '6':
                self._remove_session(console)
            elif choice == '7':
                self._show_active_details(console)
            
            console.print()
    
    def _create_session(self, console: Console):
        """Create a new SSH session"""
        name = Prompt.ask("Session name")
        host = Prompt.ask("SSH host (IP or hostname)")
        user = Prompt.ask("SSH username", default="")
        user = user if user else None
        
        auth_method = Prompt.ask("Authentication", choices=['key', 'password'], default='password')
        
        key_file = None
        password = None
        
        if auth_method == 'key':
            key_file = Prompt.ask("SSH key file path")
        else:
            password = Prompt.ask("SSH password", password=True)
        
        port = Prompt.ask("SSH port", default="22")
        try:
            port = int(port)
        except ValueError:
            port = 22
        
        session = self.ssh_manager.create_session(name, host, user, key_file, password, port)
        console.print(f"[green]SSH session '{name}' created[/green]")
        
        if Confirm.ask("Activate this session?", default=True):
            self.ssh_manager.activate_session(name)
            console.print(f"[green]Session '{name}' activated[/green]")
    
    def _create_from_credentials(self, console: Console):
        """Create SSH session from stored credentials"""
        host = Prompt.ask("SSH host (IP or hostname)")
        
        # Find credentials for this host
        creds = self.cred_manager.get_credentials_by_target(host)
        ssh_creds = [c for c in creds if c.cred_type in [CredentialType.SSH_KEY.value, CredentialType.PASSWORD.value]]
        
        if not ssh_creds:
            console.print(f"[yellow]No SSH credentials found for {host}[/yellow]")
            if Confirm.ask("Create session manually?", default=True):
                self._create_session(console)
            return
        
        console.print(f"\n[green]Found {len(ssh_creds)} credential(s)[/green]")
        for i, cred in enumerate(ssh_creds, 1):
            cred_type = "SSH Key" if cred.cred_type == CredentialType.SSH_KEY.value else "Password"
            console.print(f"  {i}. {cred.username} ({cred_type})")
        
        choice = Prompt.ask("Select credential", choices=[str(i) for i in range(1, len(ssh_creds) + 1)], default='1')
        selected_cred = ssh_creds[int(choice) - 1]
        
        name = Prompt.ask("Session name", default=f"{host}_{selected_cred.username}")
        
        session = self.ssh_manager.create_session_from_credentials(name, host, selected_cred.id)
        if session:
            console.print(f"[green]SSH session '{name}' created from credentials[/green]")
            if Confirm.ask("Activate this session?", default=True):
                self.ssh_manager.activate_session(name)
                console.print(f"[green]Session '{name}' activated[/green]")
        else:
            console.print("[red]Failed to create session[/red]")
    
    def _list_sessions(self, console: Console):
        """List all SSH sessions"""
        sessions = self.ssh_manager.list_sessions()
        
        if not sessions:
            console.print("[yellow]No SSH sessions configured[/yellow]")
            return
        
        table = Table(title="SSH Sessions", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Host", style="white")
        table.add_column("User", style="yellow")
        table.add_column("Auth", style="magenta")
        table.add_column("Active", style="green" if True else "dim")
        
        active_name = self.ssh_manager.active_session
        
        for name in sessions:
            session = self.ssh_manager.sessions[name]
            auth = "Key" if session.key_file else "Password"
            is_active = "✓" if name == active_name else ""
            
            table.add_row(
                name,
                session.host,
                session.user or "",
                auth,
                is_active
            )
        
        console.print(table)
    
    def _activate_session(self, console: Console):
        """Activate an SSH session"""
        sessions = self.ssh_manager.list_sessions()
        
        if not sessions:
            console.print("[yellow]No SSH sessions configured[/yellow]")
            return
        
        console.print("\nSessions:")
        for i, name in enumerate(sessions, 1):
            marker = " [ACTIVE]" if name == self.ssh_manager.active_session else ""
            console.print(f"  {i}. {name}{marker}")
        
        choice = Prompt.ask("Select session", choices=[str(i) for i in range(1, len(sessions) + 1)], default='1')
        selected_name = sessions[int(choice) - 1]
        
        if self.ssh_manager.activate_session(selected_name):
            console.print(f"[green]Session '{selected_name}' activated[/green]")
            console.print("[cyan]All subsequent commands will execute on this SSH host[/cyan]")
        else:
            console.print("[red]Failed to activate session[/red]")
    
    def _test_connection(self, console: Console):
        """Test SSH connection"""
        active = self.ssh_manager.get_active_session()
        
        if not active:
            console.print("[yellow]No active session to test[/yellow]")
            return
        
        console.print(f"[cyan]Testing connection to {active}...[/cyan]")
        
        from modules.utils import execute_cmd
        exit_code, stdout, stderr = execute_cmd(
            "whoami",
            ssh_host=active.host,
            ssh_user=active.user,
            ssh_key=active.key_file,
            ssh_password=active.password,
            use_active_ssh=False  # Don't use active session since we're testing it
        )
        
        if exit_code == 0:
            console.print(f"[green]Connection successful![/green]")
            console.print(f"[green]Remote user: {stdout.strip()}[/green]")
        else:
            console.print(f"[red]Connection failed: {stderr}[/red]")
    
    def _remove_session(self, console: Console):
        """Remove an SSH session"""
        sessions = self.ssh_manager.list_sessions()
        
        if not sessions:
            console.print("[yellow]No SSH sessions configured[/yellow]")
            return
        
        console.print("\nSessions:")
        for i, name in enumerate(sessions, 1):
            console.print(f"  {i}. {name}")
        
        choice = Prompt.ask("Select session to remove", choices=[str(i) for i in range(1, len(sessions) + 1)], default='1')
        selected_name = sessions[int(choice) - 1]
        
        if Confirm.ask(f"Remove session '{selected_name}'?", default=False):
            if self.ssh_manager.remove_session(selected_name):
                console.print(f"[green]Session '{selected_name}' removed[/green]")
            else:
                console.print("[red]Failed to remove session[/red]")
    
    def _show_active_details(self, console: Console):
        """Show active session details"""
        active = self.ssh_manager.get_active_session()
        
        if not active:
            console.print("[yellow]No active SSH session[/yellow]")
            return
        
        console.print("\n[bold cyan]Active SSH Session Details[/bold cyan]")
        console.print(f"Host: {active.host}")
        console.print(f"User: {active.user or 'Not specified'}")
        console.print(f"Port: {active.port}")
        console.print(f"Authentication: {'Key file' if active.key_file else 'Password'}")
        if active.key_file:
            console.print(f"Key File: {active.key_file}")
        console.print(f"Session String: {active}")
