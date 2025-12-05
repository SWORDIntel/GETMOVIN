"""Credential Manager UI Module - TUI Interface for Credential Management"""

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from rich.tree import Tree
from rich.text import Text
from pathlib import Path
from modules.credential_manager import get_credential_manager, CredentialType, CredentialSource


class CredentialManagerModule:
    """TUI Module for Credential Manager"""
    
    def __init__(self):
        self.cred_manager = get_credential_manager()
    
    def run(self, console: Console, session_data: dict):
        """Run credential manager module"""
        while True:
            console.print(Panel(
                "[bold]Credential Manager[/bold]\n\n"
                "Manage persistent credential storage for lateral movement operations.",
                title="Credential Manager",
                border_style="cyan"
            ))
            console.print()
            
            # Show summary
            summary = self.cred_manager.get_summary()
            console.print(f"[cyan]Total Credentials:[/cyan] {summary['total']}")
            console.print(f"[cyan]Valid Credentials:[/cyan] {summary['valid']}")
            console.print(f"[cyan]Domains:[/cyan] {len(summary['domains'])}")
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "View All Credentials")
            table.add_row("2", "Search Credentials")
            table.add_row("3", "View by Type")
            table.add_row("4", "View by Domain")
            table.add_row("5", "View by Target")
            table.add_row("6", "Export Credentials")
            table.add_row("7", "Import Credentials")
            table.add_row("8", "Test Credentials")
            table.add_row("9", "Delete Credentials")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'], default='0')
            
            if choice == '0':
                break
            elif choice == '1':
                self._view_all(console)
            elif choice == '2':
                self._search(console)
            elif choice == '3':
                self._view_by_type(console)
            elif choice == '4':
                self._view_by_domain(console)
            elif choice == '5':
                self._view_by_target(console)
            elif choice == '6':
                self._export(console)
            elif choice == '7':
                self._import(console)
            elif choice == '8':
                self._test_credentials(console, session_data)
            elif choice == '9':
                self._delete(console)
            
            console.print()
    
    def _view_all(self, console: Console):
        """View all credentials"""
        credentials = self.cred_manager.get_all()
        
        if not credentials:
            console.print("[yellow]No credentials stored[/yellow]")
            return
        
        table = Table(title="All Credentials", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Type", style="white", width=15)
        table.add_column("Username", style="green", width=20)
        table.add_column("Domain", style="yellow", width=15)
        table.add_column("Target", style="magenta", width=20)
        table.add_column("Source", style="dim", width=15)
        table.add_column("Valid", style="green" if True else "red", width=6)
        
        for cred in credentials[:50]:  # Limit display
            table.add_row(
                cred.id[:8],
                cred.cred_type,
                cred.username or "",
                cred.domain or "",
                cred.target or "",
                cred.source,
                "✓" if cred.valid else "✗"
            )
        
        console.print(table)
        
        if len(credentials) > 50:
            console.print(f"\n[yellow]Showing first 50 of {len(credentials)} credentials[/yellow]")
    
    def _search(self, console: Console):
        """Search credentials"""
        search_term = Prompt.ask("Search term (username, domain, target, or type)")
        
        # Search through all credentials
        all_creds = self.cred_manager.get_all()
        results = [
            c for c in all_creds
            if search_term.lower() in (c.username or "").lower() or
               search_term.lower() in (c.domain or "").lower() or
               search_term.lower() in (c.target or "").lower() or
               search_term.lower() in c.cred_type.lower()
        ]
        
        if not results:
            console.print("[yellow]No credentials found[/yellow]")
            return
        
        table = Table(title=f"Search Results: '{search_term}'", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Type", style="white", width=15)
        table.add_column("Username", style="green", width=20)
        table.add_column("Domain", style="yellow", width=15)
        table.add_column("Target", style="magenta", width=20)
        table.add_column("Valid", style="green" if True else "red", width=6)
        
        for cred in results:
            table.add_row(
                cred.id[:8],
                cred.cred_type,
                cred.username or "",
                cred.domain or "",
                cred.target or "",
                "✓" if cred.valid else "✗"
            )
        
        console.print(table)
    
    def _view_by_type(self, console: Console):
        """View credentials by type"""
        types = [e.value for e in CredentialType]
        
        console.print("\nCredential Types:")
        for i, cred_type in enumerate(types, 1):
            console.print(f"  {i}. {cred_type}")
        
        choice = Prompt.ask("Select type", choices=[str(i) for i in range(1, len(types) + 1)], default='1')
        
        selected_type = types[int(choice) - 1]
        # Convert string to enum
        cred_type_enum = CredentialType(selected_type)
        credentials = self.cred_manager.get_credentials_by_type(cred_type_enum)
        
        if not credentials:
            console.print(f"[yellow]No {selected_type} credentials found[/yellow]")
            return
        
        table = Table(title=f"{selected_type} Credentials", box=box.ROUNDED)
        table.add_column("Username", style="green", width=20)
        table.add_column("Domain", style="yellow", width=15)
        table.add_column("Target", style="magenta", width=20)
        table.add_column("Source", style="dim", width=15)
        table.add_column("Valid", style="green" if True else "red", width=6)
        
        for cred in credentials:
            table.add_row(
                cred.username or "",
                cred.domain or "",
                cred.target or "",
                cred.source,
                "✓" if cred.valid else "✗"
            )
        
        console.print(table)
    
    def _view_by_domain(self, console: Console):
        """View credentials by domain"""
        domains = self.cred_manager.get_summary()['domains']
        
        if not domains:
            console.print("[yellow]No domains found[/yellow]")
            return
        
        console.print("\nDomains:")
        for i, domain in enumerate(domains[:20], 1):
            console.print(f"  {i}. {domain}")
        
        choice = Prompt.ask("Select domain", choices=[str(i) for i in range(1, min(21, len(domains) + 1))], default='1')
        
        selected_domain = domains[int(choice) - 1]
        credentials = self.cred_manager.get_credentials_by_domain(selected_domain)
        
        table = Table(title=f"Credentials for Domain: {selected_domain}", box=box.ROUNDED)
        table.add_column("Type", style="white", width=15)
        table.add_column("Username", style="green", width=20)
        table.add_column("Target", style="magenta", width=20)
        table.add_column("Valid", style="green" if True else "red", width=6)
        
        for cred in credentials:
            table.add_row(
                cred.cred_type,
                cred.username or "",
                cred.target or "",
                "✓" if cred.valid else "✗"
            )
        
        console.print(table)
    
    def _view_by_target(self, console: Console):
        """View credentials by target"""
        target = Prompt.ask("Target IP or hostname")
        
        credentials = self.cred_manager.get_credentials_by_target(target)
        
        if not credentials:
            console.print(f"[yellow]No credentials found for {target}[/yellow]")
            return
        
        table = Table(title=f"Credentials for Target: {target}", box=box.ROUNDED)
        table.add_column("Type", style="white", width=15)
        table.add_column("Username", style="green", width=20)
        table.add_column("Domain", style="yellow", width=15)
        table.add_column("Protocol", style="cyan", width=10)
        table.add_column("Port", style="cyan", width=6)
        table.add_column("Valid", style="green" if True else "red", width=6)
        
        for cred in credentials:
            table.add_row(
                cred.cred_type,
                cred.username or "",
                cred.domain or "",
                cred.metadata.get('protocol', ''),
                str(cred.metadata.get('port', '')),
                "✓" if cred.valid else "✗"
            )
        
        console.print(table)
    
    def _export(self, console: Console):
        """Export credentials"""
        export_format = Prompt.ask("Export format", choices=['csv', 'hashcat', 'secretsdump'], default='csv')
        
        try:
            if export_format == 'csv':
                output_path = self.cred_manager.export_credentials_csv()
            elif export_format == 'hashcat':
                output_path = self.cred_manager.export_hashcat()
            elif export_format == 'secretsdump':
                output_path = self.cred_manager.export_secretsdump()
            
            console.print(f"[green]Credentials exported to {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")
    
    def _import(self, console: Console):
        """Import credentials"""
        import_file = Prompt.ask("Import file path")
        
        if not Path(import_file).exists():
            console.print(f"[red]File not found: {import_file}[/red]")
            return
        
        console.print("[yellow]Import functionality - manual import via credential manager API[/yellow]")
        console.print("[dim]Use credential_manager.add_password(), add_hash(), etc. programmatically[/dim]")
    
    def _test_credentials(self, console: Console, session_data: dict):
        """Test credentials against targets"""
        target = Prompt.ask("Target IP or hostname to test")
        protocol = Prompt.ask("Protocol", choices=['smb', 'winrm', 'rdp', 'ssh'], default='smb')
        
        credentials = self.cred_manager.get_credentials_by_target(target)
        if not credentials:
            # Try to get credentials by domain or any credentials
            credentials = self.cred_manager.get_all()[:10]
        
        if not credentials:
            console.print("[yellow]No credentials to test[/yellow]")
            return
        
        console.print(f"\n[cyan]Testing {len(credentials)} credentials against {target}...[/cyan]\n")
        
        from modules.utils import execute_cmd, execute_powershell
        lab_use = session_data.get('LAB_USE', 0)
        
        valid_count = 0
        for cred in credentials:
            if cred.cred_type == CredentialType.PASSWORD.value:
                # Test SMB
                if protocol == 'smb':
                    test_cmd = f'net use \\\\{target}\\C$ /user:{cred.domain or ""}\\{cred.username} {cred.password or ""}'
                    exit_code, stdout, stderr = execute_cmd(test_cmd, lab_use=lab_use)
                    if exit_code == 0:
                        console.print(f"[green]✓ Valid: {cred.username}@{cred.domain or 'local'}[/green]")
                        self.cred_manager.mark_as_valid(cred.id, True)
                        valid_count += 1
                    else:
                        console.print(f"[red]✗ Invalid: {cred.username}@{cred.domain or 'local'}[/red]")
                        self.cred_manager.mark_as_valid(cred.id, False)
        
        console.print(f"\n[cyan]Test complete: {valid_count}/{len(credentials)} valid[/cyan]")
    
    def _delete(self, console: Console):
        """Delete credentials"""
        cred_id = Prompt.ask("Credential ID to delete")
        
        if Confirm.ask(f"Delete credential {cred_id}?"):
            if self.cred_manager.remove_credential(cred_id):
                console.print("[green]Credential deleted[/green]")
            else:
                console.print("[red]Credential not found[/red]")
