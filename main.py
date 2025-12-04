#!/usr/bin/env python3
"""
Windows Lateral Movement Simulation TUI
Red Team / Threat Modeling Tool
"""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich import box
import os

# Import modules
from modules.foothold import FootholdModule
from modules.orientation import OrientationModule
from modules.identity import IdentityModule
from modules.lateral import LateralModule
from modules.consolidation import ConsolidationModule
from modules.opsec import OPSECModule

console = Console()


class LateralMovementTUI:
    """Main TUI application for Windows lateral movement simulation"""
    
    def __init__(self):
        self.console = console
        self.modules = {
            '1': ('Foothold & Starting Point', FootholdModule()),
            '2': ('Local Orientation', OrientationModule()),
            '3': ('Identity Acquisition', IdentityModule()),
            '4': ('Lateral Movement Channels', LateralModule()),
            '5': ('Consolidation & Dominance', ConsolidationModule()),
            '6': ('OPSEC Considerations', OPSECModule()),
        }
        self.session_data = {}
        
    def show_banner(self):
        """Display application banner"""
        banner = Text()
        banner.append("Windows Lateral Movement Simulation", style="bold cyan")
        banner.append("\n", style="bold cyan")
        banner.append("Red Team / Threat Modeling TUI", style="dim white")
        
        panel = Panel(
            banner,
            box=box.DOUBLE,
            border_style="cyan",
            title="[bold red]⚠ RED TEAM TOOL ⚠[/bold red]",
            subtitle="[dim]For authorized testing only[/dim]"
        )
        self.console.print(panel)
        self.console.print()
        
    def show_main_menu(self):
        """Display main menu"""
        table = Table(title="[bold cyan]Main Menu[/bold cyan]", box=box.ROUNDED, show_header=False)
        table.add_column("Option", style="cyan", width=3)
        table.add_column("Module", style="white")
        table.add_column("Description", style="dim white")
        
        descriptions = {
            '1': 'SSH foothold assessment & initial access',
            '2': 'Identity mapping, host role, network visibility',
            '3': 'Credential harvesting & domain context',
            '4': 'SMB/RPC, WinRM, WMI, RDP pivoting',
            '5': 'Strategic objectives & persistence',
            '6': 'OPSEC best practices & evasion'
        }
        
        for key, (name, _) in self.modules.items():
            table.add_row(f"[bold]{key}[/bold]", name, descriptions[key])
        
        table.add_row("[bold]0[/bold]", "[dim]Exit[/dim]", "[dim]Exit application[/dim]")
        
        self.console.print(table)
        self.console.print()
        
    def run(self):
        """Main application loop"""
        self.show_banner()
        
        while True:
            self.show_main_menu()
            
            choice = Prompt.ask(
                "[bold cyan]Select module[/bold cyan]",
                choices=['0', '1', '2', '3', '4', '5', '6'],
                default='0'
            )
            
            if choice == '0':
                if Confirm.ask("\n[bold yellow]Exit application?[/bold yellow]"):
                    self.console.print("[green]Goodbye![/green]")
                    sys.exit(0)
                continue
            
            module_name, module_instance = self.modules[choice]
            
            self.console.clear()
            self.console.print(f"\n[bold cyan]→ {module_name}[/bold cyan]\n")
            
            try:
                module_instance.run(self.console, self.session_data)
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled[/yellow]")
                if not Confirm.ask("\n[bold]Return to main menu?[/bold]", default=True):
                    sys.exit(0)
            except Exception as e:
                self.console.print(f"\n[bold red]Error:[/bold red] {e}")
                if not Confirm.ask("\n[bold]Return to main menu?[/bold]", default=True):
                    sys.exit(0)
            
            self.console.print()


def main():
    """Entry point"""
    try:
        app = LateralMovementTUI()
        app.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
