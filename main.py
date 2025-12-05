#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Lateral Movement Simulation TUI
Red Team / Threat Modeling Tool

A comprehensive self-contained tool for Windows lateral movement simulation
and threat modeling, aligned with APT-41 TTPs and MITRE ATT&CK framework.

Author: Security Research Team
Version: 1.0.0
License: For authorized security testing only
"""

import sys
import ipaddress
import logging
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich import box
import os
from pathlib import Path

# Configure logging for discovery
logging.basicConfig(level=logging.WARNING)

# Import modules
from modules.foothold import FootholdModule
from modules.utils import select_menu_option
from modules.orientation import OrientationModule
from modules.identity import IdentityModule
from modules.lateral import LateralModule
from modules.consolidation import ConsolidationModule
from modules.opsec import OPSECModule
from modules.llm_agent import LLMAgentModule
from modules.madcert_integration import MADCertModule
from modules.lolbins_reference import LOLBinsModule
from modules.auto_enumerate import AutoEnumerateModule
from modules.loghunter_integration import LogHunterModule, MoonwalkModule
from modules.pe5_system_escalation import PE5SystemEscalationModule
from modules.credential_manager_ui import CredentialManagerModule
from modules.vlan_bypass import VLANBypassModule

console = Console()

# LAB_USE flag: Set to 1 to limit operations to local IP ranges only
LAB_USE = 1

# AUTO_ENUMERATE flag: Set to 1 to automatically enumerate all modules and generate report
AUTO_ENUMERATE = 0  # Set to 1 for automatic enumeration on startup

# AUTO_ENUMERATE_DEPTH: Maximum depth for lateral movement (default: 3)
# Can be overridden via environment variable: AUTO_ENUMERATE_DEPTH=5
AUTO_ENUMERATE_DEPTH = int(os.getenv('AUTO_ENUMERATE_DEPTH', '3'))

# Local IP ranges (RFC 1918 + loopback)
LOCAL_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]


def is_local_ip(ip_str):
    """Check if IP address is in local ranges"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in LOCAL_IP_RANGES)
    except ValueError:
        return False


class LateralMovementTUI:
    """Main TUI application for Windows lateral movement simulation"""
    
    def __init__(self):
        self.console = console
        self.discovered_components = self._discover_and_preload_components()
        self.modules = self._initialize_modules()
        self.session_data = {
            'LAB_USE': LAB_USE,
            'AUTO_ENUMERATE': AUTO_ENUMERATE,
            'AUTO_ENUMERATE_DEPTH': AUTO_ENUMERATE_DEPTH,
            'is_local_ip': is_local_ip,
            'discovered_components': self.discovered_components,  # Make available to modules
        }
    
    def _discover_and_preload_components(self) -> dict:
        """Discover all available components and preload requirements automatically"""
        try:
            from modules.discovery import ComponentDiscovery
            
            # First discovery pass
            discovery = ComponentDiscovery(auto_preload=False)
            
            # Check for missing optional dependencies
            deps = discovery.discovered_components.get('optional_dependencies', {})
            missing = [k for k, v in deps.items() if not v]
            
            # Auto-preload missing dependencies silently
            if missing:
                self.console.print(f"[dim]Preloading optional dependencies: {', '.join(missing)}...[/dim]", end='')
                results = discovery.preload_requirements(interactive=False)
                installed = [k for k, v in results.items() if v]
                if installed:
                    self.console.print(f" [green]✓[/green]")
                    # Re-discover after installation
                    discovery = ComponentDiscovery(auto_preload=False)
                else:
                    self.console.print(f" [yellow]⚠[/yellow]")
            
            return discovery.get_summary()
        except Exception as e:
            logging.debug(f"Component discovery failed: {e}")
            # Fallback discovery
            return self._fallback_discovery()
    
    def _fallback_discovery(self) -> dict:
        """Fallback component discovery if discovery module fails"""
        components = {
            'pe5_framework': {'available': Path('pe5_framework_extracted/pe5_framework').exists()},
            'relay_service': {'available': Path('relay').exists()},
            'optional_dependencies': {}
        }
        
        # Check optional dependencies
        dep_map = {
            'websockets': 'websockets',
            'aiohttp': 'aiohttp',
            'yaml': 'yaml',
            'cryptography': 'cryptography'
        }
        
        for dep_key, dep_module in dep_map.items():
            try:
                __import__(dep_module)
                components['optional_dependencies'][dep_key] = True
            except ImportError:
                components['optional_dependencies'][dep_key] = False
        
        return components
    
    def _initialize_modules(self) -> dict:
        """Initialize modules with availability checks"""
        modules = {
            '1': ('Foothold & Starting Point', FootholdModule()),
            '2': ('Local Orientation', OrientationModule()),
            '3': ('Identity Acquisition', IdentityModule()),
            '4': ('Lateral Movement Channels', LateralModule()),
            '5': ('Consolidation & Dominance', ConsolidationModule()),
            '6': ('OPSEC Considerations', OPSECModule()),
            '7': ('LLM Remote Agent', LLMAgentModule()),
            '8': ('MADCert Certificate Generation', MADCertModule()),
            '9': ('LOLBins Reference', LOLBinsModule()),
            '10': ('LogHunter Integration', LogHunterModule()),
            '11': ('Windows Moonwalk', MoonwalkModule()),
            '13': ('Credential Manager', CredentialManagerModule()),
            '14': ('VLAN Bypass', VLANBypassModule()),
        }
        
        # PE5 module (always available, checks framework internally)
        try:
            modules['12'] = ('[PRIMARY] PE5 SYSTEM Escalation', PE5SystemEscalationModule())
        except Exception as e:
            console.print(f"[yellow]Warning: PE5 module initialization issue: {e}[/yellow]")
            modules['12'] = ('[PRIMARY] PE5 SYSTEM Escalation (Limited)', None)
        
        return modules
        
    def show_banner(self):
        """Display application banner"""
        banner = Text()
        banner.append("Windows Lateral Movement Simulation", style="bold cyan")
        banner.append("\n", style="bold cyan")
        banner.append("Red Team / Threat Modeling TUI", style="dim white")
        
        lab_status = "[bold yellow]LAB MODE[/bold yellow] - Local IP ranges only" if LAB_USE == 1 else "[bold green]LIVE MODE[/bold green] - Full execution enabled"
        enum_status = "[bold cyan]AUTO-ENUMERATE[/bold cyan]" if AUTO_ENUMERATE == 1 else ""
        depth_status = f"[bold cyan]DEPTH={AUTO_ENUMERATE_DEPTH}[/bold cyan]" if AUTO_ENUMERATE == 1 else ""
        
        status_line = f"{lab_status}"
        if enum_status:
            status_line += f" | {enum_status}"
            if depth_status:
                status_line += f" ({depth_status})"
        
        # Component availability status
        comp_status = []
        if self.discovered_components.get('pe5_framework', {}).get('available'):
            comp_status.append("[green]PE5[/green]")
        if self.discovered_components.get('relay_service', {}).get('available'):
            comp_status.append("[green]Relay[/green]")
        if comp_status:
            status_line += f" | Components: {', '.join(comp_status)}"
        
        panel = Panel(
            banner,
            box=box.DOUBLE,
            border_style="cyan",
            title="[bold red]⚠ RED TEAM TOOL ⚠[/bold red]",
            subtitle=f"[dim]For authorized testing only | {status_line}[/dim]"
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
            '6': 'OPSEC best practices & evasion',
            '7': 'LLM remote agent with self-coding execution',
            '8': 'MADCert certificate generation for AD environments',
            '9': 'LOLBins reference - Living Off The Land Binaries',
            '10': 'LogHunter - Windows event log analysis & hunting',
            '11': 'Windows Moonwalk - Cover tracks & clear logs',
            '12': '[PRIMARY] PE5 SYSTEM escalation - Kernel-level token manipulation',
            '13': 'Credential Manager - Persistent credential storage & management',
            '14': 'VLAN Bypass - Network segmentation bypass techniques'
        }
        
        for key, (name, _) in self.modules.items():
            table.add_row(f"[bold]{key}[/bold]", name, descriptions[key])
        
        table.add_row("[bold]0[/bold]", "[dim]Exit[/dim]", "[dim]Exit application[/dim]")
        table.add_row("[bold]?[/bold]", "[dim cyan]Component Discovery[/dim cyan]", "[dim]Show available components & preload[/dim]")
        
        self.console.print(table)
        self.console.print()
        
    def run(self):
        """Main application loop"""
        self.show_banner()
        
        # Check for AUTO_ENUMERATE mode
        if AUTO_ENUMERATE == 1:
            self.console.print(f"[bold yellow]AUTO-ENUMERATE MODE ENABLED[/bold yellow]")
            self.console.print(f"[bold cyan]Maximum lateral movement depth: {AUTO_ENUMERATE_DEPTH}[/bold cyan]\n")
            auto_module = AutoEnumerateModule()
            auto_module.run(self.console, self.session_data)
            if not Confirm.ask("\n[bold]Continue to interactive mode?[/bold]", default=False):
                return
        
        while True:
            self.show_main_menu()
            
            # Create menu options for navigation
            menu_options = []
            for key in sorted(self.modules.keys(), key=lambda x: int(x) if x.isdigit() else 999):
                name, _ = self.modules[key]
                menu_options.append({'key': key, 'label': name})
            menu_options.append({'key': '?', 'label': 'Component Discovery'})
            menu_options.append({'key': '0', 'label': 'Exit'})
            
            # Update choices list for Prompt validation
            valid_choices = [opt['key'] for opt in menu_options]
            
            choice = select_menu_option(
                self.console,
                menu_options,
                "Select module",
                default='0'
            )
            
            if choice == '?':
                self._show_full_discovery()
                continue
            
            if choice == '0':
                if Confirm.ask("\n[bold yellow]Exit application?[/bold yellow]"):
                    self.console.print("[green]Goodbye![/green]")
                    sys.exit(0)
                continue
            
            module_name, module_instance = self.modules[choice]
            
            # Check if module is available
            if module_instance is None:
                self.console.print(f"\n[bold red]Module '{module_name}' is not available[/bold red]")
                self.console.print("[yellow]This module requires additional components that were not found.[/yellow]\n")
                if Confirm.ask("[bold]Show component discovery report?[/bold]", default=True):
                    self._show_full_discovery()
                continue
            
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
