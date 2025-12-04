"""Utility functions for modules"""

import subprocess
import ipaddress
import re
import sys
from typing import Optional, Tuple, List, Dict
from rich.console import Console
from rich.table import Table
from rich import box


def is_local_ip(ip_str: str) -> bool:
    """Check if IP address is in local ranges"""
    try:
        ip = ipaddress.ip_address(ip_str)
        local_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
        ]
        return any(ip in network for network in local_ranges)
    except ValueError:
        return False


def extract_ip_from_string(text: str) -> Optional[str]:
    """Extract IP address from string"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, text)
    return match.group(0) if match else None


def validate_target(target: str, lab_use: int) -> Tuple[bool, Optional[str]]:
    """Validate target IP/hostname for lab use restrictions"""
    if lab_use != 1:
        return True, None
    
    # Extract IP if present
    ip = extract_ip_from_string(target)
    if ip:
        if not is_local_ip(ip):
            return False, f"Target IP {ip} is not in local range. LAB_USE=1 restricts to local IPs only."
    
    # For hostnames, we'll allow them but warn
    # In a real scenario, you'd resolve the hostname first
    return True, None


def execute_command(command: str, shell: bool = True, check_lab: bool = True, lab_use: int = 0) -> Tuple[int, str, str]:
    """
    Execute a command and return exit code, stdout, stderr
    
    Args:
        command: Command to execute
        shell: Use shell execution
        check_lab: Check LAB_USE restrictions
        lab_use: LAB_USE flag value
    """
    if check_lab and lab_use == 1:
        # Extract IP addresses from command
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, command)
        for ip in ips:
            if not is_local_ip(ip):
                return 1, "", f"ERROR: IP {ip} is not in local range. LAB_USE=1 restricts to local IPs only."
    
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "ERROR: Command timed out after 30 seconds"
    except Exception as e:
        return 1, "", f"ERROR: {str(e)}"


def execute_powershell(script: str, check_lab: bool = True, lab_use: int = 0) -> Tuple[int, str, str]:
    """Execute PowerShell script"""
    command = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{script}"'
    return execute_command(command, shell=True, check_lab=check_lab, lab_use=lab_use)


def execute_cmd(command: str, check_lab: bool = True, lab_use: int = 0) -> Tuple[int, str, str]:
    """Execute CMD command"""
    return execute_command(command, shell=True, check_lab=check_lab, lab_use=lab_use)


def _get_key() -> str:
    """Get a single keypress (cross-platform)"""
    if sys.platform == 'win32':
        import msvcrt
        key = msvcrt.getch()
        if key == b'\xe0':  # Extended key
            key2 = msvcrt.getch()
            if key2 == b'H':
                return 'UP'
            elif key2 == b'P':
                return 'DOWN'
        elif key == b'\r':
            return 'ENTER'
        elif key == b'\x1b':
            return 'ESC'
        else:
            try:
                return key.decode('utf-8')
            except:
                return ''
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            key = sys.stdin.read(1)
            if key == '\x1b':  # ESC sequence
                key2 = sys.stdin.read(1)
                if key2 == '[':
                    key3 = sys.stdin.read(1)
                    if key3 == 'A':
                        return 'UP'
                    elif key3 == 'B':
                        return 'DOWN'
            elif key == '\r' or key == '\n':
                return 'ENTER'
            elif key == '\x1b':
                return 'ESC'
            else:
                return key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def select_menu_option(
    console: Console,
    options: List[Dict[str, str]],
    prompt: str = "Select option",
    default: str = "0"
) -> str:
    """
    Interactive menu selector with arrow key navigation and number input
    
    Args:
        console: Rich console instance
        options: List of dicts with 'key' and 'label'
        prompt: Prompt text to display
        default: Default selection key
    
    Returns:
        Selected option key
    """
    # Find default index
    default_idx = 0
    for i, opt in enumerate(options):
        if opt['key'] == default:
            default_idx = i
            break
    
    current_idx = default_idx
    
    # Render menu function
    def render_menu():
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Option", style="cyan", width=3)
        table.add_column("Function", style="white")
        
        for i, opt in enumerate(options):
            if i == current_idx:
                # Highlight current selection
                table.add_row(
                    f"[bold cyan on yellow]{opt['key']}[/bold cyan on yellow]",
                    f"[bold on yellow]{opt['label']}[/bold on yellow]"
                )
            else:
                table.add_row(opt['key'], opt['label'])
        
        return table
    
    # Try arrow key navigation
    try:
        # Display initial menu
        menu_table = render_menu()
        help_text = f"[dim]{prompt} (↑↓ arrows to navigate, Enter to select, or type number)[/dim]"
        console.print(menu_table)
        console.print(help_text)
        
        # Handle input
        while True:
            try:
                key = _get_key()
                
                if key == 'UP':
                    current_idx = max(0, current_idx - 1)
                    console.clear()
                    menu_table = render_menu()
                    console.print(menu_table)
                    console.print(help_text)
                elif key == 'DOWN':
                    current_idx = min(len(options) - 1, current_idx + 1)
                    console.clear()
                    menu_table = render_menu()
                    console.print(menu_table)
                    console.print(help_text)
                elif key == 'ENTER':
                    return options[current_idx]['key']
                elif key == 'ESC':
                    return default
                elif key and key.isdigit():
                    # Direct number selection
                    for opt in options:
                        if opt['key'] == key:
                            return opt['key']
                elif key and key in [opt['key'] for opt in options]:
                    # Direct key selection (for '?' etc)
                    return key
            except (KeyboardInterrupt, EOFError):
                return default
            except Exception:
                # If arrow keys fail, fall through to Prompt
                break
    except Exception:
        pass
    
    # Fallback: Use Rich's Prompt with enhanced display
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Option", style="cyan", width=3)
    table.add_column("Function", style="white")
    
    for i, opt in enumerate(options):
        if i == current_idx:
            table.add_row(
                f"[bold cyan]{opt['key']}[/bold cyan]",
                f"[bold]{opt['label']}[/bold]"
            )
        else:
            table.add_row(opt['key'], opt['label'])
    
    console.print(table)
    console.print(f"\n[dim]{prompt} (Type number or option key)[/dim]")
    
    from rich.prompt import Prompt
    choices = [opt['key'] for opt in options]
    return Prompt.ask(prompt, choices=choices, default=default)
