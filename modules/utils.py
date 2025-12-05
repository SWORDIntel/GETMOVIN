"""Utility functions for modules"""

import subprocess
import ipaddress
import re
from typing import Optional, Tuple, List, Dict, Any
from rich.prompt import Prompt


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


def select_menu_option(console, menu_options: List[Dict[str, Any]], prompt: str, default: str = '0') -> str:
    """
    Display a menu and get user selection
    
    Args:
        console: Rich console instance
        menu_options: List of dicts with 'key' and 'label' keys
        prompt: Prompt text to display
        default: Default option key
    
    Returns:
        Selected option key
    """
    # Extract valid choices from menu options
    choices = [opt['key'] for opt in menu_options]
    
    # Display menu
    console.print()
    for opt in menu_options:
        key = opt['key']
        label = opt['label']
        marker = "[bold]" if key == default else ""
        console.print(f"  {marker}{key}[/bold] - {label}")
    console.print()
    
    # Get user choice
    choice = Prompt.ask(
        prompt,
        choices=choices,
        default=default
    )
    
    return choice
