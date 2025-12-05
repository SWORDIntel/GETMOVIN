"""Utility functions for modules

All execution functions support both local and remote SSH execution.
When used over SSH, commands execute on the remote system.

IMPORTANT: This toolkit is designed to be controlled entirely over SSH.
- Rich TUI works perfectly over SSH terminals
- All interactive features work over SSH
- Commands execute on the system where Python runs (local or remote)
- When accessed over SSH, the tool runs on the remote system
"""

import subprocess
import ipaddress
import re
import os
from typing import Optional, Tuple, List, Dict, Any
from rich.prompt import Prompt
from modules.ssh_session import get_ssh_manager


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


def _execute_ssh_command(command: str, host: str, user: Optional[str] = None, 
                         key_file: Optional[str] = None, password: Optional[str] = None) -> Tuple[int, str, str]:
    """
    Execute command over SSH
    
    Args:
        command: Command to execute
        host: SSH host
        user: SSH username
        key_file: SSH private key file path
        password: SSH password
    
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    try:
        # Build SSH command
        ssh_cmd_parts = ["ssh"]
        
        # Add SSH options for non-interactive execution
        ssh_cmd_parts.extend(["-o", "StrictHostKeyChecking=no"])
        ssh_cmd_parts.extend(["-o", "UserKnownHostsFile=/dev/null"])
        ssh_cmd_parts.extend(["-o", "ConnectTimeout=10"])
        ssh_cmd_parts.extend(["-o", "BatchMode=yes"])  # Non-interactive
        
        # Add key file if provided
        if key_file and os.path.exists(key_file):
            ssh_cmd_parts.extend(["-i", key_file])
            ssh_cmd_parts.extend(["-o", "PasswordAuthentication=no"])
        
        # Add port if needed (default 22)
        port = 22  # Could be extracted from session if needed
        
        # Add user@host
        if user:
            ssh_target = f"{user}@{host}"
        else:
            ssh_target = host
        
        ssh_cmd_parts.append(ssh_target)
        
        # Escape command for SSH
        # For Windows commands, wrap appropriately
        if command.startswith('powershell') or command.startswith('cmd'):
            # Windows command - wrap in quotes
            escaped_cmd = command.replace('"', '\\"')
            ssh_cmd_parts.append(f'"{escaped_cmd}"')
        else:
            # Unix command
            escaped_cmd = command.replace('"', '\\"').replace('$', '\\$')
            ssh_cmd_parts.append(f'"{escaped_cmd}"')
        
        ssh_cmd = " ".join(ssh_cmd_parts)
        
        # Execute SSH command
        # Note: For password auth, use sshpass or expect (not implemented here for security)
        # Prefer key-based authentication
        env = os.environ.copy()
        if password:
            # Use sshpass if available, otherwise prompt
            env['SSHPASS'] = password
            ssh_cmd = f'sshpass -e {ssh_cmd}'
        
        result = subprocess.run(
            ssh_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        
        return result.returncode, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return 1, "", "ERROR: SSH command timed out after 30 seconds"
    except FileNotFoundError:
        return 1, "", "ERROR: SSH client not found. Install OpenSSH client."
    except Exception as e:
        return 1, "", f"ERROR: SSH execution failed: {str(e)}"


def execute_command(command: str, shell: bool = True, check_lab: bool = True, lab_use: int = 0, 
                   ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                   ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                   use_active_ssh: bool = True) -> Tuple[int, str, str]:
    """
    Execute a command locally or remotely over SSH
    
    Args:
        command: Command to execute
        shell: Use shell execution
        check_lab: Check LAB_USE restrictions
        lab_use: LAB_USE flag value
        ssh_host: SSH host to execute command on (None for local)
        ssh_user: SSH username
        ssh_key: SSH private key path
        ssh_password: SSH password (if no key)
        use_active_ssh: Use active SSH session if available
    
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    if check_lab and lab_use == 1:
        # Extract IP addresses from command
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, command)
        for ip in ips:
            if not is_local_ip(ip):
                return 1, "", f"ERROR: IP {ip} is not in local range. LAB_USE=1 restricts to local IPs only."
    
    # Check for active SSH session if use_active_ssh is True
    if use_active_ssh and not ssh_host:
        try:
            ssh_manager = get_ssh_manager()
            active_session = ssh_manager.get_active_session()
            if active_session:
                ssh_host = active_session.host
                ssh_user = active_session.user
                ssh_key = active_session.key_file
                ssh_password = active_session.password
        except Exception:
            # SSH manager not available, continue with local execution
            pass
    
    # If SSH host specified, execute remotely
    if ssh_host:
        return _execute_ssh_command(command, ssh_host, ssh_user, ssh_key, ssh_password)
    
    # Local execution
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


def execute_powershell(script: str, check_lab: bool = True, lab_use: int = 0,
                      ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
                      ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                      use_active_ssh: bool = True) -> Tuple[int, str, str]:
    """
    Execute PowerShell script locally or remotely over SSH
    
    Args:
        script: PowerShell script to execute
        check_lab: Check LAB_USE restrictions
        lab_use: LAB_USE flag value
        ssh_host: SSH host to execute on (None for local)
        ssh_user: SSH username
        ssh_key: SSH private key path
        ssh_password: SSH password
        use_active_ssh: Use active SSH session if available
    """
    # Escape PowerShell script for command line
    escaped_script = script.replace('"', '`"').replace('$', '`$')
    command = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{escaped_script}"'
    return execute_command(command, shell=True, check_lab=check_lab, lab_use=lab_use,
                          ssh_host=ssh_host, ssh_user=ssh_user, ssh_key=ssh_key, ssh_password=ssh_password,
                          use_active_ssh=use_active_ssh)


def execute_cmd(command: str, check_lab: bool = True, lab_use: int = 0,
               ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
               ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
               use_active_ssh: bool = True) -> Tuple[int, str, str]:
    """
    Execute CMD command locally or remotely over SSH
    
    Args:
        command: CMD command to execute
        check_lab: Check LAB_USE restrictions
        lab_use: LAB_USE flag value
        ssh_host: SSH host to execute on (None for local)
        ssh_user: SSH username
        ssh_key: SSH private key path
        ssh_password: SSH password
        use_active_ssh: Use active SSH session if available
    """
    return execute_command(command, shell=True, check_lab=check_lab, lab_use=lab_use,
                          ssh_host=ssh_host, ssh_user=ssh_user, ssh_key=ssh_key, ssh_password=ssh_password,
                          use_active_ssh=use_active_ssh)


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
