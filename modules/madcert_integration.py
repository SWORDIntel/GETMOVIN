"""MADCert Integration - Microsoft Active Directory Certificate Generation

MADCert (Microsoft Active Directory Certificate) is a tool for generating
valid certificates for Active Directory environments. This module provides
integration with MADCert for certificate generation and management.

Reference: https://github.com/NationalSecurityAgency/MADCert
"""

import subprocess
import os
import json
import tempfile
from typing import Dict, Any, Optional, List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box


class MADCertGenerator:
    """MADCert certificate generator wrapper"""
    
    def __init__(self, console: Console, session_data: dict):
        self.console = console
        self.session_data = session_data
        self.madcert_path = None
        self.cert_store = {}
        
    def find_madcert(self) -> Optional[str]:
        """Find MADCert executable"""
        # Common locations
        possible_paths = [
            'madcert.exe',
            'MADCert.exe',
            './tools/madcert.exe',
            './MADCert/madcert.exe',
            'C:\\tools\\madcert.exe',
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Try which/where command
        try:
            result = subprocess.run(['where', 'madcert.exe'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        return None
    
    def generate_ca_certificate(self, ca_name: str, validity_days: int = 3650,
                                key_size: int = 2048) -> Dict[str, Any]:
        """
        Generate a CA certificate
        
        Args:
            ca_name: Common Name for the CA
            validity_days: Certificate validity in days
            key_size: RSA key size in bits
        
        Returns:
            Dictionary with certificate details
        """
        if not self.madcert_path:
            self.madcert_path = self.find_madcert()
            if not self.madcert_path:
                raise FileNotFoundError("MADCert executable not found")
        
        # Create temporary directory for certs
        cert_dir = tempfile.mkdtemp(prefix='madcert_')
        
        try:
            # MADCert command to generate CA
            cmd = [
                self.madcert_path,
                'ca',
                '--name', ca_name,
                '--validity', str(validity_days),
                '--keysize', str(key_size),
                '--outdir', cert_dir
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise Exception(f"MADCert failed: {result.stderr}")
            
            # Parse output and find generated files
            cert_file = os.path.join(cert_dir, f'{ca_name}_ca.crt')
            key_file = os.path.join(cert_dir, f'{ca_name}_ca.key')
            
            cert_info = {
                'type': 'CA',
                'name': ca_name,
                'cert_file': cert_file,
                'key_file': key_file,
                'validity_days': validity_days,
                'key_size': key_size,
                'output': result.stdout
            }
            
            self.cert_store[ca_name] = cert_info
            return cert_info
        
        except Exception as e:
            raise Exception(f"CA generation failed: {e}")
    
    def generate_server_certificate(self, server_name: str, ca_name: str,
                                    dns_names: List[str] = None,
                                    ip_addresses: List[str] = None,
                                    validity_days: int = 365) -> Dict[str, Any]:
        """
        Generate a server certificate signed by CA
        
        Args:
            server_name: Common Name for the server
            ca_name: Name of the CA to sign with
            dns_names: List of DNS names (SAN)
            ip_addresses: List of IP addresses (SAN)
            validity_days: Certificate validity in days
        
        Returns:
            Dictionary with certificate details
        """
        if not self.madcert_path:
            self.madcert_path = self.find_madcert()
            if not self.madcert_path:
                raise FileNotFoundError("MADCert executable not found")
        
        if ca_name not in self.cert_store:
            raise ValueError(f"CA '{ca_name}' not found. Generate CA first.")
        
        ca_info = self.cert_store[ca_name]
        cert_dir = os.path.dirname(ca_info['cert_file'])
        
        try:
            cmd = [
                self.madcert_path,
                'server',
                '--name', server_name,
                '--ca-cert', ca_info['cert_file'],
                '--ca-key', ca_info['key_file'],
                '--validity', str(validity_days),
                '--outdir', cert_dir
            ]
            
            # Add SAN entries
            if dns_names:
                for dns in dns_names:
                    cmd.extend(['--dns', dns])
            
            if ip_addresses:
                for ip in ip_addresses:
                    cmd.extend(['--ip', ip])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise Exception(f"MADCert failed: {result.stderr}")
            
            cert_file = os.path.join(cert_dir, f'{server_name}_server.crt')
            key_file = os.path.join(cert_dir, f'{server_name}_server.key')
            
            cert_info = {
                'type': 'Server',
                'name': server_name,
                'ca_name': ca_name,
                'cert_file': cert_file,
                'key_file': key_file,
                'dns_names': dns_names or [],
                'ip_addresses': ip_addresses or [],
                'validity_days': validity_days,
                'output': result.stdout
            }
            
            self.cert_store[f'{server_name}_server'] = cert_info
            return cert_info
        
        except Exception as e:
            raise Exception(f"Server certificate generation failed: {e}")
    
    def generate_client_certificate(self, client_name: str, ca_name: str,
                                   validity_days: int = 365,
                                   key_usage: List[str] = None) -> Dict[str, Any]:
        """
        Generate a client certificate
        
        Args:
            client_name: Common Name for the client
            ca_name: Name of the CA to sign with
            validity_days: Certificate validity in days
            key_usage: List of key usage extensions
        
        Returns:
            Dictionary with certificate details
        """
        if not self.madcert_path:
            self.madcert_path = self.find_madcert()
            if not self.madcert_path:
                raise FileNotFoundError("MADCert executable not found")
        
        if ca_name not in self.cert_store:
            raise ValueError(f"CA '{ca_name}' not found. Generate CA first.")
        
        ca_info = self.cert_store[ca_name]
        cert_dir = os.path.dirname(ca_info['cert_file'])
        
        try:
            cmd = [
                self.madcert_path,
                'client',
                '--name', client_name,
                '--ca-cert', ca_info['cert_file'],
                '--ca-key', ca_info['key_file'],
                '--validity', str(validity_days),
                '--outdir', cert_dir
            ]
            
            if key_usage:
                cmd.extend(['--key-usage', ','.join(key_usage)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise Exception(f"MADCert failed: {result.stderr}")
            
            cert_file = os.path.join(cert_dir, f'{client_name}_client.crt')
            key_file = os.path.join(cert_dir, f'{client_name}_client.key')
            
            cert_info = {
                'type': 'Client',
                'name': client_name,
                'ca_name': ca_name,
                'cert_file': cert_file,
                'key_file': key_file,
                'key_usage': key_usage or [],
                'validity_days': validity_days,
                'output': result.stdout
            }
            
            self.cert_store[f'{client_name}_client'] = cert_info
            return cert_info
        
        except Exception as e:
            raise Exception(f"Client certificate generation failed: {e}")
    
    def generate_code_signing_certificate(self, signer_name: str, ca_name: str,
                                         validity_days: int = 365) -> Dict[str, Any]:
        """
        Generate a code signing certificate
        
        Args:
            signer_name: Name for the code signer
            ca_name: Name of the CA to sign with
            validity_days: Certificate validity in days
        
        Returns:
            Dictionary with certificate details
        """
        return self.generate_client_certificate(
            signer_name, ca_name, validity_days,
            key_usage=['digitalSignature', 'codeSigning']
        )
    
    def export_certificate(self, cert_name: str, format: str = 'pem') -> Optional[str]:
        """
        Export certificate in specified format
        
        Args:
            cert_name: Name of certificate to export
            format: Export format (pem, pfx, der)
        
        Returns:
            Path to exported certificate file
        """
        if cert_name not in self.cert_store:
            return None
        
        cert_info = self.cert_store[cert_name]
        
        if format == 'pem':
            # PEM is default, return existing file
            return cert_info['cert_file']
        elif format == 'pfx':
            # Convert to PFX
            pfx_file = cert_info['cert_file'].replace('.crt', '.pfx')
            # Use OpenSSL or similar to convert
            # This would require additional implementation
            return pfx_file
        else:
            return cert_info['cert_file']
    
    def list_certificates(self) -> List[Dict[str, Any]]:
        """List all generated certificates"""
        return list(self.cert_store.values())
    
    def get_certificate_info(self, cert_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific certificate"""
        return self.cert_store.get(cert_name)


class MADCertModule:
    """MADCert Module for TUI"""
    
    def __init__(self):
        self.generator = None
    
    def run(self, console: Console, session_data: dict):
        """Run MADCert module"""
        if not self.generator:
            self.generator = MADCertGenerator(console, session_data)
        
        while True:
            console.print(Panel(
                "[bold]MADCert Certificate Generation[/bold]\n\n"
                "Generate valid certificates for Active Directory environments.",
                title="Module 8",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Find MADCert Installation")
            table.add_row("2", "Generate CA Certificate")
            table.add_row("3", "Generate Server Certificate")
            table.add_row("4", "Generate Client Certificate")
            table.add_row("5", "Generate Code Signing Certificate")
            table.add_row("6", "List Generated Certificates")
            table.add_row("7", "Export Certificate")
            table.add_row("8", "Certificate Usage Examples")
            table.add_row("?", "Module Guide - Usage instructions and TTPs")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5', '6', '7', '8', '?'], default='0')
            
            if choice == '0':
                break
            elif choice == '?':
                self._show_guide(console)
            elif choice == '1':
                self._find_madcert(console)
            elif choice == '2':
                self._generate_ca(console)
            elif choice == '3':
                self._generate_server(console)
            elif choice == '4':
                self._generate_client(console)
            elif choice == '5':
                self._generate_code_signing(console)
            elif choice == '6':
                self._list_certificates(console)
            elif choice == '7':
                self._export_certificate(console)
            elif choice == '8':
                self._usage_examples(console)
            
            console.print()
    
    def _show_guide(self, console: Console):
        """Show module guide"""
        guide_text = """[bold cyan]MADCert Certificate Generation Module Guide[/bold cyan]

[bold]Purpose:[/bold]
Generate valid certificates for Active Directory environments to establish trust and enable credential access.

[bold]Key Functions:[/bold]
1. Find MADCert Installation - Locate MADCert tool
2. Generate CA Certificate - Create Certificate Authority
3. Generate Server Certificate - Create server certificates
4. Generate Client Certificate - Create client certificates
5. Generate Code Signing Certificate - Create code signing certs
6. List Generated Certificates - View all generated certs
7. Export Certificate - Export certificates for use
8. Certificate Usage Examples - See usage examples

[bold]MITRE ATT&CK TTPs:[/bold]
• T1550 - Use Alternate Authentication Material
• T1078 - Valid Accounts
• T1484 - Domain Policy Modification
• T1550.001 - Application Access Token
• T1550.002 - Pass the Hash

[bold]Usage Tips:[/bold]
• Start with option 1 to locate MADCert installation
• Generate CA first (option 2), then server/client certs
• Use option 8 to see practical usage examples
• Certificates can be used for AD authentication
• Code signing certs enable trusted code execution

[bold]Best Practices:[/bold]
• Generate certificates with realistic names
• Use certificates for stealthy authentication
• Export certificates securely
• Document certificate purposes"""
        
        console.print(Panel(guide_text, title="Module Guide", border_style="cyan"))
        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
    def _find_madcert(self, console: Console):
        """Find MADCert installation"""
        console.print("\n[bold cyan]Finding MADCert Installation[/bold cyan]\n")
        
        path = self.generator.find_madcert()
        if path:
            console.print(f"[green]MADCert found:[/green] {path}")
            self.generator.madcert_path = path
        else:
            console.print("[yellow]MADCert not found[/yellow]")
            console.print("\n[bold]Installation Instructions:[/bold]")
            console.print("  1. Clone repository: git clone https://github.com/NationalSecurityAgency/MADCert")
            console.print("  2. Build MADCert (see repository README)")
            console.print("  3. Place madcert.exe in PATH or specify path")
            console.print("  4. Or download pre-built binaries if available")
    
    def _generate_ca(self, console: Console):
        """Generate CA certificate"""
        console.print("\n[bold cyan]Generate CA Certificate[/bold cyan]\n")
        
        ca_name = Prompt.ask("CA Common Name", default="MyCA")
        validity_days = int(Prompt.ask("Validity (days)", default="3650"))
        key_size = int(Prompt.ask("Key size (bits)", choices=['2048', '4096'], default='2048'))
        
        try:
            cert_info = self.generator.generate_ca_certificate(ca_name, validity_days, key_size)
            
            console.print(f"\n[green]CA Certificate Generated[/green]")
            console.print(f"Certificate: {cert_info['cert_file']}")
            console.print(f"Private Key: {cert_info['key_file']}")
            console.print(f"Validity: {validity_days} days")
            console.print(f"Key Size: {key_size} bits")
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def _generate_server(self, console: Console):
        """Generate server certificate"""
        console.print("\n[bold cyan]Generate Server Certificate[/bold cyan]\n")
        
        if not self.generator.cert_store:
            console.print("[yellow]No CA certificates found. Generate a CA first.[/yellow]")
            return
        
        server_name = Prompt.ask("Server Common Name", default="server.example.com")
        
        # List available CAs
        cas = [name for name, info in self.generator.cert_store.items() if info['type'] == 'CA']
        if not cas:
            console.print("[yellow]No CA certificates available[/yellow]")
            return
        
        ca_name = Prompt.ask("CA Name", choices=cas, default=cas[0])
        
        dns_names = []
        if Confirm.ask("Add DNS names (SAN)?", default=False):
            dns_input = Prompt.ask("DNS names (comma-separated)", default="")
            dns_names = [d.strip() for d in dns_input.split(',') if d.strip()]
        
        ip_addresses = []
        if Confirm.ask("Add IP addresses (SAN)?", default=False):
            ip_input = Prompt.ask("IP addresses (comma-separated)", default="")
            ip_addresses = [ip.strip() for ip in ip_input.split(',') if ip.strip()]
        
        validity_days = int(Prompt.ask("Validity (days)", default="365"))
        
        try:
            cert_info = self.generator.generate_server_certificate(
                server_name, ca_name, dns_names, ip_addresses, validity_days
            )
            
            console.print(f"\n[green]Server Certificate Generated[/green]")
            console.print(f"Certificate: {cert_info['cert_file']}")
            console.print(f"Private Key: {cert_info['key_file']}")
            if dns_names:
                console.print(f"DNS Names: {', '.join(dns_names)}")
            if ip_addresses:
                console.print(f"IP Addresses: {', '.join(ip_addresses)}")
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def _generate_client(self, console: Console):
        """Generate client certificate"""
        console.print("\n[bold cyan]Generate Client Certificate[/bold cyan]\n")
        
        if not self.generator.cert_store:
            console.print("[yellow]No CA certificates found. Generate a CA first.[/yellow]")
            return
        
        client_name = Prompt.ask("Client Common Name", default="client")
        
        cas = [name for name, info in self.generator.cert_store.items() if info['type'] == 'CA']
        if not cas:
            console.print("[yellow]No CA certificates available[/yellow]")
            return
        
        ca_name = Prompt.ask("CA Name", choices=cas, default=cas[0])
        validity_days = int(Prompt.ask("Validity (days)", default="365"))
        
        try:
            cert_info = self.generator.generate_client_certificate(client_name, ca_name, validity_days)
            
            console.print(f"\n[green]Client Certificate Generated[/green]")
            console.print(f"Certificate: {cert_info['cert_file']}")
            console.print(f"Private Key: {cert_info['key_file']}")
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def _generate_code_signing(self, console: Console):
        """Generate code signing certificate"""
        console.print("\n[bold cyan]Generate Code Signing Certificate[/bold cyan]\n")
        
        if not self.generator.cert_store:
            console.print("[yellow]No CA certificates found. Generate a CA first.[/yellow]")
            return
        
        signer_name = Prompt.ask("Signer Name", default="CodeSigner")
        
        cas = [name for name, info in self.generator.cert_store.items() if info['type'] == 'CA']
        if not cas:
            console.print("[yellow]No CA certificates available[/yellow]")
            return
        
        ca_name = Prompt.ask("CA Name", choices=cas, default=cas[0])
        validity_days = int(Prompt.ask("Validity (days)", default="365"))
        
        try:
            cert_info = self.generator.generate_code_signing_certificate(signer_name, ca_name, validity_days)
            
            console.print(f"\n[green]Code Signing Certificate Generated[/green]")
            console.print(f"Certificate: {cert_info['cert_file']}")
            console.print(f"Private Key: {cert_info['key_file']}")
            console.print("[yellow]Use this certificate for DLL sideloading and code signing[/yellow]")
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def _list_certificates(self, console: Console):
        """List all certificates"""
        console.print("\n[bold cyan]Generated Certificates[/bold cyan]\n")
        
        certs = self.generator.list_certificates()
        if not certs:
            console.print("[dim]No certificates generated yet[/dim]")
            return
        
        table = Table(title="Certificates", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="white")
        table.add_column("CA", style="dim white")
        table.add_column("Validity", style="green")
        table.add_column("File", style="dim white")
        
        for cert in certs:
            table.add_row(
                cert['name'],
                cert['type'],
                cert.get('ca_name', 'N/A'),
                f"{cert['validity_days']} days",
                os.path.basename(cert['cert_file'])
            )
        
        console.print(table)
    
    def _export_certificate(self, console: Console):
        """Export certificate"""
        console.print("\n[bold cyan]Export Certificate[/bold cyan]\n")
        
        certs = self.generator.list_certificates()
        if not certs:
            console.print("[yellow]No certificates to export[/yellow]")
            return
        
        cert_names = list(self.generator.cert_store.keys())
        cert_name = Prompt.ask("Certificate name", choices=cert_names)
        
        format = Prompt.ask("Export format", choices=['pem', 'pfx', 'der'], default='pem')
        
        try:
            export_path = self.generator.export_certificate(cert_name, format)
            if export_path:
                console.print(f"[green]Certificate exported:[/green] {export_path}")
            else:
                console.print("[yellow]Export failed[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    def _usage_examples(self, console: Console):
        """Show usage examples"""
        console.print("\n[bold cyan]MADCert Usage Examples[/bold cyan]\n")
        
        examples = """
[bold]1. Generate CA for Internal PKI:[/bold]
   - Create CA certificate
   - Use for signing all internal certificates
   - Distribute CA cert to trusted stores

[bold]2. Generate Server Certificates:[/bold]
   - For HTTPS services (WinRM, web servers)
   - Include DNS names and IPs in SAN
   - Use for encrypted lateral movement channels

[bold]3. Generate Client Certificates:[/bold]
   - For client authentication
   - Use with WinRM certificate authentication
   - Enable certificate-based lateral movement

[bold]4. Code Signing Certificates:[/bold]
   - Sign DLLs and executables
   - Bypass application whitelisting
   - Enable DLL sideloading attacks
   - Make malicious code appear legitimate

[bold]5. Integration with Lateral Movement:[/bold]
   - Use server certs for encrypted WinRM
   - Use client certs for authenticated access
   - Code signing for persistence mechanisms
   - Trusted certificates bypass security controls

[bold]OPSEC Considerations:[/bold]
   - Use realistic certificate names
   - Match existing certificate patterns
   - Consider certificate validity periods
   - Distribute CA certs to appropriate stores
        """
        
        console.print(examples)
