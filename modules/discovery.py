"""
Component Discovery Module

Automatically discovers and reports availability of all components:
- PE5 framework
- Relay service
- Optional dependencies
- External tools
- Configuration files

Also handles preloading/installing requirements.
"""

import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
import importlib.util


class ComponentDiscovery:
    """Discover and report component availability"""
    
    def __init__(self, auto_preload: bool = False):
        self.discovered_components = {}
        self.auto_preload = auto_preload
        self.discover_all()
        if auto_preload:
            self.preload_requirements()
    
    def discover_all(self):
        """Discover all components"""
        self.discover_pe5_framework()
        self.discover_relay_service()
        self.discover_optional_dependencies()
        self.discover_configuration_files()
        self.discover_external_tools()
    
    def discover_pe5_framework(self) -> Dict[str, any]:
        """Discover PE5 framework availability"""
        pe5_info = {
            'available': False,
            'path': None,
            'compiled': False,
            'binaries': [],
            'source_files': []
        }
        
        # Check for PE5 framework
        pe5_paths = [
            Path('pe5_framework_extracted/pe5_framework'),
            Path('../pe5_framework_extracted/pe5_framework'),
            Path('pe5_framework'),
        ]
        
        for pe5_path in pe5_paths:
            if pe5_path.exists() and pe5_path.is_dir():
                pe5_info['available'] = True
                pe5_info['path'] = str(pe5_path.resolve())
                
                # Check for source files
                src_files = list(pe5_path.rglob('*.c')) + list(pe5_path.rglob('*.h'))
                pe5_info['source_files'] = [str(f.name) for f in src_files[:10]]
                
                # Check for compiled binaries
                build_bin = pe5_path / 'build' / 'bin'
                if build_bin.exists():
                    binaries = list(build_bin.glob('pe5_*'))
                    pe5_info['compiled'] = True
                    pe5_info['binaries'] = [str(b.name) for b in binaries]
                
                break
        
        self.discovered_components['pe5_framework'] = pe5_info
        return pe5_info
    
    def discover_relay_service(self) -> Dict[str, any]:
        """Discover relay service availability"""
        relay_info = {
            'available': False,
            'path': None,
            'daemon_available': False,
            'client_available': False,
            'config_available': False
        }
        
        # Check for relay directory
        relay_paths = [
            Path('relay'),
            Path('../relay'),
        ]
        
        for relay_path in relay_paths:
            if relay_path.exists() and relay_path.is_dir():
                relay_info['available'] = True
                relay_info['path'] = str(relay_path.resolve())
                
                # Check for daemon
                daemon_file = relay_path / 'src' / 'relay_daemon.py'
                if daemon_file.exists():
                    relay_info['daemon_available'] = True
                
                # Check for client (in modules)
                client_file = Path('modules/relay_client.py')
                if client_file.exists():
                    relay_info['client_available'] = True
                
                # Check for config template
                config_file = relay_path / 'config' / 'relay.yaml.example'
                if config_file.exists():
                    relay_info['config_available'] = True
                
                break
        
        self.discovered_components['relay_service'] = relay_info
        return relay_info
    
    def discover_optional_dependencies(self) -> Dict[str, bool]:
        """Discover optional Python dependencies"""
        dependencies = {
            'websockets': False,
            'aiohttp': False,
            'yaml': False,
            'cryptography': False,
        }
        
        for dep_name in dependencies.keys():
            try:
                __import__(dep_name)
                dependencies[dep_name] = True
            except ImportError:
                dependencies[dep_name] = False
        
        self.discovered_components['optional_dependencies'] = dependencies
        return dependencies
    
    def discover_configuration_files(self) -> Dict[str, List[str]]:
        """Discover configuration files"""
        configs = {
            'relay_client_configs': [],
            'relay_server_configs': [],
            'remote_guided_configs': []
        }
        
        # Relay client configs
        client_config_paths = [
            Path.home() / '.config' / 'ai-relay' / 'client.yaml',
            Path('/etc/ai-relay/client.yaml'),
            Path('config/remote_guided.yaml'),
        ]
        
        for config_path in client_config_paths:
            if config_path.exists():
                configs['relay_client_configs'].append(str(config_path))
        
        # Relay server configs
        server_config_paths = [
            Path('/etc/ai-relay/relay.yaml'),
            Path('relay/config/relay.yaml.example'),
        ]
        
        for config_path in server_config_paths:
            if config_path.exists():
                configs['relay_server_configs'].append(str(config_path))
        
        self.discovered_components['configuration_files'] = configs
        return configs
    
    def discover_external_tools(self) -> Dict[str, Dict[str, any]]:
        """Discover external tools availability"""
        tools = {
            'tor': {
                'installed': False,
                'running': False,
                'path': None
            },
            'loghunter': {
                'available': False,
                'path': None
            }
        }
        
        # Check for Tor
        try:
            import subprocess
            result = subprocess.run(['where', 'tor'], capture_output=True, timeout=2)
            if result.returncode == 0:
                tools['tor']['installed'] = True
                tools['tor']['path'] = result.stdout.decode().strip()
        except:
            pass
        
        # Check for LogHunter (would need specific detection logic)
        # This is handled by LogHunter module itself
        
        self.discovered_components['external_tools'] = tools
        return tools
    
    def get_summary(self) -> Dict[str, any]:
        """Get summary of all discovered components"""
        return {
            'pe5_framework': self.discovered_components.get('pe5_framework', {}),
            'relay_service': self.discovered_components.get('relay_service', {}),
            'optional_dependencies': self.discovered_components.get('optional_dependencies', {}),
            'configuration_files': self.discovered_components.get('configuration_files', {}),
            'external_tools': self.discovered_components.get('external_tools', {}),
            'all_available': self._check_all_available()
        }
    
    def _check_all_available(self) -> bool:
        """Check if core components are available"""
        pe5 = self.discovered_components.get('pe5_framework', {}).get('available', False)
        relay = self.discovered_components.get('relay_service', {}).get('available', False)
        deps = self.discovered_components.get('optional_dependencies', {})
        
        # Core functionality only needs rich, which is required
        # Optional components enhance functionality but aren't required
        return True  # Core TUI always available
    
    def print_discovery_report(self):
        """Print human-readable discovery report"""
        print("\n" + "=" * 60)
        print("COMPONENT DISCOVERY REPORT")
        print("=" * 60)
        
        # PE5 Framework
        pe5 = self.discovered_components.get('pe5_framework', {})
        print(f"\nPE5 Framework:")
        print(f"  Available: {'✓' if pe5.get('available') else '✗'}")
        if pe5.get('path'):
            print(f"  Path: {pe5['path']}")
            print(f"  Compiled: {'✓' if pe5.get('compiled') else '✗'}")
            if pe5.get('binaries'):
                print(f"  Binaries: {', '.join(pe5['binaries'][:3])}")
        
        # Relay Service
        relay = self.discovered_components.get('relay_service', {})
        print(f"\nRelay Service:")
        print(f"  Available: {'✓' if relay.get('available') else '✗'}")
        if relay.get('path'):
            print(f"  Path: {relay['path']}")
            print(f"  Daemon: {'✓' if relay.get('daemon_available') else '✗'}")
            print(f"  Client: {'✓' if relay.get('client_available') else '✗'}")
        
        # Optional Dependencies
        deps = self.discovered_components.get('optional_dependencies', {})
        print(f"\nOptional Dependencies:")
        for dep_name, available in deps.items():
            print(f"  {dep_name}: {'✓' if available else '✗'}")
        
        # Configuration Files
        configs = self.discovered_components.get('configuration_files', {})
        print(f"\nConfiguration Files:")
        if configs.get('relay_client_configs'):
            print(f"  Relay Client Configs: {len(configs['relay_client_configs'])} found")
        if configs.get('relay_server_configs'):
            print(f"  Relay Server Configs: {len(configs['relay_server_configs'])} found")
        
        print("\n" + "=" * 60 + "\n")
    
    def preload_requirements(self, interactive: bool = False) -> Dict[str, bool]:
        """Preload/install missing optional requirements"""
        results = {}
        missing_deps = []
        
        # Check which dependencies are missing
        deps = self.discovered_components.get('optional_dependencies', {})
        for dep_name, available in deps.items():
            if not available:
                missing_deps.append(dep_name)
        
        if not missing_deps:
            return results
        
        # Map dependency names to pip package names
        pip_packages = {
            'websockets': 'websockets',
            'aiohttp': 'aiohttp',
            'yaml': 'pyyaml',
            'cryptography': 'cryptography',
        }
        
        if interactive:
            print(f"\n[bold yellow]Missing optional dependencies detected:[/bold yellow]")
            for dep in missing_deps:
                print(f"  - {dep}")
            
            try:
                from rich.prompt import Confirm
                if not Confirm.ask("\n[bold]Install missing dependencies?[/bold]", default=True):
                    return results
            except ImportError:
                response = input("\nInstall missing dependencies? [Y/n]: ").strip().lower()
                if response and response != 'y':
                    return results
        
        # Install missing dependencies
        for dep_name in missing_deps:
            pip_package = pip_packages.get(dep_name, dep_name)
            try:
                print(f"[dim]Installing {pip_package}...[/dim]", end='', flush=True)
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--quiet', pip_package],
                    capture_output=True,
                    timeout=60,
                    check=False
                )
                
                if result.returncode == 0:
                    # Verify installation
                    try:
                        __import__(dep_name)
                        results[dep_name] = True
                        print(f" [green]✓[/green]")
                    except ImportError:
                        results[dep_name] = False
                        print(f" [red]✗[/red]")
                else:
                    results[dep_name] = False
                    print(f" [red]✗[/red]")
            except Exception as e:
                results[dep_name] = False
                print(f" [red]✗[/red]")
                logging.debug(f"Failed to install {dep_name}: {e}")
        
        # Re-discover after installation
        if any(results.values()):
            self.discover_optional_dependencies()
        
        return results
    
    def preload_all_requirements(self, requirements_file: Optional[str] = None) -> Dict[str, bool]:
        """Preload all requirements from requirements.txt"""
        if requirements_file is None:
            # Try to find requirements.txt
            req_paths = [
                Path('requirements.txt'),
                Path('../requirements.txt'),
                Path(__file__).parent.parent / 'requirements.txt',
            ]
            
            for req_path in req_paths:
                if req_path.exists():
                    requirements_file = str(req_path)
                    break
        
        if not requirements_file or not Path(requirements_file).exists():
            return {}
        
        results = {}
        
        try:
            # Read requirements.txt
            with open(requirements_file, 'r') as f:
                requirements = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle comments and version specifiers
                        req = line.split('#')[0].strip()
                        if req:
                            requirements.append(req)
            
            if not requirements:
                return results
            
            # Install requirements
            print(f"\n[dim]Preloading requirements from {requirements_file}...[/dim]")
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '--quiet', '--upgrade'] + requirements,
                capture_output=True,
                timeout=300,
                check=False
            )
            
            if result.returncode == 0:
                # Re-discover after installation
                self.discover_optional_dependencies()
                results['all_requirements'] = True
            else:
                results['all_requirements'] = False
                logging.debug(f"Failed to install requirements: {result.stderr.decode()}")
        
        except Exception as e:
            results['all_requirements'] = False
            logging.debug(f"Failed to preload requirements: {e}")
        
        return results


def discover_all_components(auto_preload: bool = False) -> ComponentDiscovery:
    """Convenience function to discover all components"""
    return ComponentDiscovery(auto_preload=auto_preload)
