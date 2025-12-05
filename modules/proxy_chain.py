"""Multi-Hop Proxy Chain Support

Provides multi-hop proxy chain capabilities for lateral movement:
- SOCKS5 proxy chains
- SSH tunnel chains
- HTTP proxy chains
- Mixed protocol chains
- Dynamic chain routing
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import socket
import subprocess
import threading
import time


class ProxyType(Enum):
    """Proxy types"""
    SOCKS5 = "socks5"
    SOCKS4 = "socks4"
    HTTP = "http"
    HTTPS = "https"
    SSH_TUNNEL = "ssh"
    RDP_TUNNEL = "rdp"


@dataclass
class ProxyHop:
    """Single proxy hop in chain"""
    host: str
    port: int
    proxy_type: ProxyType
    username: Optional[str] = None
    password: Optional[str] = None
    key_file: Optional[str] = None
    timeout: int = 30
    
    def __str__(self):
        auth = f"{self.username}@" if self.username else ""
        return f"{self.proxy_type.value}://{auth}{self.host}:{self.port}"


class ProxyChain:
    """Multi-hop proxy chain"""
    
    def __init__(self, hops: List[ProxyHop]):
        self.hops = hops
        self.active_tunnels = []
        self.local_ports = []
    
    def __len__(self):
        return len(self.hops)
    
    def __str__(self):
        return " -> ".join(str(hop) for hop in self.hops)
    
    def add_hop(self, hop: ProxyHop):
        """Add a hop to the chain"""
        self.hops.append(hop)
    
    def establish_chain(self) -> bool:
        """Establish the proxy chain"""
        try:
            # For SSH tunnels, establish sequentially
            for i, hop in enumerate(self.hops):
                if hop.proxy_type == ProxyType.SSH_TUNNEL:
                    local_port = self._establish_ssh_tunnel(hop, i)
                    if local_port:
                        self.local_ports.append(local_port)
                    else:
                        return False
                elif hop.proxy_type in [ProxyType.SOCKS5, ProxyType.SOCKS4, ProxyType.HTTP]:
                    # SOCKS/HTTP proxies are handled by client libraries
                    pass
            
            return True
        except Exception:
            return False
    
    def _establish_ssh_tunnel(self, hop: ProxyHop, hop_index: int) -> Optional[int]:
        """Establish SSH tunnel for a hop"""
        try:
            # Use previous hop's local port if available
            if hop_index > 0 and self.local_ports:
                proxy_cmd = f"-o ProxyCommand='nc -X 5 -x localhost:{self.local_ports[-1]} %h %p'"
            else:
                proxy_cmd = ""
            
            # Find available local port
            local_port = self._find_free_port()
            
            # Build SSH command
            auth = ""
            if hop.key_file:
                auth = f"-i {hop.key_file}"
            elif hop.username and hop.password:
                # Note: Password auth via command line is insecure, use key files
                auth = f"-o PreferredAuthentications=password"
            
            ssh_cmd = (
                f"ssh -N -L {local_port}:localhost:{hop.port} "
                f"{auth} {proxy_cmd} {hop.username or 'root'}@{hop.host}"
            )
            
            # Start SSH tunnel in background
            process = subprocess.Popen(
                ssh_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.active_tunnels.append(process)
            
            # Wait a moment for tunnel to establish
            time.sleep(2)
            
            # Check if process is still running
            if process.poll() is None:
                return local_port
            else:
                return None
                
        except Exception:
            return None
    
    def _find_free_port(self) -> int:
        """Find a free local port"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def get_proxy_string(self) -> str:
        """Get proxy string for use with tools"""
        if not self.hops:
            return ""
        
        # Return first SOCKS/HTTP proxy
        for hop in self.hops:
            if hop.proxy_type in [ProxyType.SOCKS5, ProxyType.SOCKS4, ProxyType.HTTP]:
                auth = f"{hop.username}:{hop.password}@" if hop.username and hop.password else ""
                return f"{hop.proxy_type.value}://{auth}{hop.host}:{hop.port}"
        
        # If only SSH tunnels, return last local port
        if self.local_ports:
            return f"socks5://localhost:{self.local_ports[-1]}"
        
        return ""
    
    def cleanup(self):
        """Clean up all tunnels"""
        for process in self.active_tunnels:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        
        self.active_tunnels.clear()
        self.local_ports.clear()


class ProxyChainManager:
    """Manage multiple proxy chains"""
    
    def __init__(self):
        self.chains: Dict[str, ProxyChain] = {}
        self.active_chain: Optional[str] = None
    
    def create_chain(self, name: str, hops: List[ProxyHop]) -> ProxyChain:
        """Create a new proxy chain"""
        chain = ProxyChain(hops)
        self.chains[name] = chain
        return chain
    
    def activate_chain(self, name: str) -> bool:
        """Activate a proxy chain"""
        if name not in self.chains:
            return False
        
        # Cleanup previous chain
        if self.active_chain and self.active_chain != name:
            self.chains[self.active_chain].cleanup()
        
        # Establish new chain
        chain = self.chains[name]
        if chain.establish_chain():
            self.active_chain = name
            return True
        
        return False
    
    def get_active_proxy(self) -> Optional[str]:
        """Get proxy string for active chain"""
        if self.active_chain:
            return self.chains[self.active_chain].get_proxy_string()
        return None
    
    def cleanup_all(self):
        """Cleanup all chains"""
        for chain in self.chains.values():
            chain.cleanup()
        self.active_chain = None


# Global proxy chain manager
_proxy_manager: Optional[ProxyChainManager] = None


def get_proxy_manager() -> ProxyChainManager:
    """Get global proxy chain manager"""
    global _proxy_manager
    if _proxy_manager is None:
        _proxy_manager = ProxyChainManager()
    return _proxy_manager
