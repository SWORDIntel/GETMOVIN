"""
Relay Client for Remote-Guided Auto-Coding

Connects to AI Relay service to establish communication with AI controller
when direct connection is not possible (CGNAT, firewall, etc.)

Supports:
- Direct IP:port connections
- FQDN (dynamic DNS)
- Tor (.onion) endpoints
- TLS encryption
- Automatic reconnection with backoff
"""

import asyncio
import json
import logging
import ssl
import time
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

# Check for websockets availability
try:
    import websockets
    from websockets.client import WebSocketClientProtocol
    from websockets.exceptions import ConnectionClosed, ConnectionClosedError
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    websockets = None
    WebSocketClientProtocol = None
    ConnectionClosed = Exception
    ConnectionClosedError = Exception

# Import TLS extensions for command channel
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / 'relay' / 'src'))
    from tls_extensions import TLSCommandExtension, CommandChannel, TLSCommandType
except ImportError:
    TLSCommandExtension = None
    CommandChannel = None
    TLSCommandType = None


class RelayClient:
    """Client for connecting to AI Relay service"""
    
    def __init__(self, relay_host: str, relay_port: int = 8889,
                 use_tls: bool = True, auth_token: Optional[str] = None,
                 use_tor: bool = False, tor_proxy: str = "127.0.0.1:9050"):
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.use_tls = use_tls
        self.auth_token = auth_token
        self.use_tor = use_tor
        self.tor_proxy = tor_proxy
        self.ws: Optional[WebSocketClientProtocol] = None
        self.connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.reconnect_delay = 1.0
        self.max_reconnect_delay = 60.0
        self.use_command_channel = False  # TLS extension command channel
        self.command_sequence = 0  # Sequence number for commands
        
    def _build_ws_url(self) -> str:
        """Build WebSocket URL"""
        scheme = "wss" if self.use_tls else "ws"
        
        # Handle .onion addresses
        if self.relay_host.endswith('.onion'):
            # Tor .onion addresses use plain WebSocket (Tor handles encryption)
            scheme = "ws"
        
        return f"{scheme}://{self.relay_host}:{self.relay_port}"
    
    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Get SSL context for TLS connections with CNSA 2.0 compliance"""
        if not self.use_tls:
            return None
        
        # Skip SSL for .onion addresses (Tor handles encryption)
        if self.relay_host.endswith('.onion'):
            return None
        
        context = ssl.create_default_context()
        
        # CNSA 2.0 Compliant Configuration
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        
        # CNSA 2.0 Cipher Suites
        cnsa_ciphers = (
            'ECDHE-ECDSA-AES256-GCM-SHA384:'
            'ECDHE-RSA-AES256-GCM-SHA384:'
            'DHE-RSA-AES256-GCM-SHA384'
        )
        context.set_ciphers(cnsa_ciphers)
        
        # Security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_SINGLE_DH_USE
        
        # Configure ALPN for TLS extensions (command channel)
        if TLSCommandExtension:
            try:
                context.set_alpn_protocols(
                    TLSCommandExtension.create_alpn_protocols()
                )
            except AttributeError:
                logging.warning("ALPN not supported in this Python version")
        
        # Allow self-signed certificates for testing
        # In production, use proper CA certificates
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        return context
    
    def _get_headers(self) -> Dict[str, str]:
        """Get WebSocket headers including authentication"""
        headers = {}
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        return headers
    
    async def connect(self) -> bool:
        """Connect to relay server"""
        if not WEBSOCKETS_AVAILABLE:
            logging.error("websockets library not available. Install with: pip install websockets")
            return False
        
        url = self._build_ws_url()
        headers = self._get_headers()
        ssl_context = self._get_ssl_context()
        
        # Handle Tor proxy
        if self.use_tor and not self.relay_host.endswith('.onion'):
            # Use SOCKS5 proxy for Tor
            # Note: websockets library doesn't directly support SOCKS5
            # In production, use a SOCKS5 proxy wrapper or different library
            logging.warning("Tor proxy support requires additional setup")
        
        try:
            logging.info(f"Connecting to relay: {url}")
            self.ws = await websockets.connect(
                url,
                extra_headers=headers,
                ssl=ssl_context,
                ping_interval=20,
                ping_timeout=10
            )
            
            # Check if command channel is negotiated via ALPN
            if ssl_context and hasattr(self.ws, 'transport'):
                try:
                    if hasattr(self.ws.transport, '_ssl_protocol'):
                        alpn_protocol = self.ws.transport._ssl_protocol.selected_alpn_protocol()
                        if alpn_protocol == TLSCommandExtension.ALPN_PROTOCOL_COMMAND.decode('utf-8'):
                            self.use_command_channel = True
                            logging.info("Using TLS command channel (ALPN)")
                except:
                    pass
            
            self.connected = True
            self.reconnect_attempts = 0
            self.reconnect_delay = 1.0
            logging.info("Connected to relay server")
            return True
        except Exception as e:
            logging.error(f"Failed to connect to relay: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from relay server"""
        if self.ws:
            try:
                await self.ws.close()
            except Exception as e:
                logging.error(f"Error disconnecting: {e}")
            finally:
                self.ws = None
                self.connected = False
    
    async def send(self, message: bytes, use_command_channel: bool = False) -> bool:
        """
        Send message through relay
        
        Args:
            message: Message bytes (command or MEMSHADOW binary)
            use_command_channel: If True and command channel available, send as command
        """
        if not self.connected or not self.ws:
            if not await self.connect():
                return False
        
        try:
            # If command channel is available and requested, use TLS extension format
            if use_command_channel and self.use_command_channel and TLSCommandExtension:
                # Assume message is a command payload, wrap it
                # In practice, caller should specify command type
                # For now, treat as generic command
                self.command_sequence += 1
                wrapped = TLSCommandExtension.pack_command(
                    TLSCommandType.CMD_EXECUTE,
                    message,
                    self.command_sequence
                )
                await self.ws.send(wrapped)
            else:
                # Send as binary (MEMSHADOW protocol)
                await self.ws.send(message)
            return True
        except ConnectionClosed:
            logging.warning("Connection closed, attempting reconnect...")
            self.connected = False
            return await self._reconnect_and_send(message, use_command_channel)
        except Exception as e:
            logging.error(f"Error sending message: {e}")
            return False
    
    async def receive(self) -> Optional[bytes]:
        """Receive message from relay"""
        if not self.connected or not self.ws:
            if not await self.connect():
                return None
        
        try:
            message = await self.ws.recv()
            if isinstance(message, str):
                return message.encode('utf-8')
            return message
        except ConnectionClosed:
            logging.warning("Connection closed, attempting reconnect...")
            self.connected = False
            return None
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            return None
    
    async def _reconnect_and_send(self, message: bytes, use_command_channel: bool = False) -> bool:
        """Reconnect and retry sending message"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            logging.error("Max reconnect attempts reached")
            return False
        
        self.reconnect_attempts += 1
        delay = min(self.reconnect_delay * (2 ** (self.reconnect_attempts - 1)),
                   self.max_reconnect_delay)
        
        logging.info(f"Reconnecting in {delay:.1f} seconds (attempt {self.reconnect_attempts})")
        await asyncio.sleep(delay)
        
        if await self.connect():
            return await self.send(message, use_command_channel)
        return False
    
    async def send_command(self, cmd_type: TLSCommandType, payload: bytes) -> bool:
        """Send command via TLS extension channel"""
        if not self.use_command_channel or not TLSCommandExtension:
            # Fallback to regular send
            return await self.send(payload)
        
        self.command_sequence += 1
        command = TLSCommandExtension.pack_command(cmd_type, payload, self.command_sequence)
        return await self.send(command)
    
    async def listen(self, message_handler):
        """Listen for messages and call handler"""
        while True:
            try:
                message = await self.receive()
                if message:
                    await message_handler(message)
                else:
                    # Connection lost, attempt reconnect
                    await asyncio.sleep(self.reconnect_delay)
                    if not await self.connect():
                        await asyncio.sleep(self.reconnect_delay)
            except Exception as e:
                logging.error(f"Error in listen loop: {e}")
                await asyncio.sleep(self.reconnect_delay)
                if not await self.connect():
                    await asyncio.sleep(self.reconnect_delay)


class RelayClientConfig:
    """Configuration for relay client"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            # Try multiple locations (relative to workspace root)
            workspace_root = Path(__file__).parent.parent
            config_paths = [
                Path.home() / '.config' / 'ai-relay' / 'client.yaml',
                Path('/etc/ai-relay/client.yaml'),
                workspace_root / 'config' / 'remote_guided.yaml',
                workspace_root / 'config' / 'client.yaml',
                Path('config/remote_guided.yaml'),
                Path('config/client.yaml'),
            ]
            for path in config_paths:
                if Path(path).exists():
                    config_path = str(path)
                    break
        
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration"""
        if not self.config_path or not Path(self.config_path).exists():
            return {}
        
        try:
            try:
                import yaml
            except ImportError:
                logging.warning("PyYAML not available, cannot load relay config")
                return {}
            
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            return {}
    
    def get_relay_host(self) -> str:
        """Get relay host from config"""
        return self.config.get('relay_host', 'localhost')
    
    def get_relay_port(self) -> int:
        """Get relay port from config"""
        return self.config.get('relay_port', 8889)
    
    def get_use_tls(self) -> bool:
        """Get TLS setting from config"""
        return self.config.get('use_tls', True)
    
    def get_auth_token(self) -> Optional[str]:
        """Get auth token from config"""
        return self.config.get('auth_token')
    
    def get_use_tor(self) -> bool:
        """Get Tor setting from config"""
        return self.config.get('use_tor', False)
    
    def get_transport(self) -> str:
        """Get transport type"""
        return self.config.get('transport', 'websocket')


def create_relay_client_from_config(config_path: Optional[str] = None,
                                   **overrides) -> RelayClient:
    """Create relay client from configuration file with optional overrides"""
    config = RelayClientConfig(config_path)
    
    relay_host = overrides.get('relay_host', config.get_relay_host())
    relay_port = overrides.get('relay_port', config.get_relay_port())
    use_tls = overrides.get('use_tls', config.get_use_tls())
    auth_token = overrides.get('auth_token', config.get_auth_token())
    use_tor = overrides.get('use_tor', config.get_use_tor())
    
    return RelayClient(
        relay_host=relay_host,
        relay_port=relay_port,
        use_tls=use_tls,
        auth_token=auth_token,
        use_tor=use_tor
    )
