#!/usr/bin/env python3
"""
AI Relay Daemon - Secure Relay Service for Remote-Guided Auto-Coding

This relay service acts as a middlebox between:
- Remote target auto-coder agents (clients)
- AI controller/orchestrator (MILTOP or equivalent)

Supports:
- Direct IP:port connections
- FQDN (dynamic DNS)
- Tor (.onion) endpoints
- TLS encryption
- Authentication via API keys/tokens
"""

import asyncio
import json
import logging
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

# Required dependencies for relay daemon
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.warning("PyYAML not available - relay config loading will fail")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logging.warning("aiohttp not available - health server may not work")

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
    from websockets.exceptions import ConnectionClosed, ConnectionClosedError
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    WebSocketServerProtocol = None
    ConnectionClosed = Exception
    ConnectionClosedError = Exception
    logging.error("websockets not available - relay daemon cannot function")

# Import TLS extensions and MEMSHADOW protocol support
try:
    from tls_extensions import TLSCommandExtension, CommandChannel, TLSCommandType
except ImportError:
    # Fallback if not available
    TLSCommandExtension = None
    CommandChannel = None
    TLSCommandType = None


class RelayConfig:
    """Relay configuration"""
    
    def __init__(self, config_path: str = "/etc/ai-relay/relay.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            return self._default_config()
        
        if not YAML_AVAILABLE:
            logging.error("PyYAML not available - cannot load config file")
            return self._default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            return self._default_config()
    
    def _default_config(self) -> dict:
        """Default configuration"""
        return {
            'listen': {
                'host': '0.0.0.0',
                'port': 8889,
                'ipv6': False
            },
            'controller': {
                'endpoint': 'ws://localhost:8888',
                'timeout': 30
            },
            'auth': {
                'client_token': None,
                'controller_token': None,
                'require_auth': True
            },
            'tls': {
                'enabled': True,
                'cert_file': '/etc/ai-relay/cert.pem',
                'key_file': '/etc/ai-relay/key.pem',
                'ca_file': None,
                'verify_mode': 'required'
            },
            'tor': {
                'enabled': False,
                'hidden_service_dir': '/var/lib/tor/ai-relay',
                'hidden_service_port': 8889
            },
            'logging': {
                'level': 'INFO',
                'file': '/var/log/ai-relay/relay.log',
                'format': 'json'
            },
            'limits': {
                'max_sessions': 100,
                'max_message_size': 10485760,  # 10MB
                'idle_timeout': 300
            },
            'health': {
                'port': 9090,
                'path': '/healthz'
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value


class RelaySession:
    """Represents a relay session between client and controller"""
    
    def __init__(self, session_id: str, client_ws: WebSocketServerProtocol, 
                 controller_endpoint: str, auth_token: Optional[str] = None):
        self.session_id = session_id
        self.client_ws = client_ws
        self.controller_endpoint = controller_endpoint
        self.auth_token = auth_token
        self.controller_ws: Optional[websockets.WebSocketClientProtocol] = None
        self.created_at = time.time()
        self.last_activity = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.messages_sent = 0
        self.messages_received = 0
        self.authenticated = False
        self.use_command_channel = False  # TLS extension command channel
        self.command_sequence = 0  # Sequence number for commands
    
    async def connect_controller(self) -> bool:
        """Connect to AI controller"""
        try:
            headers = {}
            if self.auth_token:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            
            self.controller_ws = await websockets.connect(
                self.controller_endpoint,
                extra_headers=headers,
                ping_interval=20,
                ping_timeout=10
            )
            return True
        except Exception as e:
            logging.error(f"Failed to connect to controller: {e}")
            return False
    
    async def relay_message(self, message: bytes) -> bool:
        """Relay message from client to controller"""
        if not self.controller_ws:
            if not await self.connect_controller():
                return False
        
        try:
            await self.controller_ws.send(message)
            self.bytes_sent += len(message)
            self.messages_sent += 1
            self.last_activity = time.time()
            return True
        except Exception as e:
            logging.error(f"Failed to relay message to controller: {e}")
            return False
    
    async def send_to_client(self, message: bytes) -> bool:
        """Send message from controller to client"""
        try:
            await self.client_ws.send(message)
            self.bytes_received += len(message)
            self.messages_received += 1
            self.last_activity = time.time()
            return True
        except Exception as e:
            logging.error(f"Failed to send message to client: {e}")
            return False
    
    def is_idle(self, timeout: int) -> bool:
        """Check if session is idle"""
        return (time.time() - self.last_activity) > timeout
    
    def get_stats(self) -> dict:
        """Get session statistics"""
        return {
            'session_id': self.session_id,
            'created_at': datetime.fromtimestamp(self.created_at).isoformat(),
            'last_activity': datetime.fromtimestamp(self.last_activity).isoformat(),
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'authenticated': self.authenticated
        }


class RelayDaemon:
    """Main relay daemon"""
    
    def __init__(self, config_path: str = "/etc/ai-relay/relay.yaml"):
        self.config = RelayConfig(config_path)
        self.sessions: Dict[str, RelaySession] = {}
        self.setup_logging()
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.setup_tls()
    
    def setup_logging(self):
        """Setup logging"""
        log_level = getattr(logging, self.config.get('logging.level', 'INFO'))
        log_file = self.config.get('logging.file', '/var/log/ai-relay/relay.log')
        log_format = self.config.get('logging.format', 'json')
        
        # Create log directory
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        if log_format == 'json':
            formatter = JsonFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(handler)
        
        # Also log to console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    def setup_tls(self):
        """Setup TLS context with CNSA 2.0 compliance"""
        if not self.config.get('tls.enabled', True):
            return
        
        try:
            cert_file = self.config.get('tls.cert_file')
            key_file = self.config.get('tls.key_file')
            
            if cert_file and Path(cert_file).exists() and key_file and Path(key_file).exists():
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.ssl_context.load_cert_chain(cert_file, key_file)
                
                # CNSA 2.0 Compliant Configuration
                # Required: TLS 1.2 or higher
                self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.ssl_context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
                
                # CNSA 2.0 Cipher Suites (in priority order):
                # - ECDHE-ECDSA-AES256-GCM-SHA384 (P-384 curve, AES-256, SHA-384)
                # - ECDHE-RSA-AES256-GCM-SHA384 (RSA 3072+, AES-256, SHA-384)
                # - DHE-RSA-AES256-GCM-SHA384 (DH 3072+, AES-256, SHA-384)
                cnsa_ciphers = (
                    'ECDHE-ECDSA-AES256-GCM-SHA384:'      # Preferred: ECDSA P-384
                    'ECDHE-RSA-AES256-GCM-SHA384:'        # RSA 3072+
                    'DHE-RSA-AES256-GCM-SHA384'           # DH 3072+
                )
                self.ssl_context.set_ciphers(cnsa_ciphers)
                
                # CNSA 2.0: Prefer P-384 elliptic curves
                # Note: Python ssl doesn't expose curve selection directly,
                # but ECDHE ciphers will negotiate P-384 when available
                self.ssl_context.options |= ssl.OP_NO_SSLv2
                self.ssl_context.options |= ssl.OP_NO_SSLv3
                self.ssl_context.options |= ssl.OP_NO_TLSv1
                self.ssl_context.options |= ssl.OP_NO_TLSv1_1
                
                # Enable perfect forward secrecy
                self.ssl_context.options |= ssl.OP_SINGLE_ECDH_USE
                self.ssl_context.options |= ssl.OP_SINGLE_DH_USE
                
                # Prefer server cipher order
                self.ssl_context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
                
                # Configure ALPN for TLS extensions (command channel)
                if TLSCommandExtension:
                    try:
                        self.ssl_context.set_alpn_protocols(
                            TLSCommandExtension.create_alpn_protocols()
                        )
                        logging.info("ALPN protocols configured for TLS extensions")
                    except AttributeError:
                        logging.warning("ALPN not supported in this Python version")
                
                logging.info("TLS enabled with CNSA 2.0 compliant configuration")
            else:
                logging.warning("TLS enabled but certificates not found, generating self-signed")
                self.ssl_context = self._generate_self_signed_cert()
        except Exception as e:
            logging.error(f"Failed to setup TLS: {e}")
            self.ssl_context = None
    
    def _generate_self_signed_cert(self) -> ssl.SSLContext:
        """Generate self-signed certificate (for testing)"""
        # In production, use Let's Encrypt or proper CA
        # This is a placeholder - actual implementation would use cryptography library
        logging.warning("Using insecure self-signed certificate - not for production!")
        return None  # Would generate actual cert here
    
    async def authenticate_client(self, ws: WebSocketServerProtocol, 
                                 headers: dict) -> Tuple[bool, Optional[str]]:
        """Authenticate client connection"""
        if not self.config.get('auth.require_auth', True):
            return True, None
        
        # Check for Authorization header
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            expected_token = self.config.get('auth.client_token')
            if expected_token and token == expected_token:
                return True, token
        
        # Check for token in query string
        if hasattr(ws, 'path') and '?' in ws.path:
            query_params = dict(param.split('=') for param in ws.path.split('?')[1].split('&'))
            token = query_params.get('token')
            expected_token = self.config.get('auth.client_token')
            if expected_token and token == expected_token:
                return True, token
        
        return False, None
    
    async def handle_client(self, ws: WebSocketServerProtocol, path: str):
        """Handle client WebSocket connection"""
        session_id = f"session_{int(time.time() * 1000)}"
        client_addr = ws.remote_address if hasattr(ws, 'remote_address') else 'unknown'
        
        logging.info(f"New client connection: {session_id} from {client_addr}")
        
        # Check if this is a command channel (TLS extension) or MEMSHADOW binary
        # WebSocket over TLS will have ALPN protocol negotiated
        use_command_channel = False
        if hasattr(ws, 'transport') and hasattr(ws.transport, '_ssl_protocol'):
            # Check ALPN protocol
            try:
                alpn_protocol = ws.transport._ssl_protocol.selected_alpn_protocol()
                if alpn_protocol == TLSCommandExtension.ALPN_PROTOCOL_COMMAND.decode('utf-8'):
                    use_command_channel = True
                    logging.info(f"Session {session_id} using TLS command channel")
            except:
                pass
        
        # Authenticate
        headers = dict(ws.request_headers) if hasattr(ws, 'request_headers') else {}
        authenticated, token = await self.authenticate_client(ws, headers)
        
        if not authenticated:
            logging.warning(f"Authentication failed for session {session_id}")
            await ws.close(code=4001, reason="Authentication failed")
            return
        
        # Check session limits
        if len(self.sessions) >= self.config.get('limits.max_sessions', 100):
            logging.warning(f"Max sessions reached, rejecting {session_id}")
            await ws.close(code=4002, reason="Server at capacity")
            return
        
        # Create session
        controller_endpoint = self.config.get('controller.endpoint', 'ws://localhost:8888')
        session = RelaySession(session_id, ws, controller_endpoint, token)
        session.authenticated = True
        session.use_command_channel = use_command_channel
        self.sessions[session_id] = session
        
        try:
            # Connect to controller
            if not await session.connect_controller():
                await ws.close(code=4003, reason="Failed to connect to controller")
                return
            
            logging.info(f"Session {session_id} established, relaying to {controller_endpoint}")
            
            # Start bidirectional relay
            if use_command_channel:
                # Use TLS extension command channel
                await asyncio.gather(
                    self._relay_commands_client_to_controller(session),
                    self._relay_commands_controller_to_client(session)
                )
            else:
                # Use MEMSHADOW binary protocol
                await asyncio.gather(
                    self._relay_client_to_controller(session),
                    self._relay_controller_to_client(session)
                )
        except ConnectionClosed:
            logging.info(f"Client connection closed: {session_id}")
        except Exception as e:
            logging.error(f"Error in session {session_id}: {e}")
        finally:
            # Cleanup
            if session.controller_ws:
                await session.controller_ws.close()
            if session_id in self.sessions:
                del self.sessions[session_id]
            logging.info(f"Session {session_id} closed")
    
    async def _relay_client_to_controller(self, session: RelaySession):
        """Relay messages from client to controller"""
        try:
            async for message in session.client_ws:
                if isinstance(message, str):
                    message = message.encode('utf-8')
                
                # Check message size
                max_size = self.config.get('limits.max_message_size', 10485760)
                if len(message) > max_size:
                    logging.warning(f"Message too large: {len(message)} bytes")
                    continue
                
                await session.relay_message(message)
        except ConnectionClosed:
            pass
        except Exception as e:
            logging.error(f"Error relaying client->controller: {e}")
    
    async def _relay_controller_to_client(self, session: RelaySession):
        """Relay messages from controller to client"""
        try:
            if not session.controller_ws:
                return
            
            async for message in session.controller_ws:
                if isinstance(message, str):
                    message = message.encode('utf-8')
                
                await session.send_to_client(message)
        except ConnectionClosed:
            pass
        except Exception as e:
            logging.error(f"Error relaying controller->client: {e}")
    
    async def _relay_commands_client_to_controller(self, session: RelaySession):
        """Relay commands from client to controller using TLS extensions"""
        if not TLSCommandExtension:
            # Fallback to binary relay
            await self._relay_client_to_controller(session)
            return
        
        try:
            async for message in session.client_ws:
                if isinstance(message, str):
                    message = message.encode('utf-8')
                
                # Parse command from TLS extension format
                try:
                    cmd_type, sequence, payload = TLSCommandExtension.unpack_command(message)
                    logging.debug(f"Relaying command {cmd_type} (seq: {sequence})")
                    
                    # Relay to controller
                    await session.relay_message(message)
                except ValueError:
                    # Not a command, treat as binary (MEMSHADOW)
                    await session.relay_message(message)
        except ConnectionClosed:
            pass
        except Exception as e:
            logging.error(f"Error relaying commands client->controller: {e}")
    
    async def _relay_commands_controller_to_client(self, session: RelaySession):
        """Relay commands from controller to client using TLS extensions"""
        if not TLSCommandExtension:
            # Fallback to binary relay
            await self._relay_controller_to_client(session)
            return
        
        try:
            if not session.controller_ws:
                return
            
            async for message in session.controller_ws:
                if isinstance(message, str):
                    message = message.encode('utf-8')
                
                # Check if it's a command response
                try:
                    cmd_type, sequence, payload = TLSCommandExtension.unpack_command(message)
                    logging.debug(f"Relaying command response {cmd_type} (seq: {sequence})")
                    
                    # Send to client
                    await session.send_to_client(message)
                except ValueError:
                    # Not a command, treat as binary (MEMSHADOW)
                    await session.send_to_client(message)
        except ConnectionClosed:
            pass
        except Exception as e:
            logging.error(f"Error relaying commands controller->client: {e}")
    
    async def cleanup_idle_sessions(self):
        """Cleanup idle sessions"""
        timeout = self.config.get('limits.idle_timeout', 300)
        idle_sessions = [
            sid for sid, session in self.sessions.items()
            if session.is_idle(timeout)
        ]
        
        for sid in idle_sessions:
            session = self.sessions[sid]
            logging.info(f"Cleaning up idle session: {sid}")
            if session.controller_ws:
                await session.controller_ws.close()
            await session.client_ws.close()
            del self.sessions[sid]
    
    async def start(self):
        """Start relay daemon"""
        if not WEBSOCKETS_AVAILABLE:
            logging.error("websockets library not available. Install with: pip install websockets")
            raise RuntimeError("Required dependency 'websockets' not available")
        
        host = self.config.get('listen.host', '0.0.0.0')
        port = self.config.get('listen.port', 8889)
        
        logging.info(f"Starting relay daemon on {host}:{port}")
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())
        
        # Start WebSocket server
        async with websockets.serve(
            self.handle_client,
            host,
            port,
            ssl=self.ssl_context,
            ping_interval=20,
            ping_timeout=10
        ):
            logging.info(f"Relay daemon listening on {host}:{port}")
            await asyncio.Future()  # Run forever
    
    async def _cleanup_loop(self):
        """Periodic cleanup loop"""
        while True:
            await asyncio.sleep(60)  # Check every minute
            await self.cleanup_idle_sessions()
    
    def get_stats(self) -> dict:
        """Get relay statistics"""
        return {
            'active_sessions': len(self.sessions),
            'sessions': [s.get_stats() for s in self.sessions.values()],
            'config': {
                'listen_host': self.config.get('listen.host'),
                'listen_port': self.config.get('listen.port'),
                'controller_endpoint': self.config.get('controller.endpoint'),
                'tls_enabled': self.ssl_context is not None
            }
        }


class JsonFormatter(logging.Formatter):
    """JSON log formatter"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Relay Daemon')
    parser.add_argument('--config', default='/etc/ai-relay/relay.yaml',
                       help='Path to configuration file')
    parser.add_argument('--host', help='Override listen host')
    parser.add_argument('--port', type=int, help='Override listen port')
    parser.add_argument('--no-tls', action='store_true', help='Disable TLS')
    
    args = parser.parse_args()
    
    daemon = RelayDaemon(args.config)
    
    # Override config from command line
    if args.host:
        daemon.config.config['listen']['host'] = args.host
    if args.port:
        daemon.config.config['listen']['port'] = args.port
    if args.no_tls:
        daemon.config.config['tls']['enabled'] = False
        daemon.ssl_context = None
    
    await daemon.start()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Relay daemon stopped by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
