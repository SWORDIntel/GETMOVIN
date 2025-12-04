"""
TLS Extensions for Command Channel

Implements TLS extensions for secure command transmission
following CNSA 2.0 specifications.

Commands are transmitted via TLS extensions (ALPN/SNI) while
binary data uses MEMSHADOW protocol.
"""

import struct
import ssl
import logging
from typing import Optional, Dict, Any, Tuple
from enum import IntEnum


class TLSCommandType(IntEnum):
    """Command types for TLS extension channel"""
    CMD_EXECUTE = 0x01
    CMD_CODE_GENERATE = 0x02
    CMD_HEARTBEAT = 0x03
    CMD_REGISTER = 0x04
    CMD_RESPONSE = 0x05
    CMD_ERROR = 0x06


class TLSCommandExtension:
    """TLS extension handler for commands"""
    
    # ALPN Protocol IDs
    ALPN_PROTOCOL_COMMAND = b'ai-relay-command'
    ALPN_PROTOCOL_MEMSHADOW = b'ai-relay-memshadow'
    
    @staticmethod
    def create_alpn_protocols() -> list:
        """Create ALPN protocol list for TLS negotiation"""
        return [
            TLSCommandExtension.ALPN_PROTOCOL_COMMAND.decode('utf-8'),
            TLSCommandExtension.ALPN_PROTOCOL_MEMSHADOW.decode('utf-8')
        ]
    
    @staticmethod
    def configure_ssl_context_for_cnsa(context: ssl.SSLContext):
        """Configure SSL context with CNSA 2.0 and ALPN support"""
        # Set ALPN protocols
        context.set_alpn_protocols(TLSCommandExtension.create_alpn_protocols())
        
        # CNSA 2.0 cipher suites
        cnsa_ciphers = (
            'ECDHE-ECDSA-AES256-GCM-SHA384:'
            'ECDHE-RSA-AES256-GCM-SHA384:'
            'DHE-RSA-AES256-GCM-SHA384'
        )
        context.set_ciphers(cnsa_ciphers)
        
        # TLS 1.2+ only
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    @staticmethod
    def pack_command(cmd_type: TLSCommandType, payload: bytes, 
                     sequence: int = 0) -> bytes:
        """
        Pack command for TLS extension transmission
        
        Format:
        - Command Type: 1 byte
        - Sequence Number: 4 bytes (big-endian)
        - Payload Length: 4 bytes (big-endian)
        - Payload: N bytes
        """
        return struct.pack('!BII', cmd_type, sequence, len(payload)) + payload
    
    @staticmethod
    def unpack_command(data: bytes) -> Tuple[TLSCommandType, int, bytes]:
        """Unpack command from TLS extension"""
        if len(data) < 9:
            raise ValueError("Command too short")
        
        cmd_type, sequence, payload_len = struct.unpack('!BII', data[:9])
        
        if len(data) < 9 + payload_len:
            raise ValueError("Incomplete payload")
        
        payload = data[9:9+payload_len]
        return TLSCommandType(cmd_type), sequence, payload
    
    @staticmethod
    def create_command_response(success: bool, result: bytes, 
                                sequence: int) -> bytes:
        """Create command response"""
        status = 0x00 if success else 0x01
        return TLSCommandExtension.pack_command(
            TLSCommandType.CMD_RESPONSE,
            struct.pack('!B', status) + result,
            sequence
        )
    
    @staticmethod
    def create_error_response(error_code: int, error_msg: str, 
                              sequence: int) -> bytes:
        """Create error response"""
        error_bytes = error_msg.encode('utf-8')
        return TLSCommandExtension.pack_command(
            TLSCommandType.CMD_ERROR,
            struct.pack('!IH', error_code, len(error_bytes)) + error_bytes,
            sequence
        )


class CommandChannel:
    """Command channel using TLS extensions"""
    
    def __init__(self, ssl_socket):
        self.ssl_socket = ssl_socket
        self.sequence = 0
        self.alpn_protocol = None
        self._detect_alpn_protocol()
    
    def _detect_alpn_protocol(self):
        """Detect negotiated ALPN protocol"""
        try:
            # Get selected ALPN protocol
            if hasattr(self.ssl_socket, 'selected_alpn_protocol'):
                self.alpn_protocol = self.ssl_socket.selected_alpn_protocol()
            elif hasattr(self.ssl_socket, 'get_alpn_protocols'):
                protocols = self.ssl_socket.get_alpn_protocols()
                if protocols:
                    self.alpn_protocol = protocols[0]
        except Exception as e:
            logging.warning(f"Could not detect ALPN protocol: {e}")
    
    def is_command_channel(self) -> bool:
        """Check if command channel is active"""
        return self.alpn_protocol == TLSCommandExtension.ALPN_PROTOCOL_COMMAND.decode('utf-8')
    
    def is_memshadow_channel(self) -> bool:
        """Check if MEMSHADOW channel is active"""
        return self.alpn_protocol == TLSCommandExtension.ALPN_PROTOCOL_MEMSHADOW.decode('utf-8')
    
    def send_command(self, cmd_type: TLSCommandType, payload: bytes) -> bool:
        """Send command via TLS extension"""
        if not self.is_command_channel():
            logging.warning("Not using command channel, falling back to binary")
            return False
        
        try:
            self.sequence += 1
            command = TLSCommandExtension.pack_command(cmd_type, payload, self.sequence)
            self.ssl_socket.sendall(command)
            return True
        except Exception as e:
            logging.error(f"Failed to send command: {e}")
            return False
    
    def receive_command(self) -> Optional[Tuple[TLSCommandType, int, bytes]]:
        """Receive command via TLS extension"""
        if not self.is_command_channel():
            return None
        
        try:
            # Read header (9 bytes)
            header = self.ssl_socket.recv(9)
            if len(header) < 9:
                return None
            
            cmd_type, sequence, payload_len = struct.unpack('!BII', header)
            
            # Read payload
            payload = b''
            while len(payload) < payload_len:
                chunk = self.ssl_socket.recv(payload_len - len(payload))
                if not chunk:
                    return None
                payload += chunk
            
            return TLSCommandType(cmd_type), sequence, payload
        except Exception as e:
            logging.error(f"Failed to receive command: {e}")
            return None
