"""LLM Agent Client - For connecting to remote LLM agent server"""

import socket
import struct
import json
from typing import Dict, Any, Optional
from modules.llm_agent import BinaryProtocol


class LLMAgentClient:
    """Client for connecting to LLM Agent Server"""
    
    def __init__(self, host: str = 'localhost', port: int = 8888):
        self.host = host
        self.port = port
        self.socket = None
    
    def connect(self) -> bool:
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
    
    def send_command(self, command: str, language: str = 'powershell') -> Optional[Dict[str, Any]]:
        """Send a command execution request"""
        payload = BinaryProtocol.encode_json({
            'command': command,
            'language': language
        })
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_COMMAND, payload)
        return self._send_and_receive(message)
    
    def generate_code(self, spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Request code generation"""
        payload = BinaryProtocol.encode_json(spec)
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_CODE_GENERATE, payload)
        return self._send_and_receive(message)
    
    def execute_code(self, file_path: str, language: str, args: list = None) -> Optional[Dict[str, Any]]:
        """Request code execution"""
        payload = BinaryProtocol.encode_json({
            'file_path': file_path,
            'language': language,
            'args': args or []
        })
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_EXECUTE, payload)
        return self._send_and_receive(message)
    
    def heartbeat(self) -> Optional[Dict[str, Any]]:
        """Send heartbeat"""
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_HEARTBEAT, b'{}')
        return self._send_and_receive(message)
    
    def _send_and_receive(self, message: bytes) -> Optional[Dict[str, Any]]:
        """Send message and receive response"""
        if not self.socket:
            return None
        
        try:
            # Send message
            self.socket.sendall(message)
            
            # Receive response
            buffer = b''
            while len(buffer) < 10:
                data = self.socket.recv(4096)
                if not data:
                    return None
                buffer += data
            
            # Parse header
            _, _, _, length = struct.unpack('!4sBBL', buffer[:10])
            
            # Receive full payload
            while len(buffer) < 10 + length:
                data = self.socket.recv(4096)
                if not data:
                    return None
                buffer += data
            
            msg_type, payload = BinaryProtocol.unpack_message(buffer[:10+length])
            
            if msg_type == BinaryProtocol.MSG_RESPONSE:
                return BinaryProtocol.decode_json(payload)
            elif msg_type == BinaryProtocol.MSG_ERROR:
                error_data = BinaryProtocol.decode_json(payload)
                raise Exception(error_data.get('error', 'Unknown error'))
            else:
                raise Exception(f"Unexpected message type: {msg_type}")
        
        except Exception as e:
            print(f"Communication error: {e}")
            return None
