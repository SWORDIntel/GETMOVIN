"""MEMSHADOW MRAC Client - For connecting to remote MRAC server"""

import socket
import struct
import json
import uuid
import time
from typing import Dict, Any, Optional, List
from modules.memshadow_protocol import (
    MemshadowHeader, MRACProtocol, MRACMessageType, SelfCodeCommandType,
    HeaderFlags
)


class MRACClient:
    """Client for connecting to MEMSHADOW MRAC Server"""
    
    def __init__(self, host: str = 'localhost', port: int = 8888, session_token: Optional[bytes] = None):
        self.host = host
        self.port = port
        self.session_token = session_token
        self.socket = None
        self.app_id = uuid.uuid4().bytes
        self.sequence_num = 0
        self.registered = False
    
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
    
    def register(self, name: str, capabilities: Dict[str, Any]) -> bool:
        """Register this app with the server"""
        if not self.socket:
            return False
        
        try:
            payload = MRACProtocol.pack_register(
                self.app_id, name, capabilities, self.session_token
            )
            
            header = MemshadowHeader.pack(
                priority=0,
                flags=HeaderFlags.REQUIRES_ACK,
                msg_type=MRACMessageType.APP_REGISTER,
                batch_count=1,
                payload_len=len(payload),
                timestamp_ns=time.time_ns(),
                sequence_num=self._next_sequence()
            )
            
            self.socket.sendall(header + payload)
            
            # Receive ACK
            response = self._receive_message()
            if response and response['msg_type'] == MRACMessageType.APP_REGISTER_ACK:
                # Parse ACK
                self.registered = True
                return True
            
            return False
        except Exception as e:
            print(f"Registration failed: {e}")
            return False
    
    def send_command(self, cmd_type: int, args: Dict[str, Any], 
                     ttl_ms: int = 30000, requires_ack: bool = True) -> Optional[Dict[str, Any]]:
        """Send APP_COMMAND message"""
        if not self.socket or not self.registered:
            return None
        
        try:
            command_id = int(time.time_ns())
            args_bytes = json.dumps(args).encode('utf-8')
            
            payload = MRACProtocol.pack_command(
                self.app_id, command_id, cmd_type, args_bytes, ttl_ms, self.session_token
            )
            
            flags = HeaderFlags.REQUIRES_ACK if requires_ack else 0
            header = MemshadowHeader.pack(
                priority=0,
                flags=flags,
                msg_type=MRACMessageType.APP_COMMAND,
                batch_count=1,
                payload_len=len(payload),
                timestamp_ns=time.time_ns(),
                sequence_num=self._next_sequence()
            )
            
            self.socket.sendall(header + payload)
            
            if requires_ack:
                response = self._receive_message()
                if response and response['msg_type'] == MRACMessageType.APP_COMMAND_ACK:
                    # Parse ACK
                    ack_data = MRACProtocol.unpack_command(response['payload'])
                    result = json.loads(ack_data['args'].decode('utf-8'))
                    return result
            
            return None
        except Exception as e:
            print(f"Command failed: {e}")
            return None
    
    def send_plan_request(self, objective: str = "", paths: List[str] = None) -> Optional[Dict[str, Any]]:
        """Send SELF_CODE_PLAN_REQUEST"""
        args = {}
        if objective:
            args['objective'] = objective
        if paths:
            args['paths'] = paths
        
        return self.send_command(SelfCodeCommandType.SELF_CODE_PLAN_REQUEST, args)
    
    def send_apply_patch(self, patch: str, path: str, checksum_before: str = "") -> Optional[Dict[str, Any]]:
        """Send SELF_CODE_APPLY_PATCH"""
        args = {
            'patch': patch,
            'path': path,
            'checksum_before': checksum_before
        }
        return self.send_command(SelfCodeCommandType.SELF_CODE_APPLY_PATCH, args)
    
    def send_test_run(self, command: List[str], timeout_sec: int = 120) -> Optional[Dict[str, Any]]:
        """Send SELF_CODE_TEST_RUN"""
        args = {
            'command': command,
            'timeout_sec': timeout_sec
        }
        return self.send_command(SelfCodeCommandType.SELF_CODE_TEST_RUN, args)
    
    def send_heartbeat(self, uptime_ms: int = 0, load_pct: int = 0, temp_c: int = 0):
        """Send APP_HEARTBEAT"""
        if not self.socket:
            return
        
        try:
            payload = MRACProtocol.pack_heartbeat(
                self.app_id, uptime_ms, load_pct, temp_c, self.session_token
            )
            
            header = MemshadowHeader.pack(
                priority=0,
                flags=0,
                msg_type=MRACMessageType.APP_HEARTBEAT,
                batch_count=1,
                payload_len=len(payload),
                timestamp_ns=time.time_ns(),
                sequence_num=self._next_sequence()
            )
            
            self.socket.sendall(header + payload)
        except Exception as e:
            print(f"Heartbeat failed: {e}")
    
    def _next_sequence(self) -> int:
        """Get next sequence number"""
        self.sequence_num += 1
        return self.sequence_num
    
    def _receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive a MEMSHADOW message"""
        if not self.socket:
            return None
        
        try:
            # Receive header
            header_data = b''
            while len(header_data) < 32:
                chunk = self.socket.recv(32 - len(header_data))
                if not chunk:
                    return None
                header_data += chunk
            
            priority, flags, msg_type, batch_count, payload_len, timestamp_ns, sequence_num = \
                MemshadowHeader.unpack(header_data)
            
            # Receive payload
            payload = b''
            while len(payload) < payload_len:
                chunk = self.socket.recv(payload_len - len(payload))
                if not chunk:
                    return None
                payload += chunk
            
            return {
                'priority': priority,
                'flags': flags,
                'msg_type': msg_type,
                'batch_count': batch_count,
                'payload': payload,
                'timestamp_ns': timestamp_ns,
                'sequence_num': sequence_num
            }
        except Exception as e:
            print(f"Receive error: {e}")
            return None
