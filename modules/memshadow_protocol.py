"""MEMSHADOW Remote App Control Extension (MRAC) Protocol Implementation"""

import struct
import uuid
import hashlib
import hmac
import time
import json
from typing import Dict, Any, Optional, Tuple, List
from enum import IntEnum


class HeaderFlags(IntEnum):
    """MEMSHADOW header flags"""
    REQUIRES_ACK = 0x01
    PQC_SIGNED = 0x02
    HMAC_PRESENT = 0x04


class MRACMessageType(IntEnum):
    """MRAC message types (0x2100 - 0x21FF)"""
    APP_REGISTER = 0x2101
    APP_REGISTER_ACK = 0x2102
    APP_COMMAND = 0x2103
    APP_COMMAND_ACK = 0x2104
    APP_TELEMETRY = 0x2105
    APP_HEARTBEAT = 0x2106
    APP_ERROR = 0x2107
    APP_BULK_COMMAND = 0x2108
    APP_BULK_COMMAND_ACK = 0x2109


class SelfCodeCommandType(IntEnum):
    """Self-code control command types"""
    SELF_CODE_PLAN_REQUEST = 0x3001
    SELF_CODE_PLAN_RESPONSE = 0x3002
    SELF_CODE_APPLY_PATCH = 0x3003
    SELF_CODE_RESULT = 0x3004
    SELF_CODE_TEST_RUN = 0x3005


class ValueType(IntEnum):
    """Telemetry value types"""
    INT64 = 0
    UINT64 = 1
    FLOAT32 = 2
    FLOAT64 = 3
    BOOL = 4
    UTF8_LEN16 = 5


class MemshadowHeader:
    """MEMSHADOW v2 header (32 bytes)"""
    
    MAGIC = b'MSHW'
    VERSION = 2
    
    @staticmethod
    def pack(priority: int, flags: int, msg_type: int, batch_count: int,
             payload_len: int, timestamp_ns: int, sequence_num: int) -> bytes:
        """Pack MEMSHADOW v2 header"""
        # Format: magic(4) + version(1) + priority(1) + flags(1) + msg_type(2) + 
        #         batch_count(2) + payload_len(4) + timestamp_ns(8) + sequence_num(4) + reserved(5)
        return struct.pack(
            '!4sBBBBHHQIH',
            MemshadowHeader.MAGIC,
            MemshadowHeader.VERSION,
            priority & 0xFF,
            flags & 0xFF,
            msg_type & 0xFFFF,
            batch_count & 0xFFFF,
            payload_len & 0xFFFFFFFF,
            timestamp_ns,
            sequence_num & 0xFFFFFFFF
        ) + b'\x00' * 5  # reserved
    
    @staticmethod
    def unpack(data: bytes) -> Tuple[int, int, int, int, int, int, int]:
        """Unpack MEMSHADOW v2 header"""
        if len(data) < 32:
            raise ValueError("Header too short")
        
        magic, version, priority, flags, msg_type, batch_count, payload_len, timestamp_ns, sequence_num = struct.unpack(
            '!4sBBBBHHQIH', data[:31]
        )
        
        if magic != MemshadowHeader.MAGIC:
            raise ValueError(f"Invalid magic: {magic}")
        
        if version != MemshadowHeader.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        return priority, flags, msg_type, batch_count, payload_len, timestamp_ns, sequence_num


class MRACProtocol:
    """MRAC protocol handler"""
    
    @staticmethod
    def compute_auth(session_token: bytes, timestamp_ns: int, nonce: bytes) -> bytes:
        """Compute authentication hash"""
        data = session_token + struct.pack('!Q', timestamp_ns) + nonce
        return hashlib.sha256(data).digest()[:16]
    
    @staticmethod
    def pack_register(app_id: bytes, name: str, capabilities: Dict[str, Any],
                     session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_REGISTER message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        name_bytes = name.encode('utf-8')
        if len(name_bytes) > 64:
            raise ValueError("Name too long (max 64 bytes)")
        
        capabilities_json = json.dumps(capabilities).encode('utf-8')
        
        payload = (
            auth +
            nonce +
            app_id +
            struct.pack('!H', len(capabilities_json)) +
            struct.pack('!B', len(name_bytes)) +
            name_bytes +
            capabilities_json
        )
        
        return payload
    
    @staticmethod
    def unpack_register(payload: bytes) -> Dict[str, Any]:
        """Unpack APP_REGISTER message"""
        if len(payload) < 16 + 8 + 16 + 2 + 1:
            raise ValueError("Payload too short")
        
        offset = 0
        auth = payload[offset:offset+16]
        offset += 16
        nonce = payload[offset:offset+8]
        offset += 8
        app_id = payload[offset:offset+16]
        offset += 16
        capabilities_len = struct.unpack('!H', payload[offset:offset+2])[0]
        offset += 2
        name_len = struct.unpack('!B', payload[offset:offset+1])[0]
        offset += 1
        name = payload[offset:offset+name_len].decode('utf-8')
        offset += name_len
        capabilities_json = payload[offset:offset+capabilities_len].decode('utf-8')
        capabilities = json.loads(capabilities_json)
        
        return {
            'auth': auth,
            'nonce': nonce,
            'app_id': app_id,
            'name': name,
            'capabilities': capabilities
        }
    
    @staticmethod
    def pack_register_ack(app_id: bytes, status: int, reason: str,
                          session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_REGISTER_ACK message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        reason_bytes = reason.encode('utf-8')
        
        payload = (
            auth +
            nonce +
            app_id +
            struct.pack('!B', status) +
            struct.pack('!B', len(reason_bytes)) +
            reason_bytes
        )
        
        return payload
    
    @staticmethod
    def pack_command(app_id: bytes, command_id: int, cmd_type: int, args: bytes,
                    ttl_ms: int = 30000, session_token: Optional[bytes] = None,
                    nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_COMMAND message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        payload = (
            auth +
            nonce +
            app_id +
            struct.pack('!Q', command_id) +
            struct.pack('!I', ttl_ms) +
            struct.pack('!H', cmd_type) +
            struct.pack('!H', len(args)) +
            args
        )
        
        return payload
    
    @staticmethod
    def unpack_command(payload: bytes) -> Dict[str, Any]:
        """Unpack APP_COMMAND message"""
        if len(payload) < 16 + 8 + 16 + 8 + 4 + 2 + 2:
            raise ValueError("Payload too short")
        
        offset = 0
        auth = payload[offset:offset+16]
        offset += 16
        nonce = payload[offset:offset+8]
        offset += 8
        app_id = payload[offset:offset+16]
        offset += 16
        command_id = struct.unpack('!Q', payload[offset:offset+8])[0]
        offset += 8
        ttl_ms = struct.unpack('!I', payload[offset:offset+4])[0]
        offset += 4
        cmd_type = struct.unpack('!H', payload[offset:offset+2])[0]
        offset += 2
        arg_len = struct.unpack('!H', payload[offset:offset+2])[0]
        offset += 2
        args = payload[offset:offset+arg_len]
        
        return {
            'auth': auth,
            'nonce': nonce,
            'app_id': app_id,
            'command_id': command_id,
            'ttl_ms': ttl_ms,
            'cmd_type': cmd_type,
            'args': args
        }
    
    @staticmethod
    def pack_command_ack(app_id: bytes, command_id: int, status: int, result: bytes,
                         session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_COMMAND_ACK message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        payload = (
            auth +
            nonce +
            app_id +
            struct.pack('!Q', command_id) +
            struct.pack('!B', status) +
            struct.pack('!H', len(result)) +
            result
        )
        
        return payload
    
    @staticmethod
    def pack_heartbeat(app_id: bytes, uptime_ms: int, load_pct: int, temp_c: int,
                      session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_HEARTBEAT message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        payload = (
            auth +
            nonce +
            app_id +
            struct.pack('!Q', uptime_ms) +
            struct.pack('!B', load_pct & 0xFF) +
            struct.pack('!B', temp_c & 0xFF)
        )
        
        return payload
    
    @staticmethod
    def pack_error(app_id: bytes, error_code: int, detail: str,
                  session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_ERROR message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        detail_bytes = detail.encode('utf-8')
        
        payload = (
            auth +
            nonce +
            app_id +
            struct.pack('!H', error_code) +
            struct.pack('!H', len(detail_bytes)) +
            detail_bytes
        )
        
        return payload
    
    @staticmethod
    def pack_bulk_command(commands: List[Dict[str, Any]],
                          session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_BULK_COMMAND message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        batch_count = len(commands)
        payload = auth + nonce + struct.pack('!H', batch_count)
        
        for cmd in commands:
            app_id = cmd['app_id']
            command_id = cmd['command_id']
            ttl_ms = cmd.get('ttl_ms', 30000)
            cmd_type = cmd['cmd_type']
            args = cmd['args'] if isinstance(cmd['args'], bytes) else cmd['args'].encode('utf-8')
            
            payload += (
                app_id +
                struct.pack('!Q', command_id) +
                struct.pack('!I', ttl_ms) +
                struct.pack('!H', cmd_type) +
                struct.pack('!H', len(args)) +
                args
            )
        
        return payload
    
    @staticmethod
    def pack_bulk_command_ack(results: List[Dict[str, Any]],
                              session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_BULK_COMMAND_ACK message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        batch_count = len(results)
        payload = auth + nonce + struct.pack('!H', batch_count)
        
        for result in results:
            app_id = result['app_id']
            command_id = result['command_id']
            status = result['status']
            
            payload += (
                app_id +
                struct.pack('!Q', command_id) +
                struct.pack('!B', status)
            )
        
        return payload
    
    @staticmethod
    def pack_telemetry(app_id: bytes, readings: List[Dict[str, Any]],
                      session_token: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
        """Pack APP_TELEMETRY message"""
        if nonce is None:
            nonce = struct.pack('!Q', int(time.time_ns()))
        
        timestamp_ns = time.time_ns()
        auth = MRACProtocol.compute_auth(session_token or b'', timestamp_ns, nonce) if session_token else b'\x00' * 16
        
        payload = auth + nonce + app_id + struct.pack('!B', len(readings))
        
        for reading in readings:
            metric_id = reading['metric_id']
            value_type = reading['value_type']
            value = reading['value']
            
            payload += struct.pack('!HB', metric_id, value_type)
            
            if value_type == ValueType.INT64:
                payload += struct.pack('!q', value)
            elif value_type == ValueType.UINT64:
                payload += struct.pack('!Q', value)
            elif value_type == ValueType.FLOAT32:
                payload += struct.pack('!f', value)
            elif value_type == ValueType.FLOAT64:
                payload += struct.pack('!d', value)
            elif value_type == ValueType.BOOL:
                payload += struct.pack('!B', 1 if value else 0)
            elif value_type == ValueType.UTF8_LEN16:
                value_bytes = str(value).encode('utf-8')[:16]
                payload += struct.pack('!B', len(value_bytes)) + value_bytes + b'\x00' * (16 - len(value_bytes))
        
        return payload
    
    @staticmethod
    def add_hmac(payload: bytes, key: bytes) -> bytes:
        """Add HMAC to payload"""
        hmac_value = hmac.new(key, payload, hashlib.sha256).digest()
        return payload + struct.pack('!B', len(hmac_value)) + hmac_value
    
    @staticmethod
    def verify_hmac(payload_with_hmac: bytes, key: bytes) -> Tuple[bytes, bool]:
        """Verify HMAC and return payload without HMAC"""
        if len(payload_with_hmac) < 1:
            return payload_with_hmac, False
        
        hmac_len = struct.unpack('!B', payload_with_hmac[-1:])[0]
        if len(payload_with_hmac) < 1 + hmac_len:
            return payload_with_hmac, False
        
        payload = payload_with_hmac[:-1-hmac_len]
        received_hmac = payload_with_hmac[-1-hmac_len:-1]
        expected_hmac = hmac.new(key, payload, hashlib.sha256).digest()
        
        return payload, hmac.compare_digest(received_hmac, expected_hmac)
