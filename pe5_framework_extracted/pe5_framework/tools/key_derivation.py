#!/usr/bin/env python3
"""
PE5 Encryption Key Derivation & Decryption Tool

RECONSTRUCTED FROM SECURITY ANALYSIS
Classification: TLP:RED - Security Research Only

This tool derives and verifies encryption keys for all PE modules
based on the forensic analysis findings.
"""

import sys
import struct
from typing import Optional, Tuple, List

# PE Module encryption keys (from analysis)
PE_KEYS = {
    'PE1': {'type': 'rotating', 'base': 0xDF},
    'PE2': {'type': 'aes256', 'dynamic': True},
    'PE3': {'type': 'rotating', 'base': 0xC7},
    'PE4': {'type': 'xor', 'key': 0x55},
    'PE5': {'type': 'xor', 'key': 0xA4, 'derive': True},
}

# Known encrypted/decrypted byte pairs for verification
KNOWN_PATTERNS = {
    'PE5': {
        # SYSCALL instruction at offset 0x2C10
        0x2C10: (0xAB, 0x0F),  # encrypted -> decrypted
        0x2C11: (0xA1, 0x05),
    }
}


def derive_pe5_key(header_bytes: bytes) -> int:
    """
    Derive PE #5 XOR key from header bytes.
    
    Formula: key = header[3] ^ header[7]
    Expected: 0x35 ^ 0x91 = 0xA4
    """
    if len(header_bytes) < 8:
        raise ValueError("Need at least 8 bytes of header")
    
    byte1 = header_bytes[3]
    byte2 = header_bytes[7]
    key = byte1 ^ byte2
    
    print(f"Key derivation:")
    print(f"  header[3] = 0x{byte1:02X}")
    print(f"  header[7] = 0x{byte2:02X}")
    print(f"  key = 0x{byte1:02X} ^ 0x{byte2:02X} = 0x{key:02X}")
    
    return key


def xor_decrypt(data: bytes, key: int) -> bytes:
    """Single-byte XOR decryption."""
    return bytes(b ^ key for b in data)


def xor_decrypt_rotating(data: bytes, base_key: int) -> bytes:
    """Rotating XOR decryption."""
    result = bytearray(len(data))
    for i, b in enumerate(data):
        current_key = (base_key + (i & 0xFF)) & 0xFF
        result[i] = b ^ current_key
    return bytes(result)


def verify_decryption(encrypted: bytes, decrypted: bytes, 
                      patterns: dict) -> Tuple[bool, List[str]]:
    """Verify decryption using known byte patterns."""
    results = []
    all_match = True
    
    for offset, (enc_expected, dec_expected) in patterns.items():
        if offset >= len(encrypted):
            continue
            
        enc_byte = encrypted[offset]
        dec_byte = decrypted[offset]
        
        enc_match = (enc_byte == enc_expected)
        dec_match = (dec_byte == dec_expected)
        
        status = "✓" if (enc_match and dec_match) else "✗"
        results.append(
            f"  {status} Offset 0x{offset:04X}: "
            f"encrypted=0x{enc_byte:02X} (expected 0x{enc_expected:02X}), "
            f"decrypted=0x{dec_byte:02X} (expected 0x{dec_expected:02X})"
        )
        
        if not (enc_match and dec_match):
            all_match = False
    
    return all_match, results


def brute_force_key(encrypted_byte: int, 
                    expected_decrypted: int) -> int:
    """Find XOR key by known plaintext attack."""
    return encrypted_byte ^ expected_decrypted


def analyze_pe5(data: bytes) -> None:
    """Analyze PE #5 binary."""
    print("\n" + "="*60)
    print("PE #5 ANALYSIS")
    print("="*60)
    
    # Derive key
    key = derive_pe5_key(data[:16])
    
    # Verify against expected
    if key == PE_KEYS['PE5']['key']:
        print(f"\n✓ Key matches expected value: 0x{key:02X}")
    else:
        print(f"\n✗ Key mismatch! Got 0x{key:02X}, expected 0x{PE_KEYS['PE5']['key']:02X}")
    
    # Decrypt
    decrypted = xor_decrypt(data, key)
    
    # Verify patterns
    if 'PE5' in KNOWN_PATTERNS:
        success, results = verify_decryption(data, decrypted, KNOWN_PATTERNS['PE5'])
        print("\nPattern verification:")
        for r in results:
            print(r)
        
        if success:
            print("\n✓ All patterns verified - decryption successful!")
        else:
            print("\n✗ Pattern verification failed")
    
    # Check for SYSCALL instruction
    if len(decrypted) > 0x2C11:
        syscall = decrypted[0x2C10:0x2C12]
        if syscall == b'\x0F\x05':
            print(f"\n✓ SYSCALL instruction found at offset 0x2C10")
        else:
            print(f"\n✗ Expected SYSCALL (0F 05), got {syscall.hex()}")


def analyze_pe4(data: bytes) -> None:
    """Analyze PE #4 binary."""
    print("\n" + "="*60)
    print("PE #4 ANALYSIS (Stub)")
    print("="*60)
    
    key = PE_KEYS['PE4']['key']
    print(f"Key: 0x{key:02X} (hardcoded)")
    
    decrypted = xor_decrypt(data, key)
    
    # Check for MZ header after decryption
    if decrypted[:2] == b'MZ':
        print("✓ MZ header found after decryption")
    else:
        print(f"✗ Expected MZ header, got {decrypted[:2].hex()}")


def analyze_pe1(data: bytes) -> None:
    """Analyze PE #1 binary."""
    print("\n" + "="*60)
    print("PE #1 ANALYSIS (Loader)")
    print("="*60)
    
    base_key = PE_KEYS['PE1']['base']
    print(f"Base key: 0x{base_key:02X} (rotating)")
    
    decrypted = xor_decrypt_rotating(data, base_key)
    
    # Check for MZ header
    if decrypted[:2] == b'MZ':
        print("✓ MZ header found after decryption")
    else:
        print(f"First bytes after decryption: {decrypted[:16].hex()}")


def main():
    """Main entry point."""
    print("="*60)
    print("PE5 EXPLOIT FRAMEWORK - KEY DERIVATION TOOL")
    print("="*60)
    
    if len(sys.argv) < 2:
        print("\nUsage: python key_derivation.py <pe_file> [module_type]")
        print("\nModule types: PE1, PE2, PE3, PE4, PE5")
        print("\nExample with PE #5 header bytes:")
        
        # Demo with PE #5 header from analysis
        pe5_header = bytes([
            0xC1, 0xBD, 0x87, 0x35,  # DWORD 1
            0x1E, 0x8C, 0xA6, 0x91,  # DWORD 2
            0xF7, 0x62, 0xC0, 0xB5,
            0x75, 0x24, 0x32, 0x25
        ])
        
        print(f"\nPE #5 header: {pe5_header.hex()}")
        key = derive_pe5_key(pe5_header)
        print(f"\nDerived key: 0x{key:02X}")
        
        # Verify with SYSCALL bytes
        encrypted_syscall = bytes([0xAB, 0xA1])
        decrypted_syscall = xor_decrypt(encrypted_syscall, key)
        print(f"\nSYSCALL verification:")
        print(f"  Encrypted: {encrypted_syscall.hex()}")
        print(f"  Decrypted: {decrypted_syscall.hex()}")
        print(f"  Expected:  0f05")
        
        if decrypted_syscall == b'\x0F\x05':
            print(f"\n✓ SUCCESS! Key 0x{key:02X} is correct")
        else:
            print(f"\n✗ FAILED! Decryption mismatch")
        
        return
    
    # Read file
    try:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Determine module type
    module = sys.argv[2].upper() if len(sys.argv) > 2 else 'PE5'
    
    if module == 'PE5':
        analyze_pe5(data)
    elif module == 'PE4':
        analyze_pe4(data)
    elif module == 'PE1':
        analyze_pe1(data)
    else:
        print(f"Unknown module type: {module}")


if __name__ == "__main__":
    main()
