#!/usr/bin/env python3
"""
PE5 Payload Encryption Tool

RECONSTRUCTED FROM SECURITY ANALYSIS
Classification: TLP:RED - Security Research Only

This tool encrypts/decrypts payloads using the discovered encryption schemes.
"""

import sys
import os
import struct
from typing import Optional

class XorEncryptor:
    """XOR-based encryption used by PE modules."""
    
    @staticmethod
    def single_byte(data: bytes, key: int) -> bytes:
        """Single-byte XOR."""
        return bytes(b ^ key for b in data)
    
    @staticmethod
    def rotating(data: bytes, base_key: int) -> bytes:
        """Rotating XOR with incrementing key."""
        result = bytearray(len(data))
        for i, b in enumerate(data):
            current_key = (base_key + (i & 0xFF)) & 0xFF
            result[i] = b ^ current_key
        return bytes(result)
    
    @staticmethod
    def derive_key(header: bytes, offset1: int = 3, offset2: int = 7) -> int:
        """Derive key from header bytes."""
        return header[offset1] ^ header[offset2]


class PE5Encryptor:
    """PE #5 specific encryption."""
    
    XOR_KEY = 0xA4
    SYSCALL_OFFSET = 0x2C10
    
    def __init__(self):
        self.key = self.XOR_KEY
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt payload for PE #5."""
        return XorEncryptor.single_byte(plaintext, self.key)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt PE #5 payload."""
        return XorEncryptor.single_byte(ciphertext, self.key)
    
    def verify(self, encrypted: bytes) -> bool:
        """Verify encryption by checking SYSCALL location."""
        if len(encrypted) <= self.SYSCALL_OFFSET + 1:
            return False
        
        decrypted = self.decrypt(encrypted)
        syscall = decrypted[self.SYSCALL_OFFSET:self.SYSCALL_OFFSET + 2]
        return syscall == b'\x0F\x05'


class PE4Encryptor:
    """PE #4 specific encryption."""
    
    XOR_KEY = 0x55
    
    def encrypt(self, plaintext: bytes) -> bytes:
        return XorEncryptor.single_byte(plaintext, self.XOR_KEY)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        return XorEncryptor.single_byte(ciphertext, self.XOR_KEY)


class PE1Encryptor:
    """PE #1 specific encryption (rotating XOR)."""
    
    BASE_KEY = 0xDF
    
    def encrypt(self, plaintext: bytes) -> bytes:
        return XorEncryptor.rotating(plaintext, self.BASE_KEY)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        # Rotating XOR is its own inverse
        return XorEncryptor.rotating(ciphertext, self.BASE_KEY)


class PE3Encryptor:
    """PE #3 container encryption (multi-layer)."""
    
    OUTER_KEY = 0xC7
    
    def encrypt_layer1(self, plaintext: bytes) -> bytes:
        """Encrypt outer layer."""
        return XorEncryptor.rotating(plaintext, self.OUTER_KEY)
    
    def decrypt_layer1(self, ciphertext: bytes) -> bytes:
        """Decrypt outer layer."""
        return XorEncryptor.rotating(ciphertext, self.OUTER_KEY)


def get_encryptor(module: str):
    """Get appropriate encryptor for module."""
    encryptors = {
        'PE1': PE1Encryptor(),
        'PE3': PE3Encryptor(),
        'PE4': PE4Encryptor(),
        'PE5': PE5Encryptor(),
    }
    return encryptors.get(module.upper())


def print_stats(data: bytes, name: str):
    """Print encryption statistics."""
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / len(data)
            entropy -= p * (p and __import__('math').log2(p))
    
    print(f"\n{name} Statistics:")
    print(f"  Size: {len(data):,} bytes")
    print(f"  Entropy: {entropy:.4f} bits/byte ({entropy/8*100:.2f}%)")
    
    # Top 5 most common bytes
    top5 = sorted(enumerate(byte_counts), key=lambda x: x[1], reverse=True)[:5]
    print(f"  Most common bytes:")
    for byte_val, count in top5:
        print(f"    0x{byte_val:02X}: {count} ({count/len(data)*100:.2f}%)")


def main():
    if len(sys.argv) < 4:
        print("Usage: python encryptor.py <encrypt|decrypt> <module> <input_file> [output_file]")
        print("\nModules: PE1, PE3, PE4, PE5")
        print("\nExamples:")
        print("  python encryptor.py encrypt PE5 payload.bin payload_encrypted.bin")
        print("  python encryptor.py decrypt PE5 pe5_encrypted.bin pe5_decrypted.bin")
        return
    
    operation = sys.argv[1].lower()
    module = sys.argv[2].upper()
    input_file = sys.argv[3]
    output_file = sys.argv[4] if len(sys.argv) > 4 else None
    
    # Read input
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading input file: {e}")
        return
    
    # Get encryptor
    encryptor = get_encryptor(module)
    if encryptor is None:
        print(f"Unknown module: {module}")
        return
    
    print(f"\n{'='*60}")
    print(f"{operation.upper()} {module}")
    print(f"{'='*60}")
    
    print_stats(data, "Input")
    
    # Process
    if operation == 'encrypt':
        result = encryptor.encrypt(data)
    elif operation == 'decrypt':
        result = encryptor.decrypt(data)
    else:
        print(f"Unknown operation: {operation}")
        return
    
    print_stats(result, "Output")
    
    # Verify (for PE5)
    if module == 'PE5' and hasattr(encryptor, 'verify'):
        if operation == 'encrypt':
            verified = encryptor.verify(result)
        else:
            # For decryption, check if we got valid SYSCALL
            if len(result) > 0x2C11:
                verified = (result[0x2C10:0x2C12] == b'\x0F\x05')
            else:
                verified = False
        
        print(f"\nVerification: {'✓ PASSED' if verified else '✗ FAILED'}")
    
    # Write output
    if output_file:
        with open(output_file, 'wb') as f:
            f.write(result)
        print(f"\nOutput written to: {output_file}")
    else:
        print(f"\nFirst 32 bytes of output: {result[:32].hex()}")


if __name__ == "__main__":
    main()
