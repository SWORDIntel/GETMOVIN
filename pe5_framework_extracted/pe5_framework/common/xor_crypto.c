/**
 * Common XOR Encryption/Decryption Utilities
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * Provides XOR encryption utilities used by all PE modules.
 */

#include <windows.h>

//=============================================================================
// SINGLE-BYTE XOR
//=============================================================================

/**
 * Simple single-byte XOR encryption/decryption.
 * XOR is its own inverse.
 */
void 
XorCrypt_SingleByte(
    PBYTE   Buffer,
    DWORD   Size,
    BYTE    Key
)
{
    DWORD i;
    
    for (i = 0; i < Size; i++) {
        Buffer[i] ^= Key;
    }
}

/**
 * Optimized 8-byte XOR for larger buffers.
 */
void 
XorCrypt_SingleByte_Fast(
    PBYTE   Buffer,
    DWORD   Size,
    BYTE    Key
)
{
    ULONGLONG key64;
    ULONGLONG* ptr64;
    DWORD chunks, i;
    
    // Expand key to 64 bits
    key64 = Key;
    key64 |= (key64 << 8);
    key64 |= (key64 << 16);
    key64 |= (key64 << 32);
    
    // Process 8-byte chunks
    ptr64 = (ULONGLONG*)Buffer;
    chunks = Size / 8;
    
    for (i = 0; i < chunks; i++) {
        ptr64[i] ^= key64;
    }
    
    // Process remaining bytes
    for (i = chunks * 8; i < Size; i++) {
        Buffer[i] ^= Key;
    }
}

//=============================================================================
// ROTATING XOR
//=============================================================================

/**
 * Rotating XOR encryption.
 * Key changes for each byte: key[i] = (base_key + i) % 256
 */
void 
XorCrypt_Rotating(
    PBYTE   Buffer,
    DWORD   Size,
    BYTE    BaseKey
)
{
    DWORD i;
    BYTE currentKey;
    
    for (i = 0; i < Size; i++) {
        currentKey = (BaseKey + (i & 0xFF)) & 0xFF;
        Buffer[i] ^= currentKey;
    }
}

/**
 * Rotating XOR with custom increment.
 */
void 
XorCrypt_RotatingCustom(
    PBYTE   Buffer,
    DWORD   Size,
    BYTE    BaseKey,
    BYTE    Increment
)
{
    DWORD i;
    BYTE currentKey = BaseKey;
    
    for (i = 0; i < Size; i++) {
        Buffer[i] ^= currentKey;
        currentKey = (currentKey + Increment) & 0xFF;
    }
}

//=============================================================================
// MULTI-BYTE XOR
//=============================================================================

/**
 * Multi-byte XOR key encryption.
 */
void 
XorCrypt_MultiKey(
    PBYTE   Buffer,
    DWORD   Size,
    PBYTE   Key,
    DWORD   KeySize
)
{
    DWORD i;
    
    for (i = 0; i < Size; i++) {
        Buffer[i] ^= Key[i % KeySize];
    }
}

//=============================================================================
// KEY DERIVATION
//=============================================================================

/**
 * Derive key from buffer bytes.
 * Formula: key = buffer[offset1] ^ buffer[offset2]
 */
BYTE 
XorCrypt_DeriveKey(
    PBYTE   Buffer,
    DWORD   Offset1,
    DWORD   Offset2
)
{
    return Buffer[Offset1] ^ Buffer[Offset2];
}

/**
 * Derive key using PE #5 formula.
 * key = header[3] ^ header[7]
 */
BYTE 
XorCrypt_DerivePE5Key(
    PBYTE ModuleBase
)
{
    return ModuleBase[3] ^ ModuleBase[7];
}

//=============================================================================
// VERIFICATION
//=============================================================================

/**
 * Verify decryption by checking known byte patterns.
 */
BOOL 
XorCrypt_Verify(
    PBYTE   Buffer,
    DWORD   Offset,
    PBYTE   Expected,
    DWORD   Length
)
{
    DWORD i;
    
    for (i = 0; i < Length; i++) {
        if (Buffer[Offset + i] != Expected[i]) {
            return FALSE;
        }
    }
    
    return TRUE;
}

/**
 * Find XOR key by known plaintext attack.
 */
BYTE 
XorCrypt_FindKey(
    BYTE    EncryptedByte,
    BYTE    KnownPlaintext
)
{
    return EncryptedByte ^ KnownPlaintext;
}

/**
 * Brute-force key for known plaintext pattern.
 */
BOOL 
XorCrypt_BruteForce(
    PBYTE   EncryptedData,
    DWORD   EncryptedSize,
    PBYTE   KnownPlaintext,
    DWORD   PlaintextSize,
    PBYTE   FoundKey
)
{
    DWORD key;
    DWORD i;
    BOOL match;
    
    for (key = 0; key <= 0xFF; key++) {
        match = TRUE;
        for (i = 0; i < PlaintextSize && i < EncryptedSize; i++) {
            if ((EncryptedData[i] ^ key) != KnownPlaintext[i]) {
                match = FALSE;
                break;
            }
        }
        
        if (match) {
            *FoundKey = (BYTE)key;
            return TRUE;
        }
    }
    
    return FALSE;
}
