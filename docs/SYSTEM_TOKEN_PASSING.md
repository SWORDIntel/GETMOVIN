# SYSTEM Token Passing Implementation

## Overview

This document describes how SYSTEM token acquisition and passing is implemented throughout the LLM agent system to ensure that once a SYSTEM token is acquired, it is passed to every part of the program and any processes created by them.

## Architecture

### Token State Management

The SYSTEM token state is tracked at multiple levels:

1. **CodeGenerator Level** (`modules/llm_agent.py`):
   - `system_token_acquired`: Boolean flag indicating if SYSTEM token is currently available
   - `system_token_handle`: Stores SYSTEM token handle for reuse (future enhancement)
   - `token_pid`: PID of process from which token was acquired

2. **LLMAgentServer Level** (`modules/llm_agent.py`):
   - `system_token_acquired`: Server-level tracking of token state
   - Synchronized with CodeGenerator state

3. **Session Data** (`session_data` dictionary):
   - `SYSTEM_TOKEN_ACQUIRED`: Persistent flag stored in session
   - `SYSTEM_TOKEN_SID`: System SID (S-1-5-18) for verification

### Token Acquisition Flow

1. **Initial Check**: On server initialization, `check_system_token_pe5()` is called
2. **Acquisition**: If token not present and `system_privilege=True`, `acquire_system_token()` attempts token manipulation
3. **Verification**: Token is verified using PE5 method (checks SID S-1-5-18)
4. **State Update**: All state flags are updated across CodeGenerator, LLMAgentServer, and session_data

### Token Passing Mechanisms

#### 1. Automatic Inheritance (Windows Default Behavior)

On Windows, child processes automatically inherit the parent process's token. This means:
- If the Python process has SYSTEM token, all subprocesses created via `subprocess.run()`, `subprocess.Popen()`, or `Start-Process` will inherit it
- No explicit token passing is needed for standard subprocess creation

#### 2. Explicit Token Verification Before Execution

Before executing any code, the system:
1. Calls `ensure_system_token()` to verify token is available
2. If token is lost, attempts re-acquisition
3. Only proceeds with execution if token is confirmed available

#### 3. Code Generation Templates

All generated code includes:

**Python:**
- `pe5_check_system_token()`: Verifies SYSTEM token using PE5 method
- `create_process_with_system_token()`: Helper function to create subprocesses with explicit token verification
- Environment variable `SYSTEM_TOKEN_ACQUIRED=1` set before execution

**PowerShell:**
- `Test-PE5SystemToken`: Verifies SYSTEM token using PE5 method
- `Start-ProcessWithSystemToken`: Helper function to start processes with token verification
- Environment variable `$env:SYSTEM_TOKEN_ACQUIRED = '1'` set before execution

**C/C++:**
- `CheckSystemTokenPE5()`: Verifies SYSTEM token by checking SID
- `CreateProcessWithSystemToken()`: Helper function to create processes with token verification
- `SetEnvironmentVariableA("SYSTEM_TOKEN_ACQUIRED", "1")` called before execution

**Batch:**
- PowerShell verification command embedded in script
- Environment variable `SYSTEM_TOKEN_ACQUIRED=1` set
- Comments explaining token inheritance for child processes

#### 4. Execution Wrappers

When executing generated code with SYSTEM privilege:

**Python Execution:**
```python
# Wrapped in PowerShell to ensure SYSTEM token inheritance
ps_wrapper = """
$token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = ($token.User.Value -eq 'S-1-5-18')
if (-not $isSystem) {
    Write-Error 'SYSTEM token not available'
    exit 1
}
$proc = Start-Process -FilePath 'python.exe' `
    -ArgumentList '<script>' `
    -NoNewWindow -Wait -PassThru
exit $proc.ExitCode
"""
```

**PowerShell Execution:**
```powershell
# Token verification before script execution
$token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = ($token.User.Value -eq 'S-1-5-18')
if (-not $isSystem) {
    Write-Error 'SYSTEM token not available'
    exit 1
}
& '<script>' <args>
```

**Batch Execution:**
```powershell
# Wrapped in PowerShell for token verification
$proc = Start-Process -FilePath 'cmd.exe' `
    -ArgumentList '/c', '<batch_script>' `
    -NoNewWindow -Wait -PassThru
exit $proc.ExitCode
```

**C/C++ Execution:**
```powershell
# Binary execution with token verification
$proc = Start-Process -FilePath '<binary.exe>' `
    -ArgumentList <args> `
    -NoNewWindow -Wait -PassThru
exit $proc.ExitCode
```

### Token Persistence

The SYSTEM token state is maintained through:

1. **Session Data**: Persisted across server restarts (if session data is saved)
2. **Environment Variables**: Set in generated code to indicate token availability
3. **State Flags**: Tracked in memory for runtime verification

### Token Re-acquisition

If token is lost (detected via `check_system_token_pe5()`):
1. `ensure_system_token()` detects token loss
2. Resets `system_token_acquired` flag
3. Attempts re-acquisition via `acquire_system_token()`
4. Updates all state flags if successful

## Implementation Details

### Key Functions

#### `check_system_token_pe5()`
- Uses PE5 verification method (checks SID S-1-5-18)
- Verifies protected resource access (HKLM, LSASS)
- Updates internal state flags if SYSTEM token detected
- Returns detailed status dictionary

#### `acquire_system_token()`
- Attempts token manipulation via winlogon.exe process
- Uses Windows API calls: `OpenProcessToken`, `DuplicateTokenEx`, `SetThreadToken`
- Verifies acquisition via `check_system_token_pe5()`
- Updates all state flags on success

#### `ensure_system_token()`
- Checks if token is already acquired
- Verifies token is still valid
- Attempts acquisition if needed
- Returns True if token is available

#### `pass_system_token_to_process()`
- Verifies token is available
- Ensures child processes will inherit token
- Used for explicit token passing (though inheritance is automatic)

### Command Execution Flow

1. **Command Received**: `_handle_app_command()` receives command
2. **Token Check**: `ensure_system_token()` called if `system_privilege=True`
3. **Code Generation**: Code generated with token verification and passing helpers
4. **Execution**: Code executed with PowerShell wrapper ensuring token inheritance
5. **Verification**: Token verified before and during execution

### Generated Code Structure

All generated code follows this pattern:

1. **Imports/Includes**: Required libraries for token manipulation
2. **Token Check Function**: PE5-based verification function
3. **Escalation Function**: Token manipulation code (if needed)
4. **Process Creation Helper**: Function to create subprocesses with token verification
5. **Main Function**:
   - Check SYSTEM token
   - Acquire if needed
   - Set environment variables
   - Execute functionality
   - Note: Subprocesses inherit token automatically

## Usage Examples

### Python Code Generation

```python
spec = {
    'language': 'python',
    'description': 'Execute system command',
    'system_privilege': True
}
code, path = code_generator.generate_code(spec)
# Generated code includes:
# - pe5_check_system_token()
# - create_process_with_system_token()
# - Environment variable setting
```

### PowerShell Code Generation

```python
spec = {
    'language': 'powershell',
    'description': 'Run administrative task',
    'system_privilege': True,
    'exploit_type': 'token_manipulation'
}
code, path = code_generator.generate_code(spec)
# Generated code includes:
# - Test-PE5SystemToken
# - Invoke-TokenManipulation
# - Start-ProcessWithSystemToken
```

### C/C++ Code Generation

```python
spec = {
    'language': 'c',
    'description': 'System-level operation',
    'system_privilege': True
}
code, path = code_generator.generate_code(spec)
# Generated code includes:
# - CheckSystemTokenPE5()
# - EscalateToSystem()
# - CreateProcessWithSystemToken()
```

## Security Considerations

1. **Token Verification**: All code verifies token before execution
2. **State Tracking**: Multiple layers of state tracking prevent token loss
3. **Re-acquisition**: Automatic re-acquisition if token is lost
4. **Inheritance**: Relies on Windows default behavior (secure and reliable)
5. **Environment Variables**: Used for signaling, not security (token is the security boundary)

## Future Enhancements

1. **Token Handle Storage**: Store actual token handle for explicit passing
2. **Token Duplication**: Explicit token duplication for specific processes
3. **Token Refresh**: Periodic token refresh to prevent expiration
4. **Multi-Process Coordination**: Coordinate token state across multiple processes
5. **Token Pooling**: Manage multiple SYSTEM tokens for different operations

## Troubleshooting

### Token Not Acquired

- Check if winlogon.exe process is accessible
- Verify SeDebugPrivilege is enabled
- Check process permissions

### Token Lost During Execution

- `ensure_system_token()` will detect and attempt re-acquisition
- Check logs for token verification failures
- Verify parent process still has SYSTEM token

### Child Process Doesn't Have Token

- Verify parent process has SYSTEM token (`check_system_token_pe5()`)
- Check if child process is created with `bInheritHandles=TRUE` (default)
- Verify no explicit token replacement in child process

## References

- PE5 Framework: `modules/pe5_system_escalation.py`
- PE5 Utils: `modules/pe5_utils.py`
- Windows Token Manipulation: Windows API documentation
- Process Token Inheritance: Windows Process Creation documentation
