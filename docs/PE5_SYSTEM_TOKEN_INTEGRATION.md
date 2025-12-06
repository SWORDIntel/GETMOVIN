# PE5 SYSTEM Token Check Integration

## Overview

The LLM Agent module now uses the existing PE5 SYSTEM token verification method from `pe5_system_escalation.py` instead of creating a new implementation.

## Integration Points

### 1. CodeGenerator Class

The `CodeGenerator` class now includes:
- `check_system_token_pe5()` method that uses the existing PE5 verification approach
- Integration with `PE5Utils` and `PE5SystemEscalationModule` for PE5 operations
- Automatic SYSTEM token check before code execution when SYSTEM privilege is requested

### 2. LLMAgentServer Class

The `LLMAgentServer` now:
- Initializes `PE5SystemEscalationModule` on startup
- Checks SYSTEM token status on initialization if SYSTEM privilege is enabled
- Uses existing PE5 verification methods for token checking

### 3. Code Generation

Generated code includes PE5 SYSTEM token check functions:
- **Python**: `pe5_check_system_token()` - Uses PowerShell subprocess to check SYSTEM SID
- **PowerShell**: `Test-PE5SystemToken` - Uses same verification method as `_verify_privileges()`
- **C/C++**: `CheckSystemTokenPE5()` - Checks for SYSTEM SID (S-1-5-18)

## PE5 Verification Method

The existing PE5 verification method (from `pe5_system_escalation.py`) checks:

1. **User SID Check**: Verifies if `$token.User.Value -eq 'S-1-5-18'` (SYSTEM)
2. **Administrator Check**: Checks if user is administrator
3. **Protected Resource Access**: Tries to access `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
4. **LSASS Access**: Checks if can access LSASS process (SeDebugPrivilege)
5. **whoami Verification**: Uses `whoami /user` and `whoami /priv` for confirmation

## Usage

### In CodeGenerator

```python
generator = CodeGenerator(console, session_data, system_privilege=True)
token_status = generator.check_system_token_pe5()

if token_status.get('has_system'):
    print("SYSTEM token verified")
else:
    print("SYSTEM token not detected")
```

### In LLMAgentServer

```python
server = LLMAgentServer(console, session_data, system_privilege=True)
# Automatically checks SYSTEM token on initialization

# Manual check
token_status = server.check_system_token()
```

### In Generated Code

Generated code automatically includes PE5 token checks:

**Python:**
```python
if not pe5_check_system_token():
    print('Warning: SYSTEM token not detected')
    if not escalate_privileges():
        return 1
```

**PowerShell:**
```powershell
if (-not (Test-PE5SystemToken)) {
    Write-Warning 'SYSTEM token not detected'
    if (-not (Invoke-TokenManipulation)) {
        return 1
    }
}
```

**C:**
```c
if (!CheckSystemTokenPE5()) {
    printf("SYSTEM token not detected\n");
    if (!EscalateToSystem()) {
        return 1;
    }
}
```

## Benefits

1. **Consistency**: Uses the same verification method across the codebase
2. **Reliability**: Leverages proven PE5 verification approach
3. **Maintainability**: Single source of truth for SYSTEM token checking
4. **Integration**: Works seamlessly with existing PE5 framework

## Files Modified

- `modules/llm_agent.py`: Integrated PE5 verification methods
- Uses `PE5Utils` and `PE5SystemEscalationModule` from existing modules

## Related Modules

- `modules/pe5_utils.py`: PE5 framework utilities
- `modules/pe5_system_escalation.py`: PE5 SYSTEM escalation module with verification
- `pe5_framework_extracted/pe5_framework/`: PE5 framework source code
