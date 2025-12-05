# SSH Compatibility Guide

## Overview

This toolkit is **fully compatible with SSH** and designed to work in terminal environments. All modules support both local execution and remote execution over SSH.

## How It Works

### 1. Rich TUI Over SSH

The Rich TUI framework works **perfectly over SSH** connections:
- Automatically detects terminal capabilities
- Falls back gracefully if advanced features unavailable
- Works with standard SSH terminals (PuTTY, OpenSSH, etc.)
- No special configuration needed

### 2. Remote Command Execution

All command execution functions support SSH:

```python
from modules.utils import execute_cmd, execute_powershell

# Local execution
exit_code, stdout, stderr = execute_cmd("whoami")

# Remote execution via SSH
exit_code, stdout, stderr = execute_cmd(
    "whoami",
    ssh_host="192.168.1.100",
    ssh_user="admin",
    ssh_key="/path/to/key"
)
```

### 3. SSH Session Management

Use the SSH Session Management module (option 15) to:
- Create persistent SSH sessions
- Activate a session (all commands execute on that host)
- Manage multiple SSH connections
- Use stored credentials automatically

## Usage Scenarios

### Scenario 1: Tool Accessed Over SSH

**You SSH into a Windows box and run the tool:**

```bash
# SSH into Windows box
ssh admin@windows-host

# Run the tool
python main.py
```

✅ **Works perfectly** - Rich TUI displays correctly over SSH

### Scenario 2: Execute Commands on Remote Systems

**You run the tool locally but execute commands on remote hosts:**

1. Open SSH Session Management (option 15)
2. Create SSH session to target host
3. Activate the session
4. All subsequent commands execute on remote host

✅ **All modules work** - Commands execute remotely via SSH

### Scenario 3: Multi-Hop SSH

**SSH through jump hosts:**

1. Create SSH session to jump host
2. Activate it
3. Commands execute on jump host
4. From jump host, create another session to final target

✅ **Supported** - SSH sessions can chain

## Command Execution Flow

```
User Action
    ↓
Module Function
    ↓
execute_cmd() / execute_powershell()
    ↓
Check for Active SSH Session?
    ├─ Yes → Execute via SSH
    └─ No  → Execute Locally
    ↓
Return Results
```

## SSH Session Integration

When an SSH session is active:
- All `execute_cmd()` calls automatically use SSH
- All `execute_powershell()` calls automatically use SSH
- No code changes needed in modules
- Transparent remote execution

## Requirements

### For SSH Execution:
- **OpenSSH client** (standard on Linux/Mac, available on Windows 10+)
- **SSH access** to target systems
- **SSH key** or password credentials

### For Rich TUI Over SSH:
- **Terminal emulator** (any SSH client works)
- **Python 3.8+** on the system running the tool
- **Rich library** (auto-installed)

## Best Practices

1. **Use SSH keys** instead of passwords when possible
2. **Store SSH credentials** in Credential Manager
3. **Activate SSH session** before running operations
4. **Test connection** before executing commands
5. **Use LAB_USE=1** to restrict to local networks

## Example Workflow

```bash
# 1. SSH into your Windows host
ssh admin@windows-host

# 2. Run the toolkit
python main.py

# 3. Create SSH session to another host (option 15)
#    - Host: 192.168.1.50
#    - User: admin
#    - Key: ~/.ssh/id_rsa

# 4. Activate the session

# 5. Run lateral movement (option 4)
#    - All commands now execute on 192.168.1.50

# 6. Use network visualization (option 8)
#    - Scans execute on remote host
#    - Results displayed locally
```

## Troubleshooting

### Rich TUI Not Displaying Correctly Over SSH

**Solution:** Rich automatically detects terminal. If issues occur:
- Ensure `TERM` environment variable is set: `export TERM=xterm-256color`
- Use a modern SSH client (OpenSSH 7.0+)

### SSH Commands Failing

**Solution:**
- Check SSH client is installed: `which ssh`
- Test SSH connection manually: `ssh user@host whoami`
- Verify credentials in Credential Manager
- Check SSH key permissions: `chmod 600 ~/.ssh/id_rsa`

### Commands Not Executing Remotely

**Solution:**
- Verify SSH session is activated (option 15)
- Check session details show "Active"
- Test connection using "Test Connection" option

## Technical Details

### SSH Command Execution

Commands are executed using:
```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 -i /path/to/key user@host "command"
```

### Windows Over SSH

For Windows targets:
- PowerShell commands wrapped: `powershell.exe -Command "..."`
- CMD commands executed directly
- Paths use Windows format on remote system

### Credential Integration

SSH sessions can be created from:
- Stored SSH keys (CredentialType.SSH_KEY)
- Stored passwords (CredentialType.PASSWORD)
- Manual entry

All credentials stored in Credential Manager are available for SSH sessions.
