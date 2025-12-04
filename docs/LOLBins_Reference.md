# LOLBins and Beyond Reference

## Overview

The LOLBins (Living Off The Land Binaries) Reference module provides a comprehensive database of legitimate Windows binaries that can be used for lateral movement, execution, persistence, and other offensive operations.

Reference: https://github.com/sheimo/awesome-lolbins-and-beyond

## Categories

### Execution
Binaries used for code execution and script running:
- `mshta.exe` - Execute HTA files
- `rundll32.exe` - Execute DLL functions
- `regsvr32.exe` - Register/execute DLLs
- `wmic.exe` - WMI command execution
- `powershell.exe` - PowerShell script execution
- `cmd.exe` - Command prompt
- `cscript.exe` / `wscript.exe` - Script execution

### Lateral Movement
Binaries for remote execution and lateral movement:
- `psexec.exe` - Remote execution
- `sc.exe` - Remote service management
- `wmic.exe` - WMI remote execution
- `winrs.exe` - Windows Remote Shell
- `schtasks.exe` - Remote scheduled tasks

### Credential Access
Binaries for credential extraction and access:
- `mimikatz.exe` - Credential dumping
- `rundll32.exe` - LSASS dumping (comsvcs.dll)
- `taskmgr.exe` - Process dumping
- `procdump.exe` - Process memory dumping
- `vaultcmd.exe` - Windows Vault access
- `cmdkey.exe` - Credential management

### Discovery
Binaries for system and network discovery:
- `net.exe` - Network and account discovery
- `nltest.exe` - Domain trust testing
- `systeminfo.exe` - System information
- `whoami.exe` - User identity
- `quser.exe` / `qwinsta.exe` - Session discovery
- `arp.exe` / `ipconfig.exe` - Network discovery
- `nslookup.exe` - DNS queries

### Persistence
Binaries for maintaining persistence:
- `schtasks.exe` - Scheduled tasks
- `sc.exe` - Service creation
- `reg.exe` - Registry modification
- `wmic.exe` - WMI event subscriptions

### Defense Evasion
Binaries for bypassing defenses:
- `certutil.exe` - File download/encoding
- `bitsadmin.exe` - Background file transfer
- `curl.exe` / `wget.exe` - File download
- `findstr.exe` - File search
- `wevtutil.exe` - Event log manipulation
- `bcdedit.exe` - Boot configuration

### Collection
Binaries for data collection:
- `robocopy.exe` - Robust file copy
- `xcopy.exe` - Extended copy
- `copy.exe` - File copy

## Usage

### Search LOLBins
```
Module 9 → Option 1
Search query: wmic
```

### Browse by Category
```
Module 9 → Option 2
Category: Lateral Movement
```

### View Examples
Each LOLBin includes:
- Description
- MITRE ATT&CK technique mappings
- Use cases
- Command examples

## MADCert Integration

The Defense Evasion Builder integrates seamlessly with the MADCert module (Module 8):

### Certificate-Based File Signing

1. **Generate Code Signing Certificate** (Module 8):
   - Create CA certificate
   - Generate code signing certificate with digitalSignature and codeSigning key usage

2. **Sign Files** (Module 9 → Option 10 → "Sign File with Certificate"):
   - Automatically detects MADCert-generated certificates
   - Select certificate from list
   - Choose signing method (signtool, certutil, PowerShell, osslsigncode)
   - Generate signing commands with verification

### Workflow Example

```
1. Module 8 → Generate CA → "MyCA"
2. Module 8 → Generate Code Signing Certificate → "CodeSigner"
3. Module 9 → Option 10 → "Sign File with Certificate"
4. Select "CodeSigner" certificate
5. Choose file to sign: malicious.dll
6. Generate: signtool.exe sign /f cert.pfx malicious.dll
7. Use signed DLL for DLL sideloading attacks
```

### Signing Methods

- **signtool.exe**: Windows native signing tool
- **certutil.exe**: Certificate utility signing
- **PowerShell**: Set-AuthenticodeSignature cmdlet
- **osslsigncode**: Open source alternative

### Benefits

- **Bypass Application Whitelisting**: Signed binaries are trusted
- **DLL Sideloading**: Sign malicious DLLs for sideloading attacks
- **Legitimate Appearance**: Signed code appears legitimate
- **OPSEC**: Use legitimate signing tools and certificates

## Integration with TTPs

### Execution TTPs
- T1059.001 - PowerShell
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- T1059.005 - Visual Basic
- T1218.005 - Signed Binary Proxy Execution: mshta
- T1218.010 - Signed Binary Proxy Execution: regsvr32
- T1218.011 - Signed Binary Proxy Execution: rundll32

### Lateral Movement TTPs
- T1021.002 - Remote Services: SMB/Windows Admin Shares
- T1021.006 - Remote Services: Windows Remote Management
- T1047 - Windows Management Instrumentation
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1569.002 - System Services: Service Execution

### Credential Access TTPs
- T1003.001 - OS Credential Dumping: LSASS Memory
- T1555.003 - Credentials from Password Stores: Credentials from Web Browsers

### Discovery TTPs
- T1018 - Remote System Discovery
- T1033 - System Owner/User Discovery
- T1082 - System Information Discovery
- T1087 - Account Discovery
- T1135 - Network Share Discovery
- T1482 - Domain Trust Discovery
- T1590.002 - Gather Victim Network Information: DNS

### Persistence TTPs
- T1053.003 - Scheduled Task/Job: Cron
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1543.003 - Create/Modify System Process: Windows Service
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

### Defense Evasion TTPs
- T1027 - Obfuscated Files or Information
- T1070.001 - Indicator Removal: Clear Windows Event Logs
- T1105 - Ingress Tool Transfer
- T1562.009 - Impair Defenses: Safe Mode Boot

### Collection TTPs
- T1030 - Data Transfer Size Limits

## OPSEC Benefits

Using LOLBins provides several OPSEC advantages:
- **Legitimate binaries**: Already present on Windows systems
- **Less suspicious**: Normal administrative tools
- **No file drops**: Use existing system binaries
- **Blend in**: Match legitimate admin activity patterns
- **Whitelisting bypass**: Legitimate binaries often whitelisted

## Best Practices

1. **Use appropriate binaries** for each task
2. **Match existing patterns** in the environment
3. **Combine multiple LOLBins** for complex operations
4. **Use built-in capabilities** before external tools
5. **Document techniques** used for consistency

## References

- Awesome LOLBins: https://github.com/sheimo/awesome-lolbins-and-beyond
- MITRE ATT&CK: https://attack.mitre.org/
- LOLBAS Project: https://lolbas-project.github.io/
