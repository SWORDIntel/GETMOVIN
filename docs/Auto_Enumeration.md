# Auto-Enumeration Mode

## Overview

Auto-Enumeration mode (`AUTO_ENUMERATE = 1`) automatically runs comprehensive enumeration across all modules and generates detailed reports without user interaction.

## Features

- **Automatic Execution**: Runs enumeration commands across all modules
- **Comprehensive Data Collection**: Gathers data from foothold, orientation, identity, network, and persistence modules
- **Target Discovery**: Automatically identifies and tests lateral movement targets
- **Automatic Lateral Movement**: Automatically pivots to accessible targets using LOTL techniques
- **Depth Limiting**: Maximum 3 machines deep to prevent excessive movement
- **LOTL Techniques**: Uses only Living Off The Land binaries (wmic, schtasks, net, etc.)
- **Path Tracking**: Records all lateral movement paths and methods used
- **Multi-Format Reports**: Generates reports in TXT, JSON, and HTML formats
- **Progress Tracking**: Visual progress indicators during enumeration

## Enumeration Coverage

### Foothold Assessment
- Identity and group memberships
- Privileges enumeration
- Host role classification
- Listening ports analysis
- System information

### Local Orientation
- Local and domain groups
- Service account discovery
- Scheduled task analysis
- Security software detection
- Local administrator enumeration

### Identity & Credentials
- Stored credential enumeration (cmdkey)
- Windows Vault credentials
- Domain admin enumeration
- LSASS process identification

### Network Discovery
- Network configuration (ipconfig)
- ARP cache analysis
- Domain network enumeration
- Domain controller discovery
- Network share enumeration

### Lateral Movement Targets
- ARP-based target discovery
- SMB connectivity testing
- WinRM connectivity testing
- Target accessibility mapping

### Persistence Mechanisms
- Recent scheduled tasks
- Running services
- WMI event subscriptions
- Registry run keys (HKCU/HKLM)

### Certificates
- MADCert-generated certificate enumeration
- Certificate inventory

### Automatic Lateral Movement
- **Target Detection**: Automatically identifies accessible targets (SMB/WinRM)
- **LOTL Execution**: Uses only legitimate Windows binaries
- **Recursive Enumeration**: Enumerates from remote machines
- **Depth Control**: Limits to maximum 3 machines deep
- **Path Tracking**: Records all lateral movement paths
- **Method Selection**: Chooses best LOTL method (WMI vs SMB)

## Usage

### Enable Auto-Enumeration

Edit `main.py`:

```python
AUTO_ENUMERATE = 1
```

### Run Tool

```bash
python main.py
```

The tool will automatically:
1. Start enumeration
2. Show progress for each module
3. Collect all data
4. Generate reports
5. Offer to continue to interactive mode

## Report Formats

### Text Report (.txt)
- Human-readable format
- Summary tables
- Detailed findings
- Easy to read and share

### JSON Report (.json)
- Machine-readable format
- Complete data structure
- Easy to parse programmatically
- Suitable for automation

### HTML Report (.html)
- Formatted HTML output
- Tables and structured data
- Suitable for web viewing
- Professional presentation

## Report Contents

Reports include:

1. **Foothold Assessment**
   - Current identity
   - Host role
   - Group memberships
   - Privileges
   - Listening ports

2. **Local Orientation**
   - Local groups and admins
   - Domain groups
   - Service accounts
   - Scheduled tasks
   - Security software

3. **Identity & Credentials**
   - Stored credentials
   - Vault credentials
   - Domain admin memberships
   - LSASS process info

4. **Network Discovery**
   - Local IP addresses
   - ARP targets
   - Domain information
   - Domain controllers
   - Network shares

5. **Lateral Movement Targets**
   - Discovered targets
   - SMB accessibility
   - WinRM accessibility
   - Connectivity status

6. **Persistence Mechanisms**
   - Scheduled tasks
   - Services
   - WMI subscriptions
   - Registry entries

7. **Certificates**
   - Generated certificates
   - Certificate types
   - CA relationships

## Automatic Lateral Movement

When accessible targets are detected, the tool automatically:

1. **Detects Accessible Targets**: Tests SMB and WinRM connectivity
2. **Selects LOTL Method**: Chooses WMI or SMB based on availability
3. **Enumerates Remote Target**: Runs enumeration commands on remote machine
4. **Discovers New Targets**: Finds additional targets from remote machine
5. **Recursive Movement**: Continues to depth 3 maximum
6. **Tracks Paths**: Records all lateral movement paths

### LOTL Techniques Used

- **WMI (wmic.exe)**: Remote process creation, system queries
- **Scheduled Tasks (schtasks.exe)**: Remote task creation and execution
- **SMB (net.exe)**: Share enumeration, file access
- **PowerShell Remoting**: WinRM-based remote execution
- **Service Control (sc.exe)**: Remote service management

### Depth Limiting

- **Maximum Depth**: 3 machines
- **Path Tracking**: Records: Host1 → Host2 → Host3
- **Loop Prevention**: Tracks visited hosts to avoid cycles
- **Per-Depth Limits**: Maximum 3 targets per depth level

### Example Lateral Movement Path

```
Initial Host (192.168.1.10)
  ↓ [WMI] 
Target 1 (192.168.1.20) - Depth 1
  ↓ [SMB/Scheduled Task]
Target 2 (192.168.1.30) - Depth 2
  ↓ [WMI]
Target 3 (192.168.1.40) - Depth 3 (MAX DEPTH)
```

## Integration with LAB_USE

When `LAB_USE = 1`:
- Only enumerates local IP ranges
- Validates targets before testing
- Respects IP restrictions throughout
- Only performs lateral movement to local IPs

## OPSEC Considerations

- **Timing**: Enumeration runs quickly but may generate logs
- **Volume**: Multiple commands executed automatically
- **Patterns**: Uses legitimate Windows binaries
- **Blending**: Commands resemble normal admin activity

## Example Output

```
AUTO-ENUMERATION MODE
Running comprehensive enumeration across all modules...

[cyan]Foothold Assessment...     ████████████████████ 100% 0:00:05
[cyan]Local Orientation...        ████████████████████ 100% 0:00:08
[cyan]Identity Acquisition...     ████████████████████ 100% 0:00:03
[cyan]Network Discovery...        ████████████████████ 100% 0:00:10
[cyan]Lateral Movement Targets... ████████████████████ 100% 0:00:15
[cyan]Persistence Mechanisms...   ████████████████████ 100% 0:00:05
[cyan]Certificate Enumeration... ████████████████████ 100% 0:00:01

Enumeration Summary
─────────────────────────────────────────────────────────
Category          Status    Items Found
─────────────────────────────────────────────────────────
Foothold         Complete  15 groups, 25 ports
Orientation      Complete  Service accounts, tasks
Identity         Complete  3 credential sources
Network          Complete  3 IPs, 12 targets
Lateral Targets  Complete  5 targets
Persistence      Complete  3 mechanisms

Reports saved:
- enumeration_report_20240101_120000.txt
- enumeration_report_20240101_120000.json
- enumeration_report_20240101_120000.html
```

## Best Practices

1. **Run in Lab First**: Test auto-enumeration in lab environment
2. **Review Reports**: Always review generated reports
3. **Combine with Manual**: Use auto-enumeration + manual verification
4. **Export Formats**: Choose appropriate format for your needs
5. **Timing**: Run during appropriate hours to blend in

## Troubleshooting

- **Missing Data**: Some commands may fail due to permissions
- **Timeouts**: Network tests may timeout on unreachable targets
- **Errors**: Check individual module errors in JSON report
- **Performance**: Enumeration may take 1-2 minutes depending on network
