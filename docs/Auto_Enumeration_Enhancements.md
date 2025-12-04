# Auto-Enumeration Enhancements

## Overview

The auto-enumeration module has been significantly enhanced to leverage all available tooling when the enumeration switch is triggered (`AUTO_ENUMERATE=1`).

## New Enumeration Sections

### 1. PE5 Privilege Escalation Enumeration

**New Section**: `privilege_escalation`

**Checks Performed:**
- Current privilege status (SYSTEM, Admin, Elevated)
- Windows version detection for PE5 compatibility
- PE5 framework availability check
- PE5 framework compilation status
- Windows kernel token offsets detection
- Print Spooler service status (CVE-2020-1337)
- UAC status (CVE-2019-1388)
- SMBv3 configuration (CVE-2020-0796)
- Token manipulation opportunities
- SeDebugPrivilege availability

**Data Collected:**
```json
{
  "privilege_escalation": {
    "current_privileges": {
      "IsSystem": false,
      "IsAdmin": true,
      "HasElevatedPrivileges": true,
      "UserSID": "S-1-5-21-...",
      "UserName": "DOMAIN\\user"
    },
    "pe5_available": true,
    "pe5_framework_status": {
      "path": "pe5_framework_extracted/pe5_framework",
      "exists": true,
      "compiled": true,
      "binaries": ["pe5_exploit.dll", "pe5_exploit.exe"]
    },
    "windows_version": {
      "info": "Microsoft Windows 10 Enterprise",
      "pe5_compatible": true,
      "token_offset": "0x4B8"
    },
    "pe_techniques": {
      "print_spooler": {...},
      "uac": {...},
      "smbv3": {...},
      "token_manipulation": {...}
    },
    "escalation_attempted": false,
    "escalation_successful": false
  }
}
```

### 2. Relay Connectivity Enumeration

**New Section**: `relay_connectivity`

**Checks Performed:**
- Relay client configuration detection
- Configuration file location and parsing
- Relay endpoint configuration (host, port, TLS, Tor)
- Tor availability check
- Tor service status
- SOCKS5 proxy accessibility
- Transport method detection (Direct, Tor, .onion)

**Data Collected:**
```json
{
  "relay_connectivity": {
    "relay_configured": true,
    "config_path": "~/.config/ai-relay/client.yaml",
    "config": {
      "relay_host": "relay.example.com",
      "relay_port": 8889,
      "use_tls": true,
      "use_tor": false
    },
    "connectivity_tests": {
      "host": "relay.example.com",
      "port": 8889,
      "tls_enabled": true,
      "tor_enabled": false,
      "transport": "Direct"
    },
    "tor_available": false,
    "tor_status": {
      "tor_installed": false,
      "tor_running": false,
      "socks5_proxy": null,
      "proxy_accessible": false
    }
  }
}
```

### 3. Tooling Integration Enumeration

**New Section**: `tooling_integration`

**Checks Performed:**
- Module availability check (PE5, Relay Client, LogHunter, MADCert, LOLBins, Moonwalk)
- PE5 utilities availability
- Relay client availability and configuration
- Tools used during enumeration tracking
- Integration summary generation

**Data Collected:**
```json
{
  "tooling_integration": {
    "modules_available": {
      "PE5": true,
      "Relay Client": true,
      "LogHunter": true,
      "MADCert": true,
      "LOLBins": true,
      "Moonwalk": true
    },
    "integration_status": {
      "pe5_utils": {
        "available": true,
        "techniques": ["Direct Privilege Modification", "Token Stealing", ...]
      },
      "relay_client": {
        "available": true,
        "config_loaded": true,
        "relay_host": "relay.example.com"
      }
    },
    "tools_used": {
      "lolbins": ["wmic", "schtasks", "net view", ...],
      "powershell_commands": 45,
      "cmd_commands": 32,
      "wmi_commands": 12
    },
    "integration_summary": {
      "total_modules": 6,
      "available_modules": 6,
      "pe5_ready": true,
      "relay_ready": true,
      "loghunter_ready": true,
      "moonwalk_ready": true
    }
  }
}
```

## Enhanced Foothold Enumeration

**Added:**
- SYSTEM privilege check
- Detailed privilege status (IsSystem, IsAdmin, HasElevatedPrivileges)
- User SID extraction

## Enhanced Report Generation

**New Report Sections:**
1. **PRIVILEGE ESCALATION (PE5)** - Complete PE5 status and opportunities
2. **RELAY CONNECTIVITY** - Relay configuration and connectivity status
3. **TOOLING INTEGRATION** - All available modules and tools
4. **ENUMERATION SUMMARY** - High-level summary with key metrics

**Report Formats:**
- Text report (enhanced with new sections)
- JSON report (includes all new data)
- HTML report (enhanced with new sections)

## Usage

### Automatic Enumeration

When `AUTO_ENUMERATE=1` is set in `main.py` or via environment variable:

```bash
export AUTO_ENUMERATE=1
export AUTO_ENUMERATE_DEPTH=3
python main.py
```

The enumeration will automatically:
1. Check all foothold information (enhanced with SYSTEM check)
2. Enumerate orientation
3. Enumerate identity and credentials
4. Discover network targets
5. Perform lateral movement (up to specified depth)
6. **NEW**: Enumerate PE5 privilege escalation opportunities
7. **NEW**: Check relay connectivity configuration
8. Enumerate persistence mechanisms
9. Enumerate certificates (MADCert)
10. **NEW**: Check tooling integration status
11. Run LogHunter analysis
12. Perform Moonwalk cleanup

### Manual Enumeration

Access via main menu:
1. Select option for auto-enumeration module
2. Choose depth (if overriding default)
3. Review comprehensive report
4. Export in desired format

## Integration Points

### PE5 Integration

- Checks PE5 framework availability
- Detects Windows version compatibility
- Identifies kernel token offsets
- Enumerates PE techniques
- Tracks escalation status

### Relay Integration

- Detects relay configuration
- Checks connectivity options
- Verifies Tor availability
- Tests transport methods

### Module Integration

- Checks all module availability
- Tracks tool usage
- Generates integration summary
- Reports readiness status

## Report Enhancements

### Text Report

New sections added:
- PRIVILEGE ESCALATION (PE5)
- RELAY CONNECTIVITY
- TOOLING INTEGRATION
- LOGHUNTER ANALYSIS (enhanced)
- MOONWALK CLEANUP (enhanced)
- ENUMERATION SUMMARY

### JSON Report

All new enumeration data included:
- `privilege_escalation` object
- `relay_connectivity` object
- `tooling_integration` object
- Enhanced existing sections

### HTML Report

New HTML sections:
- Privilege Escalation (PE5) section
- Relay Connectivity section
- Tooling Integration section
- Enhanced styling and formatting

## Benefits

1. **Comprehensive Coverage**: All tooling is checked and reported
2. **PE5 Readiness**: Immediate visibility into PE5 escalation opportunities
3. **Relay Status**: Clear relay connectivity status
4. **Tool Tracking**: Complete visibility into tools used
5. **Integration Status**: Know what's available and ready
6. **Enhanced Reporting**: More detailed and actionable reports

## Example Output

When enumeration completes, you'll see:

```
ENUMERATION SUMMARY
--------------------------------------------------------------------------------
Total Lateral Targets: 5
Lateral Paths Explored: 3
PE5 Available: True
Relay Configured: True
Tools Used: 47
```

## Configuration

No additional configuration needed. The enhancements automatically:
- Detect available modules
- Check configurations
- Enumerate opportunities
- Generate comprehensive reports

All enhancements are backward compatible and work with existing enumeration workflows.
