# Auto Enumeration Enhancements

## Overview

The auto enumeration module has been enhanced with diagram generation capabilities and organized report storage.

## Diagram Generation

### Available Diagrams

The auto enumeration module automatically generates six types of Mermaid diagrams:

#### 1. MITRE ATT&CK Attack Flow (`mitre_attack_flow.mmd`)

Visual representation of the attack progression through MITRE ATT&CK phases:
- Initial Access → Foothold Establishment
- Discovery → Network Discovery → Target Identification
- Credential Access → Lateral Movement
- Privilege Escalation → Persistence
- Command & Control → Defense Evasion
- Collection → Exfiltration

**Features:**
- Color-coded phases
- Technique IDs (T-numbers) mapped to each phase
- Shows escalation success/failure
- Displays lateral movement paths
- Indicates PE5 availability and usage

#### 2. Network Topology (`network_topology.mmd`)

Network diagram showing:
- Initial host and its role
- Domain controllers
- Discovered lateral movement targets
- ARP-discovered hosts
- Lateral movement paths with methods (SMB/WinRM/WMI)
- Connection relationships

**Features:**
- Visual network layout
- Color-coded host types
- Method labels on connections
- Shows accessible vs discovered hosts

#### 3. Lateral Movement Paths (`lateral_movement.mmd`)

Detailed visualization of lateral movement sequences:
- Complete paths from initial host to targets
- Depth information for each path
- Methods used (wmic, smb, winrm, etc.)
- Maximum depth reached

**Features:**
- Flow diagram showing movement progression
- Depth indicators
- Method labels
- Path visualization

#### 4. Privilege Escalation Flow (`privilege_escalation.mmd`)

Privilege escalation techniques and opportunities:
- Current privilege level (SYSTEM/Admin/User)
- PE5 framework availability
- Windows version compatibility
- Token manipulation opportunities
- Other PE techniques (Print Spooler, UAC, etc.)
- Escalation results

**Features:**
- Current state visualization
- PE5 compatibility check
- Technique availability
- Escalation success/failure

#### 5. System Architecture (`system_architecture.mmd`)

Host-level architecture diagram:
- Host role and identity
- Network interfaces
- Listening services and ports
- Network shares
- Domain context
- Stored credentials
- Persistence mechanisms
- Tooling integration (PE5, Relay, etc.)

**Features:**
- Complete system overview
- Service and port information
- Integration status
- Credential sources

#### 6. Attack Timeline (`attack_timeline.mmd`)

Gantt chart showing attack phases:
- Initial Access
- Discovery
- Credential Access
- Lateral Movement
- Privilege Escalation
- Persistence
- Defense Evasion

**Features:**
- Timeline visualization
- Phase completion status
- Critical path identification
- Duration tracking

### Viewing Diagrams

Diagrams are saved in Mermaid format (`.mmd` files) and can be viewed using:

1. **Mermaid Live Editor**: https://mermaid.live
   - Copy diagram content
   - Paste into editor
   - View rendered diagram

2. **VS Code**:
   - Install "Markdown Preview Mermaid Support" extension
   - Open `.mmd` file
   - Use preview feature

3. **GitHub**:
   - Diagrams render automatically in markdown files
   - Include in README.md or documentation

4. **Command Line**:
   ```bash
   # Install mermaid-cli
   npm install -g @mermaid-js/mermaid-cli
   
   # Generate PNG
   mmdc -i diagram.mmd -o diagram.png
   
   # Generate SVG
   mmdc -i diagram.mmd -o diagram.svg
   ```

## Report Storage Structure

### Directory Organization

All enumeration reports are automatically stored in `enumeration_reports/` with the following structure:

```
enumeration_reports/
├── 2024-01-15/
│   ├── WORKSTATION01_20240115_143022/
│   │   ├── enumeration_report_20240115_143022.txt
│   │   ├── enumeration_report_20240115_143022.json
│   │   ├── enumeration_report_20240115_143022.html
│   │   ├── mitre_attack_flow.mmd
│   │   ├── network_topology.mmd
│   │   ├── lateral_movement.mmd
│   │   ├── privilege_escalation.mmd
│   │   ├── system_architecture.mmd
│   │   ├── attack_timeline.mmd
│   │   ├── README.md
│   │   └── remote_targets/
│   │       ├── 192_168_1_100_depth1_143530/
│   │       │   ├── enumeration_report_192_168_1_100.txt
│   │       │   ├── enumeration_report_192_168_1_100.json
│   │       │   ├── enumeration_report_192_168_1_100.html
│   │       │   ├── mitre_attack_flow.mmd
│   │       │   ├── network_topology.mmd
│   │       │   ├── lateral_movement.mmd
│   │       │   ├── privilege_escalation.mmd
│   │       │   ├── system_architecture.mmd
│   │       │   ├── attack_timeline.mmd
│   │       │   └── README.md
│   │       └── SERVER02_depth2_143545/
│   │           └── ...
│   └── DC01_20240115_150530/
│       └── ...
├── 2024-01-16/
│   └── ...
```

### Naming Convention

- **Date Folder**: `YYYY-MM-DD` format (e.g., `2024-01-15`)
- **Session Folder**: `{machine-name}_{YYYYMMDD}_{HHMMSS}` format
  - Machine name from `hostname` command
  - Timestamp ensures uniqueness for multiple runs

### Report Files

Each enumeration session generates:

1. **Text Report** (`enumeration_report_TIMESTAMP.txt`)
   - Human-readable text format
   - Comprehensive enumeration summary
   - All discovered information

2. **JSON Report** (`enumeration_report_TIMESTAMP.json`)
   - Machine-readable format
   - Complete enumeration data structure
   - Suitable for automated processing

3. **HTML Report** (`enumeration_report_TIMESTAMP.html`)
   - Formatted HTML with styling
   - Tables and organized sections
   - Suitable for sharing and presentation

4. **Diagram Files** (`.mmd` files)
   - All six diagram types
   - Mermaid format for rendering

5. **Index File** (`README.md`)
   - Overview of the enumeration session
   - Links to all reports and diagrams
   - Viewing instructions
   - List of remote machines enumerated (if any)

### Remote Machine Reports

**NEW**: When auto enumeration discovers and enumerates remote machines during lateral movement, each remote machine automatically gets its own complete set of reports and diagrams!

Each remote machine enumeration includes:
- **Complete Reports**: Text, JSON, and HTML formats
- **All 6 Diagrams**: MITRE attack flow, network topology, lateral movement, privilege escalation, system architecture, and attack timeline
- **Separate Directory**: Organized under `remote_targets/` subdirectory
- **Naming Convention**: `{target_name}_depth{depth}_{timestamp}/`
- **Index File**: Each remote machine has its own README.md

**Benefits:**
- ✅ Individual analysis of each discovered machine
- ✅ Complete context for lateral movement paths
- ✅ Easy comparison between machines
- ✅ Depth tracking for multi-hop lateral movement
- ✅ All data preserved for each target

### Benefits

This organization provides:

- **Chronological Organization**: Easy to find reports by date
- **Machine Separation**: Multiple machines' reports don't conflict
- **Session Tracking**: Multiple runs per day are preserved
- **Complete Context**: All related files in one directory
- **Easy Sharing**: Single directory contains everything
- **Historical Analysis**: Compare results over time

## Usage

### Running Auto Enumeration

```bash
# Set environment variable for auto-enumeration
export AUTO_ENUMERATE=1
export AUTO_ENUMERATE_DEPTH=3

# Run main application
python main.py
```

Or edit `main.py`:

```python
AUTO_ENUMERATE = 1
AUTO_ENUMERATE_DEPTH = 3
```

### Export Options

When enumeration completes, you'll be prompted for export format:
- `text`: Text report only
- `json`: JSON report only
- `html`: HTML report only
- `all`: All formats + diagrams
- `none`: No export

### Accessing Reports

Reports are automatically saved to:
```
enumeration_reports/{date}/{machine}_{timestamp}/
```

Navigate to the directory and:
1. Read `README.md` for overview
2. Open HTML report in browser
3. View diagrams using Mermaid Live Editor
4. Process JSON report programmatically

## Integration

### Programmatic Access

```python
from pathlib import Path
import json

# Find latest report
report_dir = Path('enumeration_reports')
latest_date = max(report_dir.iterdir(), key=lambda p: p.name)
latest_session = max(latest_date.iterdir(), key=lambda p: p.name)

# Load JSON report
with open(latest_session / 'enumeration_report_*.json') as f:
    data = json.load(f)

# Access enumeration data
foothold = data['foothold']
network = data['network']
lateral_paths = data['lateral_paths']
```

### Custom Processing

The JSON format allows for:
- Automated analysis
- Integration with SIEM systems
- Custom reporting
- Data correlation
- Trend analysis

## Examples

### Example Report Structure

```
enumeration_reports/
└── 2024-01-15/
    └── WORKSTATION01_20240115_143022/
        ├── README.md                    # Overview and index
        ├── enumeration_report_20240115_143022.txt
        ├── enumeration_report_20240115_143022.json
        ├── enumeration_report_20240115_143022.html
        ├── mitre_attack_flow.mmd        # MITRE ATT&CK flow
        ├── network_topology.mmd          # Network diagram
        ├── lateral_movement.mmd         # Lateral paths
        ├── privilege_escalation.mmd     # PE flow
        ├── system_architecture.mmd      # System overview
        ├── attack_timeline.mmd          # Timeline
        └── remote_targets/              # Remote machines enumerated
            ├── 192_168_1_100_depth1_143530/
            │   ├── README.md            # Remote machine index
            │   ├── enumeration_report_192_168_1_100.txt
            │   ├── enumeration_report_192_168_1_100.json
            │   ├── enumeration_report_192_168_1_100.html
            │   ├── mitre_attack_flow.mmd
            │   ├── network_topology.mmd
            │   ├── lateral_movement.mmd
            │   ├── privilege_escalation.mmd
            │   ├── system_architecture.mmd
            │   └── attack_timeline.mmd
            └── SERVER02_depth2_143545/
                └── ...                   # Another remote machine
```

### Example README.md Content

```markdown
# Enumeration Report Index

**Generated:** 2024-01-15T14:30:22
**Machine:** WORKSTATION01
**Date:** 2024-01-15

## Reports
- Text Report: `enumeration_report_20240115_143022.txt`
- JSON Report: `enumeration_report_20240115_143022.json`
- HTML Report: `enumeration_report_20240115_143022.html`

## Diagrams
All diagrams are in Mermaid format (.mmd). View them using:
- [Mermaid Live Editor](https://mermaid.live)
- VS Code with Mermaid extension
- GitHub (renders automatically)

- **Mitre Attack Flow**: `mitre_attack_flow.mmd`
- **Network Topology**: `network_topology.mmd`
- **Lateral Movement**: `lateral_movement.mmd`
- **Privilege Escalation**: `privilege_escalation.mmd`
- **System Architecture**: `system_architecture.mmd`
- **Attack Timeline**: `attack_timeline.mmd`
```

## Best Practices

1. **Regular Cleanup**: Archive old reports periodically
2. **Naming**: Use descriptive machine names for easy identification
3. **Backup**: Include `enumeration_reports/` in backups
4. **Sharing**: Share entire session directories for complete context
5. **Analysis**: Use JSON format for automated analysis
6. **Documentation**: Review diagrams for visual understanding
7. **Remote Machines**: Check `remote_targets/` subdirectory for discovered machines
8. **Depth Tracking**: Use depth indicators to understand lateral movement paths
9. **Comparison**: Compare remote machine reports to identify patterns
10. **Complete Context**: Each remote machine has full enumeration data for independent analysis

## Troubleshooting

### Diagrams Not Rendering

- Ensure Mermaid syntax is valid
- Check diagram file encoding (UTF-8)
- Verify diagram viewer supports Mermaid

### Reports Not Saving

- Check write permissions in `enumeration_reports/`
- Verify disk space available
- Check for path length limitations (Windows)

### Missing Diagrams

- Ensure enumeration completed successfully
- Check for errors in console output
- Verify diagram generator module is available
