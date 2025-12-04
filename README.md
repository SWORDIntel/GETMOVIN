# Windows Lateral Movement Simulation TUI

A unified Text User Interface (TUI) for Windows lateral movement simulation, designed for red team exercises and threat modeling in Active Directory environments.

## Features

- **Unified Interface**: All lateral movement functions accessible from a single TUI
- **Modular Design**: Organized into 6 main modules covering the entire attack lifecycle
- **Live Execution**: Commands execute in real-time (when LAB_USE != 1)
- **Lab Mode**: Restrict operations to local IP ranges only (LAB_USE = 1)
- **Minimal Footprint**: Uses native Windows binaries and PowerShell cmdlets
- **APT-41 TTPs**: Enhanced with known APT-41 (Winnti Group) tactics, techniques, and procedures

## Modules

1. **Foothold & Starting Point**: SSH foothold assessment, identity checks, host role classification
   - APT-41 TTPs: Initial access techniques, supply chain attacks, discovery
2. **Local Orientation**: Identity mapping, host classification, network visibility, service accounts
   - APT-41 TTPs: Discovery, security software detection, scheduled task analysis
3. **Identity Acquisition**: Credential harvesting, domain context, token extraction
   - APT-41 TTPs: LSASS dumping, credential access, domain enumeration
4. **Lateral Movement Channels**: SMB/RPC, WinRM, WMI, RDP, DCOM, SSH tunneling
   - APT-41 TTPs: Custom tools (BADSIGN, BADHATCH), DLL sideloading, lateral movement patterns
5. **Consolidation & Dominance**: Strategic objectives, DC access, persistence mechanisms
   - APT-41 TTPs: Persistence techniques, WMI event subscriptions, scheduled tasks
6. **OPSEC Considerations**: Tool selection, detection evasion, behavioral blending
   - APT-41 TTPs: Defense evasion, log clearing, masquerading, DLL sideloading

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

## LAB_USE Flag

The `LAB_USE` flag in `main.py` controls operation mode:

- **LAB_USE = 1**: Lab mode - restricts all operations to local IP ranges only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
- **LAB_USE != 1**: Live mode - full execution enabled for all targets

To change the mode, edit `LAB_USE` in `main.py`:

```python
# LAB_USE flag: Set to 1 to limit operations to local IP ranges only
LAB_USE = 1  # Lab mode
# LAB_USE = 0  # Live mode
```

## Requirements

- Python 3.7+
- Windows environment (for command execution)
- PowerShell 5.0+
- Rich library for TUI

## MITRE ATT&CK TTP Integration

This tool is aligned with comprehensive MITRE ATT&CK techniques for Windows lateral movement:

### 1. Access & Authentication
- **T1078** – Valid Accounts: Use of real domain/local/service accounts (stolen or misused) for lateral auth
- **T1550** – Use Alternate Authentication Material: Reuse of hashes, Kerberos tickets, tokens instead of cleartext passwords
  - T1550.002 – Pass-the-Hash (PtH)
  - T1550.003 – Pass-the-Ticket (PtT)
  - T1550.001 – Application Access Token

### 2. Remote Service Channels (Core Movement Rails)
- **T1021** – Remote Services (family): Moving via authenticated remote service sessions
  - **T1021.004** – SSH (headless SSH daemon on Windows box)
  - **T1021.001** – Remote Desktop Protocol (RDP)
  - **T1021.002** – SMB/Windows Admin Shares (C$, ADMIN$, IPC$)
  - **T1021.006** – Windows Remote Management (WinRM)

### 3. Discovery to Pick Hosts & Paths
- **T1018** – Remote System Discovery: Query AD, Net* commands, WMI, PS remoting to enumerate nodes
- **T1087** – Account Discovery: Find high-value/local admin/DA accounts to pivot with
  - T1087.001 – Account Discovery: Local Account
  - T1087.002 – Account Discovery: Domain Account
- **T1135** – Network Share Discovery: What shares exist where payloads/creds/tools might live
- **T1082** – System Information Discovery: Understand host role and capabilities

### 4. Credential Access to Enable More Movement
- **T1003** – OS Credential Dumping
  - **T1003.001** – LSASS Memory: Classic LSASS scraping, SAM/SECURITY hive abuse
  - T1003.002 – Security Account Manager
- **T1059.001** – Command & Scripting Interpreter: PowerShell
  - Used as execution engine and for credential access helpers (Invoke-Mimikatz, LSASS readers)

### 5. Actual Remote Execution / Tooling
- **T1569.002** – System Services: Service Execution
  - PsExec/SC-based remote service abuse for "push binary → run as service" patterns
- **T1047** – Windows Management Instrumentation (WMI)
  - WMI for remote process creation, recon, and "living off the land" movement
- **T1053.005** – Scheduled Task/Job: Scheduled Task
  - schtasks-based remote or local scheduled execution (persistence + lateral EXE/PS script runs)
- **T1570** – Lateral Tool Transfer
  - Copying tooling over SMB/WinRM/SSH shares before execution

### 6. Persistence
- **T1053.005** – Scheduled Task/Job: Scheduled Task
- **T1543.003** – Create/Modify System Process: Windows Service
- **T1053.003** – Scheduled Task/Job: WMI Event Subscription

Each module includes specific MITRE ATT&CK technique IDs and context for reference.

## Disclaimer

This tool is for **authorized red team exercises and threat modeling only**. Unauthorized use is illegal and unethical. Use only on systems you own or have explicit written permission to test.

## License

For authorized testing purposes only.
