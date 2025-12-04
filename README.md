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

## APT-41 TTP Integration

This tool incorporates known APT-41 (Winnti Group) tactics, techniques, and procedures (TTPs) including:

- **Initial Access**: Supply chain attacks, public-facing application exploitation
- **Execution**: PowerShell, WMI, scheduled tasks, DLL sideloading
- **Persistence**: Scheduled tasks, WMI event subscriptions, DLL sideloading, services
- **Privilege Escalation**: Token manipulation, credential dumping
- **Defense Evasion**: DLL sideloading, process injection, security tool disabling, log clearing
- **Credential Access**: LSASS memory dumping, credential stores, domain enumeration
- **Discovery**: Network scanning, system information, security software discovery
- **Lateral Movement**: SMB/RPC, WinRM, WMI, custom backdoors
- **Command and Control**: HTTP/HTTPS, SSH tunneling, encrypted channels

Each module includes APT-41-specific techniques and MITRE ATT&CK technique IDs for reference.

## Disclaimer

This tool is for **authorized red team exercises and threat modeling only**. Unauthorized use is illegal and unethical. Use only on systems you own or have explicit written permission to test.

## License

For authorized testing purposes only.
