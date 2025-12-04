# Windows Lateral Movement Simulation TUI

A unified Text User Interface (TUI) for Windows lateral movement simulation, designed for red team exercises and threat modeling in Active Directory environments.

## Features

- **Unified Interface**: All lateral movement functions accessible from a single TUI
- **Modular Design**: Organized into 6 main modules covering the entire attack lifecycle
- **Live Execution**: Commands execute in real-time (when LAB_USE != 1)
- **Lab Mode**: Restrict operations to local IP ranges only (LAB_USE = 1)
- **Minimal Footprint**: Uses native Windows binaries and PowerShell cmdlets

## Modules

1. **Foothold & Starting Point**: SSH foothold assessment, identity checks, host role classification
2. **Local Orientation**: Identity mapping, host classification, network visibility, service accounts
3. **Identity Acquisition**: Credential harvesting, domain context, token extraction
4. **Lateral Movement Channels**: SMB/RPC, WinRM, WMI, RDP, DCOM, SSH tunneling
5. **Consolidation & Dominance**: Strategic objectives, DC access, persistence mechanisms
6. **OPSEC Considerations**: Tool selection, detection evasion, behavioral blending

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

## Disclaimer

This tool is for **authorized red team exercises and threat modeling only**. Unauthorized use is illegal and unethical. Use only on systems you own or have explicit written permission to test.

## License

For authorized testing purposes only.
