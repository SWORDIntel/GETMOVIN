# Windows Lateral Movement Simulation TUI

**Red Team / Threat Modeling Tool for Windows Environments**

A comprehensive Terminal User Interface (TUI) tool for simulating and modeling Windows lateral movement techniques, aligned with APT-41 (Winnti Group) Tactics, Techniques, and Procedures (TTPs).

## ⚠️ WARNING

**This tool is for authorized security testing and threat modeling only. Unauthorized use is illegal.**

## Features

- **Self-Contained**: No online dependencies - all functionality is local
- **APT-41 TTP Alignment**: Techniques aligned with known APT-41 methodologies
- **MITRE ATT&CK Integration**: Comprehensive TTP coverage
- **Modular Architecture**: 12 integrated modules covering all phases of lateral movement
- **PE5 SYSTEM Escalation**: PRIMARY privilege escalation method using kernel-level token manipulation (APT-41 PE5 framework)
- **Auto-Enumeration Mode**: Automated comprehensive enumeration with lateral movement
- **LogHunter Integration**: Windows event log analysis and hunting
- **Windows Moonwalk**: Advanced log clearing with fake entry injection
- **LOLBins Reference**: Living Off The Land Binaries database
- **MADCert Integration**: Certificate generation for AD environments
- **LLM Remote Agent**: Self-coding execution agent with custom protocol

## Quick Start

### Windows

```batch
run.bat
```

### Linux/Mac (for testing)

```bash
./run.sh
```

The script will automatically:
1. ✅ Check for Python 3.8+
2. ✅ Create a virtual environment (if needed)
3. ✅ Install dependencies (only `rich` required for core)
4. ✅ Launch the tool
5. ✅ Handle optional dependencies gracefully

**That's it!** The tool is fully self-contained and auto-bootstraps everything needed.

## Manual Installation

### Prerequisites

- Python 3.8 or higher
- Windows operating system (primary target)
- Administrator privileges (for some operations)

### Cross-Platform Setup

This tool can be **prepared on Linux** and **deployed to Windows**. See [CROSS_PLATFORM.md](CROSS_PLATFORM.md) for details.

**Quick Package Creation (Linux):**
```bash
python3 package_for_windows.py
# Transfer windows_package/ to Windows PC
# On Windows: Run setup_windows.bat
```

## Installation Steps

1. **Clone or extract the tool:**
   ```bash
   git clone <repository-url>
   cd windows-lateral-movement-tui
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate virtual environment:**
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the tool:**
   ```bash
   python main.py
   ```

## Configuration

### Environment Variables

- `LAB_USE=1` - Limits operations to local IP ranges only (default: 1)
- `AUTO_ENUMERATE=1` - Enable automatic enumeration on startup (default: 0)
- `AUTO_ENUMERATE_DEPTH=3` - Maximum lateral movement depth (default: 3)

### Configuration in Code

Edit `main.py` to change default settings:

```python
LAB_USE = 1  # Set to 0 for live mode
AUTO_ENUMERATE = 0  # Set to 1 for auto-enumeration
AUTO_ENUMERATE_DEPTH = 3  # Maximum lateral movement depth
```

## Modules

### 1. Foothold & Starting Point
- Identity and privilege assessment
- Host role classification
- Network visibility analysis
- APT-41 initial access techniques

### 2. Local Orientation
- Identity and privilege mapping
- Host role classification
- Network visibility
- Service account discovery
- Scheduled task analysis
- Security software discovery

### 3. Identity Acquisition
- Local credential sources
- Credential store access
- Configuration secrets
- User artifacts
- Domain context and delegation
- Token and ticket extraction
- LSASS memory dumping

### 4. Lateral Movement Channels
- SMB/RPC-based movement
- WinRM / PowerShell Remoting
- WMI-based execution
- RDP-based pivoting
- DCOM / COM-based movement
- SSH tunneling and port forwarding
- APT-41 custom tools

### 5. Consolidation & Dominance
- Strategic objectives
- Domain controller access
- Persistence mechanisms
- Control planes
- Cleanup operations
- APT-41 persistence techniques

### 6. OPSEC Considerations
- Tool selection and native binaries
- Detection evasion
- Logging avoidance
- Behavioral blending
- OPSEC checklist
- APT-41 defense evasion

### 7. LLM Remote Agent
- Self-coding execution agent
- MEMSHADOW MRAC protocol
- Remote command execution
- Code generation and patching

### 8. MADCert Certificate Generation
- CA certificate generation
- Server certificate generation
- Client certificate generation
- Code signing certificate generation
- Certificate management

### 9. LOLBins Reference
- Comprehensive LOLBins database
- Search and browse functionality
- Dynamic command builders
- Defense evasion builders
- Certificate signing integration

### 10. LogHunter Integration
- Credential access event hunting
- Lateral movement indicator hunting
- Privilege escalation event hunting
- Custom log queries
- Log export functionality

### 11. Windows Moonwalk
- Event log clearing with fake entry injection
- PowerShell history clearing
- Command history clearing
- Registry trace removal
- Prefetch file clearing
- Recent files and Jump Lists clearing
- Temp file cleanup
- Browser history clearing
- Windows Defender log clearing
- Windows artifact cleanup
- Application compatibility cache clearing

### 12. PE5 SYSTEM Escalation [PRIMARY PE METHOD]
- Kernel-level privilege escalation using APT-41 PE5 framework
- Direct _EPROCESS.Token manipulation via SYSCALL
- Multiple exploitation techniques (token stealing, direct modification, integrity elevation)
- Windows version-specific kernel offsets
- Print Spooler exploit (CVE-2020-1337)
- UAC bypass techniques (CVE-2019-1388)
- SMBv3 local PE (CVE-2020-0796)
- Privilege verification and reporting
- Enhanced with techniques from post-hub repository

## Auto-Enumeration Mode

Enable automatic comprehensive enumeration:

```bash
# Set environment variable
export AUTO_ENUMERATE=1
export AUTO_ENUMERATE_DEPTH=3

# Or edit main.py
AUTO_ENUMERATE = 1
AUTO_ENUMERATE_DEPTH = 3

# Run tool
python main.py
```

Auto-enumeration will:
- Enumerate all modules automatically
- Perform lateral movement up to specified depth
- Use LOTL techniques for remote enumeration
- Generate comprehensive reports (TXT, JSON, HTML)
- Perform moonwalk cleanup after operations

## Dependencies

### Python Packages

- `rich>=13.0.0` - Terminal UI framework

All dependencies are listed in `requirements.txt` and can be installed offline.

### External Tools (Optional)

- **LogHunter**: For advanced log analysis (optional)
- **MADCert**: For certificate generation (optional)

These tools are optional and the TUI will function without them.

## Project Structure

```
.
├── main.py                      # Main entry point
├── run.bat                      # Windows launcher script
├── run.sh                       # Linux/Mac launcher script
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── modules/                     # Core modules
│   ├── __init__.py
│   ├── utils.py                # Utility functions
│   ├── foothold.py             # Foothold module
│   ├── orientation.py          # Orientation module
│   ├── identity.py             # Identity module
│   ├── lateral.py              # Lateral movement module
│   ├── consolidation.py        # Consolidation module
│   ├── opsec.py                # OPSEC module
│   ├── llm_agent.py            # LLM agent module
│   ├── madcert_integration.py  # MADCert integration
│   ├── lolbins_reference.py    # LOLBins reference
│   ├── auto_enumerate.py       # Auto-enumeration
│   ├── loghunter_integration.py # LogHunter & Moonwalk
│   ├── memshadow_protocol.py   # MRAC protocol
│   └── memshadow_client.py     # MRAC client
├── docs/                        # Documentation
│   ├── Auto_Enumeration.md
│   ├── LOLBins_Reference.md
│   ├── MADCert_Integration.md
│   └── PE5_Integration.md       # PE5 SYSTEM escalation integration
├── pe5_framework_extracted/     # PE5 framework source code
│   └── pe5_framework/           # APT-41 PE5 exploit framework
└── examples/                    # Example scripts
    └── llm_agent_example.py
```

## Usage Examples

### Basic Usage

```bash
# Run with default settings (LAB_USE=1)
python main.py

# Run in live mode
# Edit main.py: LAB_USE = 0
python main.py

# Run with auto-enumeration
# Edit main.py: AUTO_ENUMERATE = 1
python main.py
```

### Module Selection

1. Launch the tool
2. Select a module from the main menu (1-12)
3. Choose specific functions within the module
4. Review results and execute commands

### Auto-Enumeration

```bash
# Set environment variables
export AUTO_ENUMERATE=1
export AUTO_ENUMERATE_DEPTH=3

# Run tool
python main.py

# Tool will automatically:
# - Enumerate all modules
# - Perform lateral movement
# - Generate reports
# - Clean up traces
```

## MITRE ATT&CK TTPs

The tool aligns with the following MITRE ATT&CK techniques:

- **T1078** - Valid Accounts
- **T1550** - Alternate Authentication Material
- **T1021** - Remote Services
- **T1087** - Account Discovery
- **T1018** - Remote System Discovery
- **T1003** - OS Credential Dumping
- **T1059** - Command and Scripting Interpreter
- **T1053** - Scheduled Task/Job
- **T1562** - Impair Defenses
- **T1070** - Indicator Removal
- **T1036** - Masquerading
- **T1027** - Obfuscated Files or Information
- **T1105** - Ingress Tool Transfer
- And many more...

## Security Considerations

- **LAB_USE Mode**: Default mode restricts operations to local IP ranges
- **No Online Dependencies**: All functionality is local and self-contained
- **Authorization Required**: Use only in authorized testing environments
- **Log Clearing**: Moonwalk module includes advanced evasion techniques
- **OPSEC**: Built-in operational security considerations

## Troubleshooting

### Python Not Found

```bash
# Windows: Add Python to PATH
# Or use full path: C:\Python3x\python.exe main.py

# Linux/Mac: Install Python 3.8+
sudo apt-get install python3  # Debian/Ubuntu
brew install python3          # macOS
```

### Module Import Errors

```bash
# Ensure virtual environment is activated
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Permission Errors

- Some operations require administrator privileges
- Run as administrator on Windows
- Use `sudo` on Linux (if needed)

## Contributing

This is a security research tool. Contributions should focus on:
- Bug fixes
- Performance improvements
- Additional TTP coverage
- Documentation improvements

## License

**For authorized security testing and threat modeling only.**

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before using this tool in any environment.

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [APT-41 (Winnti Group)](https://attack.mitre.org/groups/G0016/)
- [LogHunter](https://github.com/CICADA8-Research/LogHunter)
- [MADCert](https://github.com/NationalSecurityAgency/MADCert)
- [Awesome LOLBins](https://github.com/sheimo/awesome-lolbins-and-beyond)
- [post-hub](https://github.com/ybdt/post-hub) - Post-exploitation techniques repository

## Version

Current Version: 1.0.0

## Support

For issues, questions, or contributions, please refer to the project repository.

---

**Remember: Always obtain proper authorization before using this tool.**
