<<<<<<< HEAD
# W-SLAM : WIndows-Spcieic Lateral Access / Movement tool

**Red team enumeration and movement plus full tooling for complex systems**

A comprehensive, self-contained Terminal User Interface (TUI) tool for simulating and modeling Windows lateral movement techniques, aligned with APT-41 (Winnti Group) Tactics, Techniques, and Procedures (TTPs) and MITRE ATT&CK framework.

## ⚠️ WARNING

**Unauthorized use is illegal and unethical unless the target has something you want,in which case do not get caught**

## 🚀 Quick Start

**Windows:**
=======
# Windows Lateral Movement Simulation TUI

**Red Team / Threat Modeling Tool for Windows Environments**

A comprehensive Terminal User Interface (TUI) tool for simulating and modeling Windows lateral movement techniques, aligned with APT-41 (Winnti Group) Tactics, Techniques, and Procedures (TTPs).

## ⚠️ WARNING

**This tool is for authorized security testing and threat modeling only. Unauthorized use is illegal.**

## Features

- **Self-Contained**: No online dependencies - all functionality is local
- **APT-41 TTP Alignment**: Techniques aligned with known APT-41 methodologies
- **MITRE ATT&CK Integration**: Comprehensive TTP coverage
- **Modular Architecture**: 11 integrated modules covering all phases of lateral movement
- **Auto-Enumeration Mode**: Automated comprehensive enumeration with lateral movement
- **LogHunter Integration**: Windows event log analysis and hunting
- **Windows Moonwalk**: Advanced log clearing with fake entry injection
- **LOLBins Reference**: Living Off The Land Binaries database
- **MADCert Integration**: Certificate generation for AD environments
- **LLM Remote Agent**: Self-coding execution agent with custom protocol

## Quick Start

### Windows

>>>>>>> origin/cursor/tui-for-windows-lateral-movement-simulation-composer-1-e45e
```batch
run.bat
```

<<<<<<< HEAD
**Linux/Mac (for testing/preparation):**
=======
### Linux/Mac (for testing)

>>>>>>> origin/cursor/tui-for-windows-lateral-movement-simulation-composer-1-e45e
```bash
./run.sh
```

<<<<<<< HEAD
**Cross-Platform Setup (Prepare on Linux, Deploy to Windows):**
```bash
# On Linux: Create Windows package
python3 package_for_windows.py

# Transfer windows_package/ to Windows PC
# On Windows: Run setup_windows.bat
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for detailed quick start guide.

## ✨ Features

### Core Capabilities

- **Self-Contained**: Fully autonomous - no online dependencies required
- **Auto-Bootstrap**: Single command setup - everything auto-installs
- **Cross-Platform Preparation**: Prepare on Linux, deploy to Windows
- **Graceful Degradation**: Works with or without optional components
- **Comprehensive Discovery**: Automatically finds and reports all components

### APT-41 TTP Alignment

- **PE5 SYSTEM Escalation**: PRIMARY privilege escalation using kernel-level token manipulation
- **Token Stealing**: Direct `_EPROCESS.Token` manipulation via SYSCALL
- **Integrity Level Elevation**: SYSTEM privilege acquisition techniques
- **Kernel-Level Exploitation**: APT-41's PE5 framework integration

### MITRE ATT&CK Integration

- **Comprehensive TTP Coverage**: All phases of lateral movement
- **TTP Mapping**: Detailed technique mappings in UI
- **Tactical Guidance**: Context-aware help and guidance
- **Reference Database**: LOLBins, techniques, and procedures

### 12 Integrated Modules

1. **Foothold & Starting Point** - Initial access and establishment
2. **Local Orientation** - System reconnaissance and discovery
3. **Identity Acquisition** - Credential harvesting and token manipulation
4. **Lateral Movement Channels** - Network pivoting and movement
5. **Consolidation & Dominance** - Persistence and control establishment
6. **OPSEC Considerations** - Operational security and evasion
7. **LLM Remote Agent** - Self-coding execution agent with custom protocol
8. **MADCert Integration** - Certificate generation for AD environments
9. **LOLBins Reference** - Living Off The Land Binaries database
10. **LogHunter Integration** - Windows event log analysis and hunting
11. **Windows Moonwalk** - Advanced log clearing with fake entry injection
12. **[PRIMARY] PE5 SYSTEM Escalation** - Kernel-level privilege escalation

### Advanced Features

- **Auto-Enumeration Mode**: Automated comprehensive enumeration with lateral movement
- **Diagram Generation**: Automatic Mermaid diagram generation for MITRE ATT&CK flows, network topologies, and attack timelines
- **Organized Report Storage**: All enumeration data stored in `enumeration_reports/` sorted by date and machine+time
- **AI Remote Guidance**: Interactive, contextual help system
- **Relay Service**: Secure relay architecture for CGNAT scenarios
- **MEMSHADOW Protocol**: Custom binary protocol for efficient data transfer
- **CNSA 2.0 Compliant TLS**: Military-grade security for relay communications
- **Tor Support**: Hidden service support for relay endpoints
- **Structured Logging**: JSON logging for security monitoring
- **Comprehensive Testing**: End-to-end test harness with coverage reporting

## 📋 Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Modules](#modules)
- [Cross-Platform Setup](#cross-platform-setup)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 📦 Installation

### Prerequisites

- **Python 3.8+** (3.9+ recommended)
- **Windows OS** (primary target) or Linux/Mac (for preparation)
- **Administrator privileges** (for some operations)
- **Internet connection** (for initial dependency installation, or use offline dependencies)

### Quick Installation

#### Windows

```batch
# One-command setup
run.bat
```

This automatically:
1. ✅ Checks Python installation
2. ✅ Creates virtual environment
3. ✅ Installs dependencies
4. ✅ Launches the tool

#### Linux/Mac

```bash
# One-command setup
./run.sh
```

### Manual Installation

#### Step 1: Clone/Extract Repository

```bash
git clone <repository-url>
cd windows-lateral-movement-tui
```

Or extract the archive to a directory.

#### Step 2: Create Virtual Environment

**Windows:**
```batch
python -m venv venv
venv\Scripts\activate.bat
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Note**: Only `rich` is required for core functionality. Optional dependencies are auto-discovered and can be preloaded.

#### Step 4: Run the Tool

```bash
python main.py
```

### Cross-Platform Setup (Linux → Windows)

#### On Linux (Preparation)

**Step 1: Download Dependencies and Python (Optional but Recommended)**

Download all dependencies and optionally Python itself for offline installation on Windows:

```bash
# Download Windows-compatible dependencies
python3 download_deps.py --windows

# Download dependencies AND Python embeddable package (fully self-contained)
python3 download_deps.py --windows --include-python

# Or specify Python version and architecture
python3 download_deps.py --windows --include-python --python-version 3.11 --arch amd64

# This creates: offline_deps/ directory with all dependency files
# If --include-python is used: offline_deps/python/ with Python embeddable package
```

**Step 2: Create Windows Package**

```bash
# Create Windows package (automatically includes offline_deps/ if present)
python3 package_for_windows.py

# Output: windows_package/windows-lateral-movement-tui/
# Transfer this directory to Windows PC
```

#### On Windows (Deployment)

```cmd
# Navigate to package directory
cd windows-lateral-movement-tui

# Run setup script (automatically uses offline_deps/ if available)
setup_windows.bat

# Run the tool
run_windows.bat
```

**Benefits of Offline Dependencies:**
- ✅ **No internet required** on Windows PC
- ✅ **Faster installation** (no download time)
- ✅ **Works in air-gapped environments**
- ✅ **Reproducible deployments** (same dependency versions)

**Benefits of Bundled Python (`--include-python`):**
- ✅ **No Python installation required** on Windows PC
- ✅ **Works even if Python is not installed** on target system
- ✅ **Uses specific Python version** you tested with
- ✅ **Fully self-contained** deployment package
- ✅ **Bundled Python is used preferentially** if available

**How It Works:**
- The `download_deps.py` script downloads all Python packages (wheels and source distributions) to `offline_deps/`
- With `--include-python`, it also downloads Python embeddable package to `offline_deps/python/`
- The `package_for_windows.py` script automatically includes `offline_deps/` and bundled Python if they exist
- The Windows `setup_windows.bat` script automatically detects and uses bundled Python preferentially
- If bundled Python is not found, it falls back to system Python
- If `offline_deps/` is not found, the setup script falls back to downloading from the internet

See [docs/CROSS_PLATFORM.md](docs/CROSS_PLATFORM.md) for detailed cross-platform guide.

## ⚙️ Configuration
=======
The script will automatically:
1. Check for Python 3.8+
2. Create a virtual environment (if needed)
3. Install dependencies
4. Launch the tool

## Manual Installation

### Prerequisites

- Python 3.8 or higher
- Windows operating system (primary target)
- Administrator privileges (for some operations)

### Installation Steps

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
>>>>>>> origin/cursor/tui-for-windows-lateral-movement-simulation-composer-1-e45e

### Environment Variables

- `LAB_USE=1` - Limits operations to local IP ranges only (default: 1)
- `AUTO_ENUMERATE=1` - Enable automatic enumeration on startup (default: 0)
- `AUTO_ENUMERATE_DEPTH=3` - Maximum lateral movement depth (default: 3)
<<<<<<< HEAD
- `PRELOAD_REQUIREMENTS=1` - Auto-install missing optional dependencies (default: auto)
=======
>>>>>>> origin/cursor/tui-for-windows-lateral-movement-simulation-composer-1-e45e

### Configuration in Code

Edit `main.py` to change default settings:

```python
LAB_USE = 1  # Set to 0 for live mode
AUTO_ENUMERATE = 0  # Set to 1 for auto-enumeration
AUTO_ENUMERATE_DEPTH = 3  # Maximum lateral movement depth
```

<<<<<<< HEAD
### Module Configuration

Each module has its own configuration options accessible through the TUI menu system.

## 🧩 Modules

### 1. Foothold & Starting Point

Initial access techniques and foothold establishment.

**Features:**
- Initial access vectors
- Foothold establishment
- Persistence mechanisms
- System integration

**TTPs:** T1190, T1078, T1133, T1055

### 2. Local Orientation

System reconnaissance and environment discovery.

**Features:**
- System information gathering
- Network discovery
- Service enumeration
- Configuration analysis

**TTPs:** T1082, T1018, T1049, T1033

### 3. Identity Acquisition

Credential harvesting and identity manipulation.

**Features:**
- Credential dumping
- Token manipulation
- Hash extraction
- Key material harvesting

**TTPs:** T1003, T1555, T1556, T1078

### 4. Lateral Movement Channels

Network pivoting and lateral movement techniques.

**Features:**
- SMB/WinRM movement
- RDP tunneling
- SSH pivoting
- Custom protocols

**TTPs:** T1021, T1072, T1105, T1570

### 5. Consolidation & Dominance

Persistence and control establishment.

**Features:**
- Scheduled tasks
- Service installation
- Registry persistence
- Domain dominance

**TTPs:** T1053, T1543, T1112, T1484

### 6. OPSEC Considerations

Operational security and evasion techniques.

**Features:**
- Log evasion
- Process hiding
- Network obfuscation
- Detection avoidance

**TTPs:** T1562, T1070, T1027, T1497

### 7. LLM Remote Agent

Self-coding execution agent with custom protocol.

**Features:**
- Remote code generation
- MEMSHADOW protocol
- Binary data transfer
- Autonomous execution

**TTPs:** T1059, T1105, T1566

### 8. MADCert Certificate Generation

Certificate generation for Active Directory environments.

**Features:**
- Certificate generation
- AD integration
- Trust establishment
- Credential material

**TTPs:** T1550, T1078, T1484

### 9. LOLBins Reference

Living Off The Land Binaries database.

**Features:**
- Comprehensive LOLBins database
- Usage examples
- Detection evasion
- Technique references

**TTPs:** T1218, T1059, T1105

### 10. LogHunter Integration

Windows event log analysis and hunting.

**Features:**
- Event log analysis
- Security event hunting
- Credential access detection
- Lateral movement indicators

**TTPs:** T1055, T1003, T1021

### 11. Windows Moonwalk

Advanced log clearing with fake entry injection.

**Features:**
- Log clearing
- Fake entry injection
- Event log manipulation
- OPSEC enhancement

**TTPs:** T1070, T1562

### 12. [PRIMARY] PE5 SYSTEM Escalation

Kernel-level privilege escalation using APT-41 PE5 framework.

**Features:**
- Kernel-level token manipulation
- Direct `_EPROCESS.Token` modification
- SYSCALL-based exploitation
- Integrity level elevation
- Token stealing techniques
- Interactive AI guidance
- Step-by-step instructions
- TTP mapping

**TTPs:** T1068, T1134, T1078

**Technical Details:**
- XOR key derivation (0xA4)
- SYSCALL instruction (0x0F 0x05)
- Token structure manipulation
- Windows version offsets
- Shellcode generation

See [docs/PE5_Integration.md](docs/PE5_Integration.md) for technical details.

## 🌐 Cross-Platform Setup

### Overview

The tool can be **prepared on Linux** and **deployed to Windows** for execution.

### Quick Cross-Platform Workflow

1. **On Linux**: `python3 package_for_windows.py`
2. **Transfer** `windows_package/` to Windows PC
3. **On Windows**: Run `setup_windows.bat`

### Key Points

- ✅ **Dependencies are cross-platform** - All Python packages work on Windows
- ✅ **Virtual environments are NOT portable** - Created fresh on Windows
- ✅ **Python code is cross-platform** - All modules work on Windows
- ⚠️ **Some features require Windows tools** - LogHunter, PE5 compilation

See [CROSS_PLATFORM.md](CROSS_PLATFORM.md) for complete guide.

## 🏗️ Architecture

### Component Discovery

The tool automatically discovers and reports:

- **PE5 Framework**: Availability, path, compilation status
- **Relay Service**: Daemon, client, configuration
- **Optional Dependencies**: websockets, aiohttp, pyyaml, cryptography
- **Configuration Files**: Relay configs, client configs
- **External Tools**: Tor, LogHunter availability

### Dependency Management

- **Core**: `rich` (required)
- **Optional**: websockets, aiohttp, pyyaml, cryptography (auto-discovered)
- **Graceful Degradation**: Features work with or without optional deps

### Auto-Bootstrap

The tool automatically:

1. Discovers all components
2. Preloads missing optional dependencies
3. Reports component availability
4. Handles missing components gracefully

See [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md) for bootstrap details.

### Relay Architecture

Secure relay service for CGNAT scenarios:

- **CNSA 2.0 Compliant TLS**: Military-grade security
- **ALPN Protocol Negotiation**: Command/data channel separation
- **Tor Support**: Hidden service endpoints
- **Dynamic DNS**: FQDN support
- **Structured Logging**: JSON logging for monitoring

See [docs/remote_guided_relay.md](docs/remote_guided_relay.md) for relay architecture.

## 📊 Auto-Enumeration & Reporting

### Diagram Generation

The auto-enumeration module automatically generates comprehensive Mermaid diagrams:

- **MITRE ATT&CK Attack Flow**: Visual representation of attack progression through MITRE ATT&CK phases
- **Network Topology**: Network diagram showing discovered hosts, lateral movement paths, and connections
- **Lateral Movement Paths**: Detailed visualization of lateral movement sequences and methods
- **Privilege Escalation Flow**: PE5 and other privilege escalation techniques visualization
- **System Architecture**: Host-level architecture showing services, shares, and integrations
- **Attack Timeline**: Gantt chart showing attack phases and timing

All diagrams are saved in Mermaid format (`.mmd`) and can be viewed using:
- [Mermaid Live Editor](https://mermaid.live)
- VS Code with Mermaid extension
- GitHub (renders automatically in markdown)

### Report Storage Structure

All enumeration reports are automatically organized in the `enumeration_reports/` directory:

```
enumeration_reports/
├── YYYY-MM-DD/
│   ├── machine-name_TIMESTAMP/
│   │   ├── enumeration_report_TIMESTAMP.txt
│   │   ├── enumeration_report_TIMESTAMP.json
│   │   ├── enumeration_report_TIMESTAMP.html
│   │   ├── mitre_attack_flow.mmd
│   │   ├── network_topology.mmd
│   │   ├── lateral_movement.mmd
│   │   ├── privilege_escalation.mmd
│   │   ├── system_architecture.mmd
│   │   ├── attack_timeline.mmd
│   │   ├── README.md
│   │   └── remote_targets/          # NEW: Remote machines enumerated
│   │       ├── target1_depth1_TIMESTAMP/
│   │       │   ├── Complete reports & diagrams
│   │       │   └── README.md
│   │       └── target2_depth2_TIMESTAMP/
│   │           └── ...
```

Reports are sorted by:
1. **Date** (YYYY-MM-DD format)
2. **Machine name** + **Timestamp** (for multiple runs on same day)
3. **Remote targets** (in `remote_targets/` subdirectory, organized by target name, depth, and timestamp)

**NEW Feature**: When auto enumeration discovers remote machines during lateral movement, each machine automatically gets its own complete set of reports and diagrams stored in `remote_targets/`!

This organization makes it easy to:
- Track enumeration history over time
- Compare results across different machines
- Review specific enumeration sessions
- Share reports with team members
- **Analyze each discovered remote machine independently**
- **Track lateral movement depth and paths**
- **Compare remote machine configurations**

## 🧪 Testing

### Running Tests

The project includes a comprehensive end-to-end test harness covering all modules:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=modules --cov-report=html

# Run specific test file
pytest tests/test_all_modules.py -v

# Run specific test class
pytest tests/test_all_modules.py::TestDiagramGenerator -v
```

### Test Coverage

Current test coverage includes:
- ✅ All module initialization tests
- ✅ Module execution tests (with mocked user input)
- ✅ Auto-enumeration functionality
- ✅ Report generation (text, JSON, HTML)
- ✅ Diagram generation (all diagram types)
- ✅ Utility functions
- ✅ Error handling

### Test Structure

```
tests/
├── __init__.py
├── test_all_modules.py      # End-to-end tests for all modules
└── test_diagram_generator.py # Additional diagram generator tests
```

### Coverage Reports

Coverage reports are generated in multiple formats:
- **Terminal**: `--cov-report=term-missing`
- **HTML**: `--cov-report=html` (view in `htmlcov/index.html`)
- **XML**: `--cov-report=xml` (for CI/CD integration)

## 📚 Documentation

### Core Documentation

- **[docs/QUICKSTART.md](docs/QUICKSTART.md)** - Quick start guide
- **[docs/BOOTSTRAP.md](docs/BOOTSTRAP.md)** - Auto-bootstrap process
- **[docs/CROSS_PLATFORM.md](docs/CROSS_PLATFORM.md)** - Cross-platform setup
- **[docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md)** - Project organization

### Utility Scripts

- **`download_deps.py`** - Download dependencies and optionally Python for offline installation
  ```bash
  python3 download_deps.py --windows  # Download Windows dependencies
  python3 download_deps.py --windows --include-python  # Include Python embeddable package
  python3 download_deps.py --windows --include-python --python-version 3.11 --arch amd64
  ```
- **`package_for_windows.py`** - Create Windows deployment package
  ```bash
  python3 package_for_windows.py  # Creates windows_package/
  ```

### Module Documentation

- **[docs/PE5_Integration.md](docs/PE5_Integration.md)** - PE5 framework integration
- **[docs/PE5_UI_Integration.md](docs/PE5_UI_Integration.md)** - PE5 UI and guidance
- **[docs/remote_guided_relay.md](docs/remote_guided_relay.md)** - Relay architecture
- **[docs/Auto_Enumeration.md](docs/Auto_Enumeration.md)** - Auto-enumeration features
- **[docs/Auto_Enumeration_Enhancements.md](docs/Auto_Enumeration_Enhancements.md)** - Diagram generation and report storage
- **[docs/MADCert_Integration.md](docs/MADCert_Integration.md)** - MADCert integration
- **[docs/LOLBins_Reference.md](docs/LOLBins_Reference.md)** - LOLBins database

### Installation Guides

- **[docs/INSTALL.md](docs/INSTALL.md)** - Detailed installation guide

## 🔧 Troubleshooting

### Python Not Found

**Error**: `Python 3 is not installed`

**Solution**: 
- Install Python 3.8+ from [python.org](https://www.python.org/downloads/)
- Ensure Python is added to PATH during installation

### Virtual Environment Fails

**Error**: `Failed to create virtual environment`

**Solution**:
- Ensure `python -m venv` works
- Check write permissions in directory
- Try running as Administrator (Windows)

### Dependencies Fail to Install

**Error**: `Failed to install dependencies`

**Solution**:
- Check internet connection
- Try: `pip install --upgrade pip`
- Some packages may require Visual C++ Build Tools (Windows)

### Module Import Errors

**Error**: `ModuleNotFoundError` or `ImportError`

**Solution**:
- Ensure virtual environment is activated
- Run: `pip install -r requirements.txt`
- Check Python version (3.8+ required)

### Optional Features Unavailable

**Info**: `websockets not available` or similar

**Solution**:
- This is normal - optional dependencies are auto-discovered
- Features gracefully degrade if dependencies are missing
- Install manually: `pip install websockets aiohttp pyyaml cryptography`
- Or use `?` menu in TUI to install missing dependencies

### PE5 Framework Not Found

**Info**: `PE5 Framework: Not available`

**Solution**:
- PE5 framework is optional
- Extract `pe5_framework.zip` if available
- Compile on Windows: See [docs/PE5_Integration.md](docs/PE5_Integration.md)

### Relay Service Issues

**Error**: Relay connection failures

**Solution**:
- Check relay configuration: `config/remote_guided.yaml`
- Verify relay daemon is running (if using relay service)
- Check network connectivity
- Review relay logs: `/var/log/ai-relay/` (Linux)

### Cross-Platform Issues

**Error**: Virtual environment from Linux doesn't work on Windows

**Solution**:
- Virtual environments are NOT portable
- Always create venv on target platform
- Use `setup_windows.bat` on Windows
- See [CROSS_PLATFORM.md](CROSS_PLATFORM.md)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd windows-lateral-movement-tui

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install development dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest

# Run linter (if configured)
pylint modules/
```
## 🙏 Acknowledgments

- **APT-41 (Winnti Group)** - TTP reference and PE5 framework(Thanks you fucks for your malware!)
- **MITRE ATT&CK** - Framework and technique mappings
- **LogHunter** - Windows event log analysis
- **MADCert** - Certificate generation
- **post-hub** - Additional PE techniques

## 📞 Support

For issues, questions, or contributions:

- **Documentation**: See `docs/` directory
- **Quick Start**: See [docs/QUICKSTART.md](docs/QUICKSTART.md)
- **Installation**: See [docs/INSTALL.md](docs/INSTALL.md)
- **Troubleshooting**: See [Troubleshooting](#troubleshooting) section

## 🔄 Version History

See [docs/CHANGELOG.md](docs/CHANGELOG.md) for version history and changes.

## 📊 Project Status

- ✅ **Core Functionality**: Complete
- ✅ **PE5 Integration**: Complete
- ✅ **Relay Service**: Complete
- ✅ **Auto-Enumeration**: Complete
- ✅ **Diagram Generation**: Complete (MITRE ATT&CK flows, network diagrams, timelines)
- ✅ **Report Organization**: Complete (date/machine+time sorted storage)
- ✅ **Test Harness**: Complete (end-to-end tests for all modules)
- ✅ **Cross-Platform**: Complete
- ✅ **Documentation**: Complete

**Current Version**: See [VERSION](VERSION)

### Recent Enhancements

- **Diagram Generation Module**: Automatic Mermaid diagram generation for attack flows, network topologies, and timelines
- **Organized Report Storage**: Reports automatically organized by date and machine+time in `enumeration_reports/`
- **Comprehensive Test Suite**: End-to-end test harness with coverage reporting for all modules

---

**⚠️ REMEMBER: This tool is for authorized security testing only. Always obtain proper authorization before use.**
=======
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
│   └── MADCert_Integration.md
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
2. Select a module from the main menu (1-11)
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

## Version

Current Version: 1.0.0

## Support

For issues, questions, or contributions, please refer to the project repository.

---

**Remember: Always obtain proper authorization before using this tool.**
>>>>>>> origin/cursor/tui-for-windows-lateral-movement-simulation-composer-1-e45e
