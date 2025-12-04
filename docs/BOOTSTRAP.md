# Bootstrap & Self-Contained Repository Guide

## Overview

This repository is **fully self-contained** and **auto-bootstraps** everything needed to run the Windows Lateral Movement Simulation TUI.

## Auto-Bootstrap Process

### Quick Start

**Windows:**
```batch
run.bat
```

**Linux/Mac (for testing):**
```bash
./run.sh
```

### What Gets Auto-Bootstrapped

1. **Python Version Check**
   - Verifies Python 3.8+ is installed
   - Shows version information
   - Exits gracefully if not found

2. **Virtual Environment Creation**
   - Creates `venv/` directory if it doesn't exist
   - Isolates dependencies from system Python

3. **Dependency Installation**
   - Checks if `rich` package is installed
   - Automatically installs from `requirements.txt` if missing
   - Upgrades pip silently
   - Installs dependencies quietly

4. **Tool Launch**
   - Activates virtual environment
   - Runs `main.py`
   - Handles errors gracefully

## Self-Contained Structure

### Core Components (Always Included)

```
/
├── main.py                    # Main entry point
├── run.bat                    # Windows bootstrap script
├── run.sh                     # Linux/Mac bootstrap script
├── requirements.txt           # Core dependencies (rich only)
├── setup.py                   # Python package setup
├── modules/                   # All core modules
│   ├── __init__.py
│   ├── utils.py
│   ├── foothold.py
│   ├── orientation.py
│   ├── identity.py
│   ├── lateral.py
│   ├── consolidation.py
│   ├── opsec.py
│   ├── llm_agent.py
│   ├── llm_client.py
│   ├── madcert_integration.py
│   ├── lolbins_reference.py
│   ├── auto_enumerate.py
│   ├── loghunter_integration.py
│   ├── pe5_system_escalation.py  # NEW: PE5 module
│   ├── pe5_utils.py              # NEW: PE5 utilities
│   ├── relay_client.py           # NEW: Relay client
│   ├── memshadow_protocol.py
│   └── memshadow_client.py
├── config/                    # Configuration templates
│   └── remote_guided.yaml.example
├── docs/                      # Documentation
│   ├── Auto_Enumeration.md
│   ├── Auto_Enumeration_Enhancements.md
│   ├── PE5_Integration.md
│   ├── PE5_UI_Integration.md
│   ├── remote_guided_relay.md
│   └── ...
└── docs/
    └── examples/               # Example scripts
        └── llm_agent_example.py
```

### Optional Components (Gracefully Handled)

```
/
├── pe5_framework_extracted/   # PE5 framework source (optional)
│   └── pe5_framework/
│       ├── README.md
│       ├── build.py
│       └── ...
├── relay/                     # Relay service (optional)
│   ├── src/
│   ├── config/
│   ├── scripts/
│   └── ...
```

## Dependency Management

### Core Dependencies (Required)

- **rich>=13.0.0** - Terminal UI framework
  - Only dependency needed for core functionality
  - Auto-installed by bootstrap scripts

### Optional Dependencies (Gracefully Handled)

The following dependencies are **optional** and handled with try/except blocks:

- **websockets** - For relay client/server
- **aiohttp** - For relay health server
- **pyyaml** - For configuration file parsing
- **cryptography** - For TLS/CNSA 2.0 support

**Behavior:**
- If optional dependencies are missing, related features are disabled
- No errors are raised
- Tool continues to function normally
- User is informed via logging if features are unavailable

## Bootstrap Scripts

### run.bat (Windows)

```batch
1. Check Python installation
2. Check Python version
3. Create venv if needed
4. Activate venv
5. Check for rich package
6. Install dependencies if needed
7. Run main.py
8. Handle errors gracefully
```

### run.sh (Linux/Mac)

```bash
1. Check Python3 installation
2. Check Python version
3. Create venv if needed
4. Activate venv
5. Check for rich package
6. Install dependencies if needed
7. Run main.py
8. Handle errors gracefully
```

## Module Import Handling

All modules use graceful import handling:

```python
# Example from relay_client.py
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    # Feature disabled, no error raised
```

## Configuration Files

### Default Locations (Checked in Order)

1. `~/.config/ai-relay/client.yaml` (user config)
2. `/etc/ai-relay/client.yaml` (system config)
3. `config/remote_guided.yaml` (project config)

**Behavior:**
- If config files don't exist, defaults are used
- No errors raised
- Tool functions with defaults

## PE5 Framework

### Availability Check

The tool checks for PE5 framework:
- Path: `pe5_framework_extracted/pe5_framework/`
- If exists: Reports availability
- If not exists: Reports as unavailable
- No errors raised

### Compilation Status

- Checks for `build/bin/` directory
- Lists available binaries
- Reports compilation status
- No errors if not compiled

## Relay Service

### Client Side

- Checks for relay configuration
- If config found: Reports connectivity options
- If not found: Reports as not configured
- No errors raised

### Server Side

Relay daemon has its own requirements:
- `relay/requirements.txt` - Separate dependency file
- Installed separately via `relay/scripts/install.sh`
- Not required for main TUI operation

## Error Handling

### Graceful Degradation

1. **Missing Optional Modules**
   - Feature disabled
   - Warning logged
   - Tool continues

2. **Missing Configuration**
   - Defaults used
   - Info logged
   - Tool continues

3. **Missing External Tools**
   - Feature disabled
   - Info logged
   - Tool continues

### Error Messages

All errors are:
- Clear and actionable
- Non-fatal when possible
- Logged appropriately
- User-friendly

## Verification

### Check Bootstrap

```bash
# Test bootstrap (dry run)
python3 -c "import sys; print(f'Python {sys.version}')"
python3 -m venv --help
pip --version
```

### Check Dependencies

```bash
# After bootstrap
source venv/bin/activate  # or venv\Scripts\activate on Windows
python3 -c "import rich; print('rich:', rich.__version__)"
```

### Check Optional Dependencies

```bash
python3 -c "import websockets; print('websockets: OK')" || echo "websockets: Not installed (optional)"
python3 -c "import yaml; print('yaml: OK')" || echo "yaml: Not installed (optional)"
python3 -c "import aiohttp; print('aiohttp: OK')" || echo "aiohttp: Not installed (optional)"
```

## Installation Verification

After running bootstrap:

1. **Virtual Environment**: `venv/` directory exists
2. **Dependencies**: `rich` package installed
3. **Tool Runs**: `python main.py` executes successfully
4. **Modules Load**: All core modules import successfully
5. **Optional Features**: Checked gracefully, no errors

## Self-Contained Checklist

- ✅ Single command bootstrap (`run.bat` or `run.sh`)
- ✅ Automatic virtual environment creation
- ✅ Automatic dependency installation
- ✅ Graceful handling of optional dependencies
- ✅ No external downloads required (except pip packages)
- ✅ All code included in repository
- ✅ Configuration templates included
- ✅ Documentation included
- ✅ Examples included
- ✅ Error handling for missing components
- ✅ Clean structure
- ✅ No hardcoded paths (uses relative paths)
- ✅ Cross-platform support (Windows/Linux/Mac)

## Repository Structure

```
windows-lateral-movement-tui/
├── Core (Required)
│   ├── main.py
│   ├── modules/
│   ├── run.bat / run.sh
│   ├── requirements.txt
│   └── setup.py
├── Optional Components
│   ├── pe5_framework_extracted/  # PE5 framework
│   ├── relay/                     # Relay service
│   └── config/                    # Config templates
├── Documentation
│   ├── README.md
│   ├── BOOTSTRAP.md (this file)
│   ├── docs/
│   └── INSTALL.md
└── Examples
    └── examples/
```

## Usage

### First Time

```bash
# Clone/extract repository
cd windows-lateral-movement-tui

# Run bootstrap (one command)
./run.sh  # or run.bat on Windows

# Tool launches automatically
```

### Subsequent Runs

```bash
# Just run bootstrap again (checks everything)
./run.sh  # or run.bat

# Or activate venv and run directly
source venv/bin/activate  # Windows: venv\Scripts\activate
python main.py
```

## Troubleshooting

### Python Not Found

**Error**: `Python 3 is not installed`
**Solution**: Install Python 3.8+ from python.org

### Virtual Environment Fails

**Error**: `Failed to create virtual environment`
**Solution**: Ensure `python3 -m venv` works, check permissions

### Dependencies Fail

**Error**: `Failed to install dependencies`
**Solution**: Check internet connection, try: `pip install --upgrade pip`

### Optional Features Unavailable

**Info**: `websockets not available`
**Solution**: Install optional dependencies: `pip install websockets aiohttp pyyaml`

## Summary

✅ **Fully Self-Contained**: All code included  
✅ **Auto-Bootstrap**: Single command setup  
✅ **Graceful Degradation**: Optional features handled elegantly  
✅ **Clean Structure**: Well-organized repository  
✅ **Cross-Platform**: Works on Windows/Linux/Mac  
✅ **No External Downloads**: Except pip packages (which are cached)  
✅ **Error Handling**: Comprehensive error handling  
✅ **Documentation**: Complete documentation included  

The repository is **production-ready** and **fully self-contained**.
