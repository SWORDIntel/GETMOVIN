# Quick Start Guide

Get up and running with the Windows Lateral Movement Simulation TUI in under 2 minutes.

## 🚀 One-Command Setup

### Windows

```batch
run.bat
```

### Linux/Mac (for testing/preparation)

```bash
./run.sh
```

**That's it!** The bootstrap script automatically:
- ✅ Checks Python 3.8+ installation
- ✅ Creates virtual environment (`venv/`)
- ✅ Installs dependencies (`rich` and optional packages)
- ✅ Launches the TUI

## 📋 Prerequisites

- **Python 3.8+** (3.9+ recommended)
- **Windows OS** (primary target) or Linux/Mac (for preparation)
- **Internet connection** (for initial dependency installation)

## 🎯 First Run

1. **Run the bootstrap script:**
   ```batch
   # Windows
   run.bat
   
   # Linux/Mac
   ./run.sh
   ```

2. **The TUI launches automatically** - You'll see the main menu

3. **Select a module** from the menu (1-12):
   - `1` - Foothold & Starting Point
   - `2` - Local Orientation
   - `3` - Identity Acquisition
   - `4` - Lateral Movement Channels
   - `5` - Consolidation & Dominance
   - `6` - OPSEC Considerations
   - `7` - LLM Remote Agent
   - `8` - MADCert Integration
   - `9` - LOLBins Reference
   - `10` - LogHunter Integration
   - `11` - Windows Moonwalk
   - `12` - **[PRIMARY] PE5 SYSTEM Escalation**

4. **Navigate** through sub-menus and execute functions

5. **Use `?`** for Component Discovery & Dependency Preloading

## ⚙️ Configuration (Optional)

### Environment Variables

Set these before running (or edit `main.py`):

```bash
# Lab mode (restricts to local IPs) - DEFAULT
export LAB_USE=1

# Auto-enumeration mode
export AUTO_ENUMERATE=1
export AUTO_ENUMERATE_DEPTH=3
```

### Quick Configuration Edit

Edit `main.py`:

```python
# Line ~20-25
LAB_USE = 1  # Set to 0 for live mode
AUTO_ENUMERATE = 0  # Set to 1 for auto-enumeration
AUTO_ENUMERATE_DEPTH = 3  # Maximum lateral movement depth
```

## 🔧 Manual Setup (If Bootstrap Fails)

### Step 1: Create Virtual Environment

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

### Step 2: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Note:** Only `rich` is required for core functionality. Optional dependencies are auto-discovered.

### Step 3: Run the Tool

```bash
python main.py
```

## 🌐 Cross-Platform Setup (Linux → Windows)

### On Linux (Preparation)

**Step 1: Download Dependencies (Optional but Recommended)**

```bash
# Download Windows-compatible dependencies for offline installation
python3 download_deps.py --windows

# This creates: offline_deps/ directory with all dependency files
```

**Step 2: Create Windows Package**

```bash
# Create Windows package (automatically includes offline_deps/ if present)
python3 package_for_windows.py

# Output: windows_package/windows-lateral-movement-tui/
# Transfer this directory to Windows PC (USB, network share, etc.)
```

### On Windows (Deployment)

```cmd
REM Navigate to package directory
cd windows-lateral-movement-tui

REM Run setup script (automatically uses offline_deps/ if available)
setup_windows.bat

REM Run the tool
run_windows.bat
```

**Offline Installation Benefits:**
- ✅ No internet required on Windows PC
- ✅ Faster installation
- ✅ Works in air-gapped environments

See [CROSS_PLATFORM.md](CROSS_PLATFORM.md) for detailed guide.

## ✨ Key Features Quick Reference

### Component Discovery

Press `?` in the main menu to:
- View all available components
- Check PE5 framework status
- Check Relay service status
- Install missing optional dependencies

### Auto-Enumeration Mode

Enable automatic comprehensive enumeration:

```bash
# Set environment variable
export AUTO_ENUMERATE=1
export AUTO_ENUMERATE_DEPTH=3

# Or edit main.py
AUTO_ENUMERATE = 1

# Run tool
python main.py
```

Auto-enumeration will:
- Enumerate all modules automatically
- Perform lateral movement up to specified depth
- Generate comprehensive reports (TXT, JSON, HTML)
- Clean up traces automatically

### PE5 SYSTEM Escalation (Primary PE Method)

Select module `12` from the main menu for:
- Kernel-level privilege escalation
- Token stealing techniques
- Integrity level elevation
- Interactive AI guidance
- Step-by-step instructions

### Optional Dependencies

The tool auto-discovers and can install:
- `websockets` - For relay client
- `aiohttp` - For relay client
- `pyyaml` - For configuration parsing
- `cryptography` - For certificate operations

**Installation:**
- Automatic on startup (silent preload)
- Manual via `?` menu option
- Manual via: `pip install websockets aiohttp pyyaml cryptography`

## 📊 Verification

Check that everything works:

```bash
# Activate virtual environment
source venv/bin/activate  # Windows: venv\Scripts\activate

# Run tool
python main.py

# Check component discovery
# Press '?' in main menu

# Check modules
python -c "from modules.pe5_system_escalation import PE5SystemEscalationModule; print('PE5: OK')"
python -c "from modules.relay_client import RelayClient; print('Relay: OK')"
python -c "from modules.auto_enumerate import AutoEnumerator; print('Auto-Enum: OK')"
```

## 🐛 Troubleshooting

### Python Not Found

**Error:** `Python 3 is not installed` or `python: command not found`

**Solution:**
- **Windows:** Install Python 3.8+ from [python.org](https://www.python.org/downloads/)
- **Linux:** `sudo apt-get install python3 python3-venv` (Debian/Ubuntu)
- **Mac:** `brew install python3`

### Virtual Environment Fails

**Error:** `Failed to create virtual environment`

**Solution:**
- Ensure Python 3.8+ is installed
- Check write permissions in directory
- Try running as Administrator (Windows)
- Try: `python -m venv --clear venv`

### Dependencies Fail to Install

**Error:** `Failed to install dependencies` or `pip install` errors

**Solution:**
- Check internet connection
- Try: `pip install --upgrade pip`
- Try: `pip install --user -r requirements.txt`
- **Windows:** May need Visual C++ Build Tools for some packages

### Module Import Errors

**Error:** `ModuleNotFoundError: No module named 'rich'`

**Solution:**
- Ensure virtual environment is activated
- Run: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.8+)

### Optional Features Unavailable

**Info:** `websockets not available` or similar messages

**Solution:**
- This is **normal** - optional dependencies are auto-discovered
- Features gracefully degrade if dependencies are missing
- Install manually: `pip install websockets aiohttp pyyaml cryptography`
- Or use `?` menu in TUI to install missing dependencies

### PE5 Framework Not Found

**Info:** `PE5 Framework: Not available`

**Solution:**
- PE5 framework is optional
- Extract `pe5_framework.zip` if available
- Compile on Windows: See [docs/PE5_Integration.md](docs/PE5_Integration.md)

### Relay Service Issues

**Error:** Relay connection failures

**Solution:**
- Check relay configuration: `config/remote_guided.yaml`
- Verify relay daemon is running (if using relay service)
- Check network connectivity
- Review relay logs: `/var/log/ai-relay/` (Linux)

### Cross-Platform Issues

**Error:** Virtual environment from Linux doesn't work on Windows

**Solution:**
- Virtual environments are **NOT portable**
- Always create venv on target platform
- Use `setup_windows.bat` on Windows
- See [CROSS_PLATFORM.md](CROSS_PLATFORM.md)

## 📚 Next Steps

- **Read [README.md](README.md)** - Comprehensive documentation
- **Read [BOOTSTRAP.md](BOOTSTRAP.md)** - Auto-bootstrap details
- **Read [CROSS_PLATFORM.md](CROSS_PLATFORM.md)** - Cross-platform guide
- **Explore modules/** - Module source code
- **Check docs/** - Detailed module documentation

## 🎓 Example Workflow

1. **Start the tool:**
   ```bash
   ./run.sh  # or run.bat on Windows
   ```

2. **Check components:**
   - Press `?` in main menu
   - Review component discovery report
   - Install missing dependencies if needed

3. **Run orientation:**
   - Select `2` - Local Orientation
   - Execute system discovery functions

4. **Acquire identity:**
   - Select `3` - Identity Acquisition
   - Harvest credentials and tokens

5. **Escalate privileges:**
   - Select `12` - PE5 SYSTEM Escalation
   - Follow interactive guidance

6. **Move laterally:**
   - Select `4` - Lateral Movement Channels
   - Establish remote sessions

7. **Consolidate:**
   - Select `5` - Consolidation & Dominance
   - Establish persistence

8. **Clean up:**
   - Select `11` - Windows Moonwalk
   - Clear traces and logs

## ✅ Self-Contained Checklist

- ✅ Single command bootstrap (`run.bat` / `run.sh`)
- ✅ Automatic virtual environment creation
- ✅ Automatic dependency installation
- ✅ Component discovery and reporting
- ✅ Optional dependency preloading
- ✅ Graceful degradation for missing components
- ✅ Cross-platform preparation support
- ✅ Complete documentation
- ✅ Clean repository structure

**The repository is production-ready and fully self-contained!**

---

**⚠️ REMEMBER: This tool is for authorized security testing only. Always obtain proper authorization before use.**
