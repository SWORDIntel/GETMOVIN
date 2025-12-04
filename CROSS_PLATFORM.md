# Cross-Platform Setup Guide

This tool can be **prepared on Linux** and **deployed to Windows** for execution.

## Overview

- **Development/Preparation**: Linux (or any platform)
- **Target Execution**: Windows PC
- **Dependencies**: Cross-platform Python packages only

## Preparing Package on Linux

### Option 1: Automated Packaging

```bash
# Create Windows package
python3 package_for_windows.py

# This creates: windows_package/windows-lateral-movement-tui/
# Transfer this directory to Windows PC
```

### Option 2: Manual Preparation

```bash
# On Linux, create a clean copy
mkdir -p windows_package/windows-lateral-movement-tui
cp -r modules/ docs/ config/ examples/ windows_package/windows-lateral-movement-tui/
cp main.py requirements.txt VERSION LICENSE README.md windows_package/windows-lateral-movement-tui/

# Copy optional components if they exist
[ -d pe5_framework_extracted ] && cp -r pe5_framework_extracted windows_package/windows-lateral-movement-tui/
[ -d relay ] && cp -r relay windows_package/windows-lateral-movement-tui/

# Transfer windows_package/ to Windows PC
```

## Deploying to Windows

### Step 1: Transfer Package

Copy the `windows-lateral-movement-tui` directory to your Windows PC (via USB, network share, etc.)

### Step 2: Setup on Windows

```cmd
REM Navigate to package directory
cd windows-lateral-movement-tui

REM Run setup script
setup_windows.bat
```

This will:
- Check for Python installation
- Create virtual environment
- Install all dependencies
- Set up the tool

### Step 3: Run on Windows

```cmd
REM Run the TUI
run_windows.bat
```

Or manually:

```cmd
venv\Scripts\activate.bat
python main.py
```

## Cross-Platform Compatibility

### Python Dependencies

All dependencies in `requirements.txt` are **cross-platform**:

- ✅ `rich` - Pure Python, works on Windows/Linux/Mac
- ✅ `websockets` - Cross-platform networking
- ✅ `aiohttp` - Cross-platform async HTTP
- ✅ `pyyaml` - Cross-platform YAML parser
- ✅ `cryptography` - Cross-platform crypto (has Windows binaries)

### Platform-Specific Considerations

#### Windows-Specific Features

Some modules require Windows-specific tools:

- **LogHunter**: Windows executable (`.exe`) - must be on Windows PC
- **PE5 Framework**: C code compiled for Windows - compile on Windows
- **Windows Moonwalk**: Windows-specific techniques

#### Linux Preparation Benefits

- Can prepare package structure
- Can verify Python code syntax
- Can create documentation
- Can test packaging scripts
- **Cannot** compile Windows executables
- **Cannot** test Windows-specific features

## Virtual Environment Portability

**Important**: Virtual environments are **NOT** portable between platforms.

- Linux venv → Windows: ❌ Won't work (different binaries)
- Windows venv → Linux: ❌ Won't work

**Solution**: Always create venv on the target platform (Windows).

The packaging script creates `setup_windows.bat` which handles this automatically.

## Dependency Installation

### On Linux (Preparation)

```bash
# Can install to verify requirements.txt is valid
pip install -r requirements.txt

# But don't package the venv - create fresh on Windows
```

### On Windows (Deployment)

```bash
# Fresh installation on Windows
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Package Structure

```
windows-lateral-movement-tui/
├── main.py                    # Cross-platform Python
├── modules/                   # Cross-platform Python
├── requirements.txt           # Cross-platform dependencies
├── setup_windows.bat          # Windows setup script
├── run_windows.bat            # Windows launcher
├── docs/                      # Documentation
├── config/                    # Config templates
├── pe5_framework_extracted/  # Source code (compile on Windows)
└── relay/                     # Cross-platform Python
```

## Verification Checklist

### On Linux (Before Packaging)

- [ ] All Python files are syntactically correct
- [ ] `requirements.txt` is complete
- [ ] Documentation is included
- [ ] Config templates are included
- [ ] Package script runs successfully

### On Windows (After Deployment)

- [ ] Python 3.8+ is installed
- [ ] Virtual environment created successfully
- [ ] All dependencies installed without errors
- [ ] `python main.py` runs successfully
- [ ] TUI displays correctly
- [ ] Modules load without errors

## Troubleshooting

### "Module not found" on Windows

**Cause**: Dependencies not installed in Windows venv

**Solution**:
```cmd
venv\Scripts\activate.bat
pip install -r requirements.txt
```

### "Python not found" on Windows

**Cause**: Python not in PATH

**Solution**: 
- Reinstall Python and check "Add Python to PATH"
- Or use full path: `C:\Python39\python.exe main.py`

### Import Errors on Windows

**Cause**: Platform-specific binary dependencies

**Solution**: Some packages (like `cryptography`) may need Visual C++ Build Tools:
- Download from: https://visualstudio.microsoft.com/downloads/
- Install "C++ build tools" workload

### Virtual Environment Issues

**Cause**: Venv created on wrong platform

**Solution**: Always create venv on target platform:
```cmd
# Delete old venv
rmdir /s venv

# Create fresh venv
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Best Practices

1. **Always package on Linux** - Cleaner, easier automation
2. **Never package venv** - Create fresh on Windows
3. **Include all source code** - Don't rely on compiled binaries
4. **Test on Windows** - Verify after deployment
5. **Document platform requirements** - Clear instructions

## Summary

✅ **Can be prepared on Linux**  
✅ **Can be deployed to Windows**  
✅ **Dependencies are cross-platform**  
✅ **Virtual environment created on Windows**  
✅ **Tool runs natively on Windows**  

The tool is designed for **Windows execution** but can be **prepared and packaged on any platform**.
