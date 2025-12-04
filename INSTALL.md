# Installation Guide

## Quick Installation

### Windows

1. **Download or clone the repository**
2. **Double-click `run.bat`**
   - The script will automatically set up everything

### Linux/Mac

1. **Download or clone the repository**
2. **Make script executable:**
   ```bash
   chmod +x run.sh
   ```
3. **Run the script:**
   ```bash
   ./run.sh
   ```

## Manual Installation

### Step 1: Prerequisites

- **Python 3.8 or higher**
  - Download from: https://www.python.org/downloads/
  - Ensure "Add Python to PATH" is checked during installation

### Step 2: Extract/Clone Repository

```bash
# If using git
git clone <repository-url>
cd windows-lateral-movement-tui

# Or extract ZIP file
unzip windows-lateral-movement-tui.zip
cd windows-lateral-movement-tui
```

### Step 3: Create Virtual Environment

**Windows:**
```batch
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 5: Verify Installation

```bash
python -c "import rich; print('Installation successful!')"
```

### Step 6: Run the Tool

```bash
python main.py
```

## Offline Installation

If you need to install without internet access:

1. **On a machine with internet:**
   ```bash
   pip download -r requirements.txt -d packages/
   ```

2. **Copy the `packages/` directory to the target machine**

3. **Install from local packages:**
   ```bash
   pip install --no-index --find-links=packages/ -r requirements.txt
   ```

## Troubleshooting

### Issue: "Python is not recognized"

**Solution:**
- Add Python to your system PATH
- Or use full path: `C:\Python3x\python.exe main.py`

### Issue: "pip is not recognized"

**Solution:**
- Ensure Python was installed with pip
- Try: `python -m pip install -r requirements.txt`

### Issue: "Permission denied" (Linux/Mac)

**Solution:**
- Don't use `sudo` for pip install in virtual environment
- Ensure virtual environment is activated
- Check file permissions: `chmod +x run.sh`

### Issue: "Module not found"

**Solution:**
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt --force-reinstall`
- Check Python version: `python --version` (should be 3.8+)

### Issue: "Virtual environment activation fails"

**Windows:**
```batch
# If Scripts\activate.bat doesn't work, try:
venv\Scripts\python.exe main.py
```

**Linux/Mac:**
```bash
# Use direct Python path:
venv/bin/python3 main.py
```

## System Requirements

- **Operating System:** Windows 7/8/10/11, Windows Server 2012+
- **Python:** 3.8 or higher
- **RAM:** 512 MB minimum
- **Disk Space:** 100 MB for tool + dependencies
- **Privileges:** Administrator (for some operations)

## Optional Tools

These tools enhance functionality but are not required:

- **LogHunter:** Advanced log analysis
  - Download from: https://github.com/CICADA8-Research/LogHunter
  - Place `loghunter.exe` in PATH or tool directory

- **MADCert:** Certificate generation
  - Download from: https://github.com/NationalSecurityAgency/MADCert
  - Place `madcert.exe` in PATH or tool directory

## Verification

After installation, verify everything works:

```bash
# Test Python
python --version

# Test dependencies
python -c "import rich; print('Rich library OK')"

# Test tool launch
python main.py
# Should see the main menu
```

## Next Steps

1. Review `README.md` for usage instructions
2. Check `docs/` directory for module-specific documentation
3. Configure `LAB_USE` and `AUTO_ENUMERATE` in `main.py` if needed
4. Start using the tool!

## Support

For installation issues:
1. Check Python version: `python --version`
2. Verify virtual environment: `which python` (should point to venv)
3. Check dependencies: `pip list`
4. Review error messages carefully

---

**Remember: This tool is for authorized testing only.**
