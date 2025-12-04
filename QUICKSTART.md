# Quick Start Guide

## One-Command Setup

### Windows
```batch
run.bat
```

### Linux/Mac
```bash
./run.sh
```

**That's it!** The bootstrap script handles everything:
- ✅ Python version check
- ✅ Virtual environment creation
- ✅ Dependency installation
- ✅ Tool launch

## What You Get

After bootstrap, you have:
- ✅ Fully functional TUI
- ✅ All 12 modules available
- ✅ Auto-enumeration ready
- ✅ PE5 escalation module
- ✅ Relay client support
- ✅ Complete documentation

## Optional: Install Additional Features

### Relay Service (Optional)

If you want to use the relay service:

```bash
# Install relay dependencies
pip install websockets aiohttp pyyaml

# Or install relay service
cd relay
sudo ./scripts/install.sh
```

### PE5 Framework (Optional)

The PE5 framework source is included but needs compilation:

```bash
cd pe5_framework_extracted/pe5_framework
python build.py all
```

## First Run

1. Run bootstrap: `./run.sh` or `run.bat`
2. Tool launches automatically
3. Select modules from menu
4. Use option 12 for PE5 SYSTEM escalation
5. Set `AUTO_ENUMERATE=1` in `main.py` for automatic enumeration

## Verification

Check that everything works:

```bash
# Activate venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Run tool
python main.py

# Check modules
python -c "from modules.pe5_system_escalation import PE5SystemEscalationModule; print('PE5: OK')"
python -c "from modules.relay_client import RelayClient; print('Relay: OK')"
python -c "from modules.auto_enumerate import AutoEnumerator; print('Auto-Enum: OK')"
```

## Troubleshooting

**Problem**: Python not found  
**Solution**: Install Python 3.8+ from python.org

**Problem**: Dependencies fail  
**Solution**: Check internet, try: `pip install --upgrade pip`

**Problem**: Optional features unavailable  
**Solution**: This is normal - optional features are gracefully disabled

## Repository Structure

```
/
├── main.py              # Entry point
├── run.bat / run.sh     # Bootstrap scripts
├── requirements.txt     # Dependencies (rich only)
├── modules/             # All modules
├── relay/               # Relay service (optional)
├── pe5_framework_extracted/  # PE5 framework (optional)
├── config/              # Config templates
└── docs/                # Documentation
```

## Self-Contained Checklist

- ✅ Single command bootstrap
- ✅ Automatic setup
- ✅ No external downloads (except pip)
- ✅ All code included
- ✅ Graceful optional dependencies
- ✅ Clean structure
- ✅ Complete documentation

**The repository is production-ready and fully self-contained!**
