# Quick Start Guide

Get up and running in 60 seconds!

## Windows Users

1. **Double-click `run.bat`**
   - That's it! The script handles everything

## Linux/Mac Users

1. **Make script executable:**
   ```bash
   chmod +x run.sh
   ```

2. **Run the script:**
   ```bash
   ./run.sh
   ```

## What Happens

The run script automatically:
- ✅ Checks for Python 3.8+
- ✅ Creates virtual environment
- ✅ Installs dependencies
- ✅ Launches the tool

## First Run

1. You'll see the main menu
2. Select a module (1-11)
3. Explore the features!

## Configuration

Edit `main.py` to change settings:

```python
LAB_USE = 1              # Lab mode (safe testing)
AUTO_ENUMERATE = 0       # Auto-enumeration mode
AUTO_ENUMERATE_DEPTH = 3 # Lateral movement depth
```

## Need Help?

- Read `README.md` for full documentation
- Check `INSTALL.md` for detailed installation
- Review `docs/` for module-specific guides

---

**Ready to start? Run `run.bat` (Windows) or `./run.sh` (Linux/Mac)!**
