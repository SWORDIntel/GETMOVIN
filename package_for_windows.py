#!/usr/bin/env python3
"""
Package Tool for Windows Deployment

Creates a portable package that can be prepared on Linux and run on Windows.
Includes all dependencies and ensures cross-platform compatibility.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import json


class WindowsPackager:
    """Package the tool for Windows deployment"""
    
    def __init__(self, output_dir: str = "windows_package"):
        self.output_dir = Path(output_dir)
        self.workspace_root = Path(__file__).parent
        self.package_dir = self.output_dir / "windows-lateral-movement-tui"
    
    def create_package(self):
        """Create portable Windows package"""
        print("[*] Creating Windows package...")
        
        # Check for offline dependencies
        deps_dir = self.workspace_root / 'offline_deps'
        if deps_dir.exists():
            print(f"[*] Found offline dependencies: {deps_dir}")
        else:
            print(f"[!] No offline dependencies found - run 'python3 download_deps.py --windows' first")
            print(f"[!] Windows setup will download dependencies from internet")
        
        # Clean and create directories
        if self.package_dir.exists():
            shutil.rmtree(self.package_dir)
        self.package_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy core files
        self._copy_core_files()
        
        # Copy modules
        self._copy_modules()
        
        # Copy documentation
        self._copy_docs()
        
        # Copy config templates
        self._copy_configs()
        
        # Copy optional components
        self._copy_optional_components()
        
        # Copy offline dependencies if they exist
        self._copy_offline_deps()
        
        # Copy bundled Python if it exists
        self._copy_bundled_python()
        
        # Create Windows-specific files
        self._create_windows_files()
        
        # Create requirements file for Windows
        self._create_windows_requirements()
        
        # Create setup script
        self._create_setup_script()
        
        # Create README
        self._create_package_readme()
        
        print(f"\n[+] Package created at: {self.package_dir}")
        print(f"[*] To deploy: Copy '{self.package_dir.name}' to Windows PC")
        print(f"[*] On Windows: Run 'setup_windows.bat'")
    
    def _copy_core_files(self):
        """Copy core application files"""
        core_files = [
            'main.py',
            'requirements.txt',
            'VERSION',
            'LICENSE',
            'README.md',
        ]
        
        for file in core_files:
            src = self.workspace_root / file
            if src.exists():
                shutil.copy2(src, self.package_dir / file)
                print(f"  [✓] Copied {file}")
    
    def _copy_modules(self):
        """Copy modules directory"""
        modules_src = self.workspace_root / 'modules'
        modules_dst = self.package_dir / 'modules'
        
        if modules_src.exists():
            shutil.copytree(modules_src, modules_dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            print(f"  [✓] Copied modules/")
    
    def _copy_docs(self):
        """Copy documentation"""
        docs_src = self.workspace_root / 'docs'
        docs_dst = self.package_dir / 'docs'
        
        if docs_src.exists():
            shutil.copytree(docs_src, docs_dst)
            print(f"  [✓] Copied docs/")
    
    def _copy_configs(self):
        """Copy configuration templates"""
        config_src = self.workspace_root / 'config'
        config_dst = self.package_dir / 'config'
        
        if config_src.exists():
            shutil.copytree(config_src, config_dst)
            print(f"  [✓] Copied config/")
        else:
            config_dst.mkdir(exist_ok=True)
    
    def _copy_optional_components(self):
        """Copy optional components if they exist"""
        # PE5 framework
        pe5_src = self.workspace_root / 'pe5_framework_extracted'
        if pe5_src.exists():
            pe5_dst = self.package_dir / 'pe5_framework_extracted'
            shutil.copytree(pe5_src, pe5_dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'build'))
            print(f"  [✓] Copied pe5_framework_extracted/")
        
        # Relay service
        relay_src = self.workspace_root / 'relay'
        if relay_src.exists():
            relay_dst = self.package_dir / 'relay'
            shutil.copytree(relay_src, relay_dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            print(f"  [✓] Copied relay/")
        
        # Examples (now in docs/examples)
        examples_src = self.workspace_root / 'docs' / 'examples'
        if examples_src.exists():
            examples_dst = self.package_dir / 'docs' / 'examples'
            examples_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(examples_src, examples_dst)
            print(f"  [✓] Copied docs/examples/")
    
    def _copy_offline_deps(self):
        """Copy offline dependencies directory if it exists"""
        deps_src = self.workspace_root / 'offline_deps'
        if deps_src.exists() and deps_src.is_dir():
            deps_dst = self.package_dir / 'offline_deps'
            # Copy everything except python directory (handled separately)
            deps_dst.mkdir(parents=True, exist_ok=True)
            for item in deps_src.iterdir():
                if item.name != 'python':  # Skip python, handled separately
                    if item.is_dir():
                        shutil.copytree(item, deps_dst / item.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, deps_dst / item.name)
            print(f"  [✓] Copied offline_deps/")
        else:
            print(f"  [!] offline_deps/ not found - Windows setup will download from internet")
    
    def _copy_bundled_python(self):
        """Copy bundled Python if it exists"""
        python_src = self.workspace_root / 'offline_deps' / 'python'
        if python_src.exists() and python_src.is_dir():
            python_dst = self.package_dir / 'python'
            shutil.copytree(python_src, python_dst)
            print(f"  [✓] Copied bundled Python")
            
            # Check for version info
            version_file = python_dst / 'VERSION'
            if version_file.exists():
                version_info = version_file.read_text().strip().split('\n')
                if len(version_info) >= 2:
                    print(f"      Python {version_info[0]} ({version_info[1]})")
        else:
            print(f"  [!] Bundled Python not found - Windows setup will use system Python")
    
    def _create_windows_files(self):
        """Create Windows-specific files"""
        # Setup batch script
        setup_bat = self.package_dir / 'setup_windows.bat'
        setup_bat.write_text('''@echo off
REM Windows Setup Script
REM Run this on Windows to set up the tool

echo.
echo ========================================
echo Windows Lateral Movement Simulation TUI
echo Setup Script
echo ========================================
echo.

REM Check for bundled Python first (preferred)
set PYTHON_EXE=
set PYTHON_DIR=

if exist "python\\" (
    REM Find Python executable in bundled Python
    for /d %%d in (python\\python-*) do (
        if exist "%%d\\python.exe" (
            set PYTHON_DIR=%%d
            set PYTHON_EXE=%%d\\python.exe
            echo [*] Found bundled Python: %%d
            goto :found_python
        )
    )
)

:found_python
REM If no bundled Python, check system Python
if "%PYTHON_EXE%"=="" (
    python --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python not found.
        echo [ERROR] Please install Python 3.8+ from python.org
        echo [ERROR] Or use bundled Python by running: download_deps.py --windows --include-python
        pause
        exit /b 1
    )
    set PYTHON_EXE=python
    echo [*] Using system Python
)

REM Verify Python version
echo [*] Checking Python version...
%PYTHON_EXE% --version
if errorlevel 1 (
    echo [ERROR] Python executable not working: %PYTHON_EXE%
    pause
    exit /b 1
)

REM Create virtual environment
if not exist "venv\\" (
    echo [*] Creating virtual environment...
    %PYTHON_EXE% -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate and install dependencies
echo [*] Installing dependencies...
call venv\\Scripts\\activate.bat
pip install --upgrade pip --quiet

REM Check if offline dependencies are available
if exist "offline_deps\\" (
    echo [*] Using offline dependencies from offline_deps\\
    pip install --no-index --find-links offline_deps -r requirements.txt --quiet
    if errorlevel 1 (
        echo [WARNING] Offline installation failed, trying online...
        pip install -r requirements.txt --quiet
        if errorlevel 1 (
            echo [ERROR] Failed to install dependencies
            pause
            exit /b 1
        )
    ) else (
        echo [+] Dependencies installed from offline package
    )
) else (
    echo [*] Downloading dependencies from internet...
    pip install -r requirements.txt --quiet
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo [+] Setup complete!
echo [*] Run: run_windows.bat
echo.
pause
''')
        print(f"  [✓] Created setup_windows.bat")
        
        # Run batch script
        run_bat = self.package_dir / 'run_windows.bat'
        run_bat.write_text('''@echo off
REM Windows Launcher Script

if not exist "venv\\" (
    echo [ERROR] Virtual environment not found. Run setup_windows.bat first.
    pause
    exit /b 1
)

call venv\\Scripts\\activate.bat
python main.py %*
''')
        print(f"  [✓] Created run_windows.bat")
    
    def _create_windows_requirements(self):
        """Create Windows-specific requirements file"""
        # Requirements are the same, but ensure Windows-compatible versions
        req_file = self.package_dir / 'requirements_windows.txt'
        req_file.write_text('''# Windows Lateral Movement Simulation TUI - Dependencies
# All dependencies are cross-platform compatible

# Core Terminal UI Framework (Required)
rich>=13.0.0

# Optional: Relay Service Support
websockets>=11.0
aiohttp>=3.8.0
pyyaml>=6.0

# Optional: Advanced Security
cryptography>=41.0.0

# Note: This tool is designed for Windows execution
# Dependencies are cross-platform and will work on Windows
''')
        print(f"  [✓] Created requirements_windows.txt")
    
    def _create_setup_script(self):
        """Create Python setup script"""
        setup_py_content = '''#!/usr/bin/env python3
"""Setup script for Windows Lateral Movement Simulation TUI"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version
version_file = Path(__file__).parent / "VERSION"
version = version_file.read_text().strip() if version_file.exists() else "1.0.0"

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file) as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="windows-lateral-movement-tui",
    version=version,
    description="Windows Lateral Movement Simulation TUI - Red Team Tool",
    long_description=Path("README.md").read_text() if Path("README.md").exists() else "",
    author="Security Research Team",
    license="For authorized security testing only",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "lateral-tui=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
'''
        setup_py = self.package_dir / 'setup.py'
        setup_py.write_text(setup_py_content)
        print(f"  [✓] Created setup.py")
    
    def _create_package_readme(self):
        """Create package README"""
        readme_content = '''# Windows Lateral Movement Simulation TUI - Windows Package

This package was prepared on Linux and is ready to run on Windows.

## Quick Start on Windows

1. **Extract** this package to a directory on your Windows PC
2. **Run** `setup_windows.bat` to install dependencies
3. **Run** `run_windows.bat` to start the TUI

## Manual Setup

If the batch scripts don't work:

```cmd
REM Create virtual environment
python -m venv venv

REM Activate virtual environment
venv\\Scripts\\activate.bat

REM Install dependencies
pip install -r requirements.txt

REM Run the tool
python main.py
```

## Requirements

- Windows 7+ (Windows 10/11 recommended)
- Python 3.8 or higher
- Internet connection (for initial dependency installation)

## Cross-Platform Notes

- This package was prepared on Linux but contains only cross-platform Python code
- All dependencies are Windows-compatible
- The tool is designed to simulate Windows lateral movement techniques
- Some features require Windows-specific tools (LogHunter, etc.)

## Troubleshooting

### Python Not Found
- Install Python 3.8+ from https://www.python.org/downloads/
- Ensure Python is added to PATH during installation

### Virtual Environment Fails
- Ensure you have write permissions in the directory
- Try running as Administrator if needed

### Dependencies Fail to Install
- Check internet connection
- Try: `pip install --upgrade pip`
- Some dependencies may require Visual C++ Build Tools on Windows

## Package Contents

- `main.py` - Main application entry point
- `modules/` - All core modules
- `docs/` - Documentation
- `config/` - Configuration templates
- `requirements.txt` - Python dependencies
- `offline_deps/` - Offline dependencies (if included)
- `setup_windows.bat` - Windows setup script
- `run_windows.bat` - Windows launcher script

## Offline Dependencies

If `offline_deps/` folder is included in this package, the setup script will automatically use offline dependencies instead of downloading from the internet. This is useful for:
- Air-gapped environments
- Systems without internet access
- Faster installation
- Reproducible deployments

## Support

See `README.md` and `docs/` for detailed documentation.
'''
        readme = self.package_dir / 'PACKAGE_README.md'
        readme.write_text(readme_content)
        print(f"  [✓] Created PACKAGE_README.md")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Package tool for Windows deployment')
    parser.add_argument('-o', '--output', default='windows_package', help='Output directory')
    args = parser.parse_args()
    
    packager = WindowsPackager(output_dir=args.output)
    packager.create_package()


if __name__ == '__main__':
    main()
