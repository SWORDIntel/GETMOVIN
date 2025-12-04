#!/usr/bin/env python3
"""
Bootstrap Requirements Preloader

Preloads all requirements from requirements.txt before starting the TUI.
Can be run standalone or imported.
"""

import sys
import subprocess
from pathlib import Path


def preload_requirements(requirements_file: str = None, quiet: bool = False) -> bool:
    """Preload requirements from requirements.txt"""
    if requirements_file is None:
        # Find requirements.txt relative to this script
        script_dir = Path(__file__).parent
        requirements_file = script_dir / 'requirements.txt'
    
    if not Path(requirements_file).exists():
        if not quiet:
            print(f"[!] requirements.txt not found at {requirements_file}")
        return False
    
    if not quiet:
        print(f"[*] Preloading requirements from {requirements_file}...")
    
    try:
        # Use pip to install requirements
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '--upgrade', '-r', str(requirements_file)],
            capture_output=quiet,
            timeout=300,
            check=False
        )
        
        if result.returncode == 0:
            if not quiet:
                print("[+] Requirements preloaded successfully")
            return True
        else:
            if not quiet:
                print(f"[!] Failed to preload requirements: {result.stderr.decode() if result.stderr else 'Unknown error'}")
            return False
    
    except Exception as e:
        if not quiet:
            print(f"[!] Error preloading requirements: {e}")
        return False


if __name__ == '__main__':
    quiet = '--quiet' in sys.argv or '-q' in sys.argv
    success = preload_requirements(quiet=quiet)
    sys.exit(0 if success else 1)
