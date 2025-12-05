#!/usr/bin/env python3
"""
Get the path to DSSSL (secure OpenSSL fork) binary
Returns the local repository DSSSL if available, otherwise None
"""

import os
import sys
from pathlib import Path

def get_dsssl_path():
    """Get path to DSSSL binary, checking local repo first"""
    # Get repository root (assuming script is in scripts/ directory)
    script_dir = Path(__file__).parent.absolute()
    repo_root = script_dir.parent
    
    # Check local DSSSL installation
    local_dsssl = repo_root / "dsssl" / "install" / "bin" / "dsssl"
    if local_dsssl.exists() and local_dsssl.is_file():
        return str(local_dsssl)
    
    # Check for openssl in local installation (DSSSL may be symlinked as openssl)
    local_openssl = repo_root / "dsssl" / "install" / "bin" / "openssl"
    if local_openssl.exists() and local_openssl.is_file():
        return str(local_openssl)
    
    return None

def get_dsssl_command():
    """Get DSSSL command (full path or command name)"""
    local_path = get_dsssl_path()
    if local_path:
        return local_path
    
    # Fallback to system commands
    import shutil
    if shutil.which("dsssl"):
        return "dsssl"
    if shutil.which("openssl"):
        return "openssl"
    
    return None

if __name__ == "__main__":
    dsssl_path = get_dsssl_path()
    if dsssl_path:
        print(dsssl_path)
        sys.exit(0)
    else:
        # Try system command
        cmd = get_dsssl_command()
        if cmd:
            print(cmd)
            sys.exit(0)
        else:
            print("ERROR: DSSSL not found", file=sys.stderr)
            print("Build DSSSL: bash scripts/build_dsssl.sh", file=sys.stderr)
            sys.exit(1)
