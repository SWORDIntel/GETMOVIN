#!/usr/bin/env python3
"""
Download Dependencies for Offline Installation

Downloads all Python dependencies (including wheels) into a local directory
for offline installation on Windows or other systems without internet access.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse
import urllib.request
import urllib.error
import json
import zipfile
import tempfile


class DependencyDownloader:
    """Download Python dependencies for offline installation"""
    
    def __init__(self, deps_dir: str = "offline_deps", requirements_file: str = "requirements.txt"):
        self.deps_dir = Path(deps_dir)
        self.requirements_file = Path(requirements_file)
        self.workspace_root = Path(__file__).parent
        self.python_dir = self.deps_dir / "python"
    
    def download_dependencies(self, python_version: str = None, platform: str = None):
        """
        Download all dependencies from requirements.txt
        
        Args:
            python_version: Target Python version (e.g., "3.9")
            platform: Target platform (e.g., "win_amd64", "win32", "linux_x86_64")
        """
        if not self.requirements_file.exists():
            print(f"[ERROR] Requirements file not found: {self.requirements_file}")
            return False
        
        # Create dependencies directory
        self.deps_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] Downloading dependencies to: {self.deps_dir}")
        
        # Build pip download command
        cmd = [
            sys.executable, "-m", "pip", "download",
            "-r", str(self.requirements_file),
            "-d", str(self.deps_dir),
            "--no-binary", ":all:",  # Download source distributions
            "--prefer-binary",  # But prefer wheels if available
        ]
        
        # Add platform-specific options if specified
        if platform:
            cmd.extend(["--platform", platform])
            print(f"[*] Targeting platform: {platform}")
        
        if python_version:
            cmd.extend(["--python-version", python_version])
            print(f"[*] Targeting Python version: {python_version}")
        
        # For Windows, download Windows-compatible wheels
        if platform and platform.startswith("win"):
            # Also download any available wheels
            cmd_wheels = [
                sys.executable, "-m", "pip", "download",
                "-r", str(self.requirements_file),
                "-d", str(self.deps_dir),
                "--only-binary", ":all:",  # Only wheels
                "--platform", platform,
            ]
            if python_version:
                cmd_wheels.extend(["--python-version", python_version])
            
            print(f"[*] Downloading Windows wheels...")
            try:
                result = subprocess.run(cmd_wheels, check=False, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"[+] Windows wheels downloaded")
                else:
                    print(f"[!] Some wheels may not be available (this is OK)")
            except Exception as e:
                print(f"[!] Error downloading wheels: {e}")
        
        # Download source distributions and available wheels
        print(f"[*] Downloading dependencies...")
        print(f"[*] Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"[+] Dependencies downloaded successfully")
            
            # Count downloaded files
            downloaded_files = list(self.deps_dir.glob("*"))
            print(f"[+] Downloaded {len(downloaded_files)} files")
            
            # Create requirements file in deps directory
            self._create_deps_requirements()
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to download dependencies")
            print(f"[ERROR] {e.stderr}")
            return False
    
    def download_for_windows(self, python_version: str = "3.9", arch: str = "amd64"):
        """
        Download dependencies specifically for Windows
        
        Args:
            python_version: Python version (e.g., "3.9")
            arch: Architecture ("amd64" or "32")
        """
        platform = f"win_{arch}" if arch == "32" else "win_amd64"
        return self.download_dependencies(python_version=python_version, platform=platform)
    
    def _create_deps_requirements(self):
        """Create a requirements file in the deps directory"""
        if self.requirements_file.exists():
            deps_req = self.deps_dir / "requirements.txt"
            shutil.copy2(self.requirements_file, deps_req)
            print(f"[+] Created {deps_req}")
    
    def download_python(self, python_version: str = "3.11", arch: str = "amd64"):
        """
        Download Python embeddable package for Windows
        
        Args:
            python_version: Python version (e.g., "3.11")
            arch: Architecture ("amd64" or "win32")
        """
        print(f"[*] Downloading Python {python_version} embeddable package for Windows ({arch})...")
        
        # Parse version
        major, minor = python_version.split('.')[:2]
        version_str = f"{major}.{minor}"
        
        # Determine architecture string for download
        if arch == "32":
            arch_str = "win32"
            arch_dir = "win32"
        else:
            arch_str = "amd64"
            arch_dir = "amd64"
        
        # Python embeddable download URL
        # Format: https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip
        # We'll try to get the latest patch version for the given minor version
        base_url = f"https://www.python.org/ftp/python/{version_str}.0/python-{version_str}.0-embed-{arch_str}.zip"
        
        # Alternative: try to find latest patch version
        # For now, we'll use a known good URL pattern
        python_dir = self.python_dir
        python_dir.mkdir(parents=True, exist_ok=True)
        
        zip_path = python_dir / f"python-{version_str}-embed-{arch_str}.zip"
        
        # Check if already downloaded
        if zip_path.exists():
            print(f"[*] Python already downloaded: {zip_path}")
            return True
        
        # Try downloading from Python.org
        urls_to_try = [
            base_url,
            f"https://www.python.org/ftp/python/{version_str}.1/python-{version_str}.1-embed-{arch_str}.zip",
            f"https://www.python.org/ftp/python/{version_str}.2/python-{version_str}.2-embed-{arch_str}.zip",
            f"https://www.python.org/ftp/python/{version_str}.3/python-{version_str}.3-embed-{arch_str}.zip",
            f"https://www.python.org/ftp/python/{version_str}.4/python-{version_str}.4-embed-{arch_str}.zip",
            f"https://www.python.org/ftp/python/{version_str}.5/python-{version_str}.5-embed-{arch_str}.zip",
        ]
        
        downloaded = False
        for url in urls_to_try:
            try:
                print(f"[*] Trying: {url}")
                urllib.request.urlretrieve(url, zip_path)
                # Verify it's a valid zip file
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    # Check if python.exe exists in the zip
                    if any('python.exe' in name.lower() for name in zf.namelist()):
                        print(f"[+] Python downloaded successfully: {zip_path}")
                        downloaded = True
                        break
                    else:
                        zip_path.unlink()  # Remove invalid zip
            except (urllib.error.URLError, urllib.error.HTTPError, zipfile.BadZipFile) as e:
                if zip_path.exists():
                    zip_path.unlink()
                continue
        
        if not downloaded:
            print(f"[!] Could not download Python automatically")
            print(f"[!] Please download Python embeddable manually from:")
            print(f"[!] https://www.python.org/downloads/windows/")
            print(f"[!] Look for 'Windows embeddable package ({arch_dir})'")
            print(f"[!] Extract it to: {python_dir}")
            return False
        
        # Extract Python
        print(f"[*] Extracting Python...")
        extract_dir = python_dir / f"python-{version_str}-{arch_str}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_dir)
            print(f"[+] Python extracted to: {extract_dir}")
            
            # Create a symlink or copy python.exe to python_dir for easier access
            python_exe = extract_dir / "python.exe"
            if python_exe.exists():
                # Create a marker file with version info
                version_file = python_dir / "VERSION"
                version_file.write_text(f"{version_str}\n{arch_str}\n")
                print(f"[+] Python {version_str} ({arch_str}) ready")
                return True
            else:
                print(f"[!] python.exe not found in extracted package")
                return False
        except Exception as e:
            print(f"[ERROR] Failed to extract Python: {e}")
            return False
    
    def get_download_info(self):
        """Get information about downloaded dependencies"""
        if not self.deps_dir.exists():
            return None
        
        files = list(self.deps_dir.glob("*"))
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        
        return {
            "directory": str(self.deps_dir),
            "file_count": len([f for f in files if f.is_file()]),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "files": [f.name for f in files if f.is_file()][:10]  # First 10 files
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Download Python dependencies for offline installation'
    )
    parser.add_argument(
        '-d', '--deps-dir',
        default='offline_deps',
        help='Directory to store downloaded dependencies (default: offline_deps)'
    )
    parser.add_argument(
        '-r', '--requirements',
        default='requirements.txt',
        help='Requirements file (default: requirements.txt)'
    )
    parser.add_argument(
        '--windows',
        action='store_true',
        help='Download Windows-compatible dependencies'
    )
    parser.add_argument(
        '--python-version',
        default='3.9',
        help='Target Python version (default: 3.9)'
    )
    parser.add_argument(
        '--arch',
        choices=['amd64', '32'],
        default='amd64',
        help='Windows architecture: amd64 or 32 (default: amd64)'
    )
    parser.add_argument(
        '--platform',
        help='Target platform (e.g., win_amd64, win32, linux_x86_64)'
    )
    parser.add_argument(
        '--include-python',
        action='store_true',
        help='Download Python embeddable package (Windows only, use with --windows)'
    )
    
    args = parser.parse_args()
    
    downloader = DependencyDownloader(
        deps_dir=args.deps_dir,
        requirements_file=args.requirements
    )
    
    if args.windows:
        print("[*] Downloading dependencies for Windows...")
        success = downloader.download_for_windows(
            python_version=args.python_version,
            arch=args.arch
        )
        
        # Download Python if requested
        if args.include_python and success:
            print("\n[*] Downloading Python embeddable package...")
            python_success = downloader.download_python(
                python_version=args.python_version,
                arch=args.arch
            )
            if python_success:
                print("[+] Python included in offline package")
            else:
                print("[!] Python download failed, but dependencies are ready")
    elif args.platform:
        print(f"[*] Downloading dependencies for platform: {args.platform}...")
        success = downloader.download_dependencies(
            python_version=args.python_version,
            platform=args.platform
        )
    else:
        print("[*] Downloading dependencies (source distributions)...")
        success = downloader.download_dependencies(
            python_version=args.python_version
        )
    
    if success:
        info = downloader.get_download_info()
        if info:
            print(f"\n[+] Download Summary:")
            print(f"    Directory: {info['directory']}")
            print(f"    Files: {info['file_count']}")
            print(f"    Size: {info['total_size_mb']} MB")
            print(f"\n[*] To use offline installation:")
            print(f"    pip install --no-index --find-links {info['directory']} -r requirements.txt")
        print(f"\n[+] Dependencies ready for offline installation!")
    else:
        print(f"\n[ERROR] Failed to download dependencies")
        sys.exit(1)


if __name__ == '__main__':
    main()
