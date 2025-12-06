"""
Anti-Forensic Utilities Module

Provides utilities for anti-forensic operations including:
- File attribute manipulation (hidden, system, etc.)
- Timestamp manipulation
- Alternate Data Streams (ADS)
- File system artifact removal
- Steganography support

All operations require SYSTEM privileges for maximum effectiveness.
"""

import os
import sys
import ctypes
from ctypes import wintypes
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from modules.utils import execute_powershell, execute_cmd


# Windows API constants
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_ARCHIVE = 0x20
FILE_ATTRIBUTE_NORMAL = 0x80

INVALID_HANDLE_VALUE = -1
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2


class AntiForensics:
    """Anti-forensic utilities for file manipulation and artifact removal"""
    
    def __init__(self, lab_use: int = 0):
        self.lab_use = lab_use
        self.kernel32 = ctypes.windll.kernel32
        self.advapi32 = ctypes.windll.advapi32
        
        # Load Windows API functions
        self._load_apis()
    
    def _load_apis(self):
        """Load required Windows API functions"""
        # SetFileAttributes
        self.kernel32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        self.kernel32.SetFileAttributesW.restype = wintypes.BOOL
        
        # GetFileAttributes
        self.kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetFileAttributesW.restype = wintypes.DWORD
        
        # CreateFile for timestamp manipulation
        self.kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.SECURITY_ATTRIBUTES), wintypes.DWORD,
            wintypes.DWORD, wintypes.HANDLE
        ]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        
        # SetFileTime
        self.kernel32.SetFileTime.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME)
        ]
        self.kernel32.SetFileTime.restype = wintypes.BOOL
        
        # CloseHandle
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
    
    def set_file_attributes(self, file_path: str, hidden: bool = True, 
                           system: bool = True, readonly: bool = False,
                           archive: bool = False) -> bool:
        """
        Set file attributes (hidden, system, readonly, archive)
        
        Args:
            file_path: Path to file
            hidden: Set hidden attribute
            system: Set system attribute
            readonly: Set readonly attribute
            archive: Set archive attribute
        
        Returns:
            True if successful, False otherwise
        """
        try:
            attributes = FILE_ATTRIBUTE_NORMAL
            
            if hidden:
                attributes |= FILE_ATTRIBUTE_HIDDEN
            if system:
                attributes |= FILE_ATTRIBUTE_SYSTEM
            if readonly:
                attributes |= FILE_ATTRIBUTE_READONLY
            if archive:
                attributes |= FILE_ATTRIBUTE_ARCHIVE
            
            # Convert to wide string
            file_path_w = file_path if isinstance(file_path, str) else str(file_path)
            
            result = self.kernel32.SetFileAttributesW(file_path_w, attributes)
            return bool(result)
        except Exception as e:
            print(f"Error setting file attributes: {e}")
            return False
    
    def set_file_timestamps(self, file_path: str, 
                           creation_time: Optional[datetime] = None,
                           access_time: Optional[datetime] = None,
                           modification_time: Optional[datetime] = None,
                           randomize: bool = True) -> bool:
        """
        Set file timestamps (creation, access, modification)
        
        Args:
            file_path: Path to file
            creation_time: Creation time (None = randomize or keep)
            access_time: Access time (None = randomize or keep)
            modification_time: Modification time (None = randomize or keep)
            randomize: If True, randomize timestamps if not specified
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert datetime to FILETIME
            def datetime_to_filetime(dt: datetime) -> wintypes.FILETIME:
                if dt is None:
                    return None
                
                # Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
                epoch = datetime(1601, 1, 1)
                delta = dt - epoch
                filetime = int(delta.total_seconds() * 10000000)
                
                ft = wintypes.FILETIME()
                ft.dwLowDateTime = filetime & 0xFFFFFFFF
                ft.dwHighDateTime = filetime >> 32
                return ft
            
            # Randomize timestamps if requested
            if randomize:
                import random
                base_time = datetime.now() - timedelta(days=random.randint(30, 365))
                if creation_time is None:
                    creation_time = base_time - timedelta(days=random.randint(1, 30))
                if access_time is None:
                    access_time = base_time - timedelta(days=random.randint(1, 10))
                if modification_time is None:
                    modification_time = base_time - timedelta(days=random.randint(1, 20))
            
            # Open file handle
            file_path_w = file_path if isinstance(file_path, str) else str(file_path)
            h_file = self.kernel32.CreateFileW(
                file_path_w,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if h_file == INVALID_HANDLE_VALUE:
                return False
            
            try:
                # Convert timestamps
                creation_ft = datetime_to_filetime(creation_time) if creation_time else None
                access_ft = datetime_to_filetime(access_time) if access_time else None
                modification_ft = datetime_to_filetime(modification_time) if modification_time else None
                
                # Set file times
                result = self.kernel32.SetFileTime(
                    h_file,
                    ctypes.byref(creation_ft) if creation_ft else None,
                    ctypes.byref(access_ft) if access_ft else None,
                    ctypes.byref(modification_ft) if modification_ft else None
                )
                
                return bool(result)
            finally:
                self.kernel32.CloseHandle(h_file)
        
        except Exception as e:
            print(f"Error setting file timestamps: {e}")
            return False
    
    def create_hidden_file(self, file_path: str, content: bytes = b'',
                          hidden: bool = True, system: bool = True,
                          randomize_timestamps: bool = True) -> bool:
        """
        Create a file with anti-forensic attributes
        
        Args:
            file_path: Path to create file
            content: File content (bytes)
            hidden: Set hidden attribute
            system: Set system attribute
            randomize_timestamps: Randomize file timestamps
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Create file
            with open(file_path, 'wb') as f:
                f.write(content)
            
            # Set attributes
            self.set_file_attributes(file_path, hidden=hidden, system=system)
            
            # Randomize timestamps
            if randomize_timestamps:
                self.set_file_timestamps(file_path, randomize=True)
            
            return True
        except Exception as e:
            print(f"Error creating hidden file: {e}")
            return False
    
    def create_ads_stream(self, file_path: str, stream_name: str, 
                         content: bytes) -> bool:
        """
        Create Alternate Data Stream (ADS) on file
        
        Args:
            file_path: Path to base file
            stream_name: Name of ADS stream
            content: Content to write to stream
        
        Returns:
            True if successful, False otherwise
        """
        try:
            ads_path = f"{file_path}:{stream_name}"
            with open(ads_path, 'wb') as f:
                f.write(content)
            return True
        except Exception as e:
        # ADS creation may fail on some systems
            return False
    
    def hide_directory(self, dir_path: str) -> bool:
        """
        Hide directory by setting hidden and system attributes
        
        Args:
            dir_path: Path to directory
        
        Returns:
            True if successful, False otherwise
        """
        return self.set_file_attributes(dir_path, hidden=True, system=True)
    
    def remove_file_artifacts(self, file_path: str) -> bool:
        """
        Remove file artifacts (timestamps, attributes) for anti-forensics
        
        Args:
            file_path: Path to file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Randomize timestamps
            self.set_file_timestamps(file_path, randomize=True)
            
            # Set hidden and system attributes
            self.set_file_attributes(file_path, hidden=True, system=True)
            
            return True
        except Exception as e:
            print(f"Error removing file artifacts: {e}")
            return False
    
    def apply_anti_forensics(self, file_path: str, 
                            hidden: bool = True,
                            system: bool = True,
                            randomize_timestamps: bool = True,
                            create_ads: bool = False,
                            ads_content: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Apply comprehensive anti-forensic measures to a file
        
        Args:
            file_path: Path to file
            hidden: Set hidden attribute
            system: Set system attribute
            randomize_timestamps: Randomize file timestamps
            create_ads: Create Alternate Data Stream
            ads_content: Content for ADS stream
        
        Returns:
            Dictionary with operation results
        """
        results = {
            'file_path': file_path,
            'attributes_set': False,
            'timestamps_randomized': False,
            'ads_created': False,
            'success': False
        }
        
        try:
            # Set attributes
            if self.set_file_attributes(file_path, hidden=hidden, system=system):
                results['attributes_set'] = True
            
            # Randomize timestamps
            if randomize_timestamps:
                if self.set_file_timestamps(file_path, randomize=True):
                    results['timestamps_randomized'] = True
            
            # Create ADS if requested
            if create_ads and ads_content:
                ads_name = f"hidden_{os.urandom(4).hex()}"
                if self.create_ads_stream(file_path, ads_name, ads_content):
                    results['ads_created'] = True
                    results['ads_name'] = ads_name
            
            results['success'] = (
                results['attributes_set'] and
                (not randomize_timestamps or results['timestamps_randomized'])
            )
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def bulk_apply_anti_forensics(self, file_paths: List[str],
                                  hidden: bool = True,
                                  system: bool = True,
                                  randomize_timestamps: bool = True) -> Dict[str, Dict[str, Any]]:
        """
        Apply anti-forensic measures to multiple files
        
        Args:
            file_paths: List of file paths
            hidden: Set hidden attribute
            system: Set system attribute
            randomize_timestamps: Randomize file timestamps
        
        Returns:
            Dictionary mapping file paths to results
        """
        results = {}
        for file_path in file_paths:
            results[file_path] = self.apply_anti_forensics(
                file_path,
                hidden=hidden,
                system=system,
                randomize_timestamps=randomize_timestamps
            )
        return results


def create_hidden_file_with_anti_forensics(file_path: str, content: bytes,
                                          lab_use: int = 0) -> bool:
    """
    Convenience function to create a file with full anti-forensic measures
    
    Args:
        file_path: Path to create file
        content: File content
        lab_use: LAB_USE flag
    
    Returns:
        True if successful
    """
    af = AntiForensics(lab_use=lab_use)
    return af.create_hidden_file(file_path, content, hidden=True, system=True, randomize_timestamps=True)
