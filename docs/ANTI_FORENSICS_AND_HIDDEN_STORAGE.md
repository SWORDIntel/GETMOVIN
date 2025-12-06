# Anti-Forensics and Hidden Storage Implementation

## Overview

This document describes the anti-forensic capabilities and hidden virtual disk storage system integrated into the LLM agent. These features leverage SYSTEM privileges to minimize forensic artifacts and provide secure temporary storage.

## Anti-Forensics Module (`modules/anti_forensics.py`)

### Features

1. **File Attribute Manipulation**
   - Set files as hidden (`FILE_ATTRIBUTE_HIDDEN`)
   - Set files as system (`FILE_ATTRIBUTE_SYSTEM`)
   - Combine attributes for maximum stealth

2. **Timestamp Randomization**
   - Randomize creation time (30-365 days ago)
   - Randomize access time (1-10 days variation)
   - Randomize modification time (1-20 days variation)
   - Prevents timeline analysis

3. **Alternate Data Streams (ADS)**
   - Create hidden data streams on files
   - Store additional data without visible file size changes
   - Useful for steganography

4. **Directory Hiding**
   - Hide entire directories with system attribute
   - Prevents normal directory enumeration

### Usage

```python
from modules.anti_forensics import AntiForensics, create_hidden_file_with_anti_forensics

# Initialize
af = AntiForensics(lab_use=0)

# Create hidden file
af.create_hidden_file(
    file_path="C:\\Windows\\Temp\\hidden.txt",
    content=b"secret data",
    hidden=True,
    system=True,
    randomize_timestamps=True
)

# Apply anti-forensics to existing file
af.apply_anti_forensics(
    file_path="existing_file.txt",
    hidden=True,
    system=True,
    randomize_timestamps=True,
    create_ads=False
)

# Convenience function
create_hidden_file_with_anti_forensics(
    file_path="C:\\Windows\\Temp\\data.bin",
    content=b"binary data"
)
```

### Integration

All generated code automatically includes anti-forensic utilities:

**Python:**
- `apply_anti_forensics_to_file()` - Apply measures to existing file
- `create_hidden_file()` - Create file with anti-forensics

**PowerShell:**
- `Set-FileAntiForensics` - Apply measures to file
- `New-HiddenFile` - Create hidden file

**C/C++:**
- `ApplyAntiForensicsToFile()` - Apply measures to file

## Hidden Virtual Disk Module (`modules/hidden_vdisk.py`)

### Features

1. **Virtual Disk Creation**
   - Create VHD/VHDX files dynamically
   - Configurable size (default: 10GB)
   - Dynamic allocation (sparse files)

2. **Hidden Mounting**
   - Mount without drive letter assignment
   - Access via volume GUID path (`\\?\Volume{...}\`)
   - Not visible in normal file system operations

3. **Full File System Access**
   - Full NTFS capabilities
   - Standard file operations
   - No restrictions on file types

4. **Automatic Anti-Forensics**
   - All stored files automatically get anti-forensic attributes
   - Hidden and system attributes applied
   - Timestamps randomized

5. **Cleanup Options**
   - Unmount without removing VHD (preserve data)
   - Remove VHD file (complete cleanup)
   - Automatic cleanup on server stop

### Usage

```python
from modules.hidden_vdisk import HiddenVirtualDisk, create_hidden_storage

# Create and mount hidden disk
vdisk = create_hidden_storage(size_gb=10, lab_use=0)

# Store file
success, dest_path = vdisk.store_file(
    source_path="C:\\temp\\loot.txt",
    dest_name="loot.txt",
    apply_anti_forensics=True
)

# Store data directly
success, dest_path = vdisk.store_data(
    data=b"secret data",
    filename="secret.txt",
    apply_anti_forensics=True
)

# List files
files = vdisk.list_files()

# Get mount info
info = vdisk.get_mount_info()
print(f"Mount Path: {info['mount_path']}")
print(f"Volume GUID: {info['volume_guid']}")

# Cleanup (unmount but keep VHD)
vdisk.cleanup(remove_vhd=False)

# Complete cleanup
vdisk.cleanup(remove_vhd=True)
```

### Integration with LLM Agent

The hidden virtual disk is automatically created when the LLM agent server starts with SYSTEM privileges:

```python
# In LLMAgentServer.__init__()
if system_privilege:
    self.hidden_vdisk = create_hidden_storage(size_gb=10, lab_use=lab_use)
    if self.hidden_vdisk:
        mount_info = self.hidden_vdisk.get_mount_info()
        self.session_data['HIDDEN_VDISK_MOUNT'] = mount_info.get('mount_path')
```

### Storage Workflow

1. **File Creation**: Generated code files are created with anti-forensic attributes
2. **Temporary Storage**: Files can be stored in hidden virtual disk
3. **Exfiltration**: Files are exfiltrated from hidden disk
4. **Cleanup**: Hidden disk is unmounted (VHD preserved for future use)

## Automatic Application

### File Creation

All files created by the code generator automatically receive anti-forensic measures:

```python
# In CodeGenerator.generate_code()
file_path = os.path.join(self.temp_dir, f'generated_{len(self.execution_history)}{ext}')
with open(file_path, 'w', encoding='utf-8') as f:
    f.write(code)

# Apply anti-forensic measures
if self.system_privilege and system_privilege:
    self.anti_forensics.apply_anti_forensics(
        file_path,
        hidden=True,
        system=True,
        randomize_timestamps=True
    )
```

### Directory Hiding

Temporary directories are hidden:

```python
# In CodeGenerator.__init__()
if system_privilege:
    self.anti_forensics.hide_directory(self.temp_dir)
```

### Generated Code

All generated code includes anti-forensic utilities and uses them automatically:

**Python Example:**
```python
# Generated code includes:
def create_hidden_file(file_path, content, apply_anti_forensics=True):
    # Creates file with hidden/system attributes and randomized timestamps
    pass

# Usage in generated code:
create_hidden_file("output.txt", "data", apply_anti_forensics=True)
```

**PowerShell Example:**
```powershell
# Generated code includes:
function New-HiddenFile {
    # Creates file with anti-forensic measures
}

# Usage:
New-HiddenFile -FilePath "output.txt" -Content "data"
```

## Security Considerations

### SYSTEM Privileges Required

- File attribute manipulation requires SYSTEM privileges
- Hidden virtual disk creation requires SYSTEM privileges
- Timestamp manipulation requires SYSTEM privileges

### Detection Avoidance

1. **File Attributes**: Hidden + System attributes prevent normal enumeration
2. **Timestamps**: Randomized timestamps prevent timeline analysis
3. **Hidden Disk**: No drive letter assignment prevents discovery via normal means
4. **Volume GUID**: Access via GUID path is less obvious than drive letters

### Limitations

1. **Forensic Tools**: Advanced forensic tools can still detect hidden files
2. **Event Logs**: Some operations may leave traces in Windows Event Logs
3. **Memory Analysis**: File operations may leave traces in memory
4. **Disk Analysis**: VHD files can be detected via disk analysis tools

## Best Practices

1. **Use Hidden Disk**: Store all temporary files in hidden virtual disk
2. **Apply Anti-Forensics**: Always apply anti-forensic measures to created files
3. **Cleanup**: Unmount hidden disk before shutdown (preserve VHD for future use)
4. **Exfiltration**: Exfiltrate files from hidden disk, then cleanup
5. **Minimize Traces**: Use hidden disk for all file operations to minimize host file system traces

## Troubleshooting

### Hidden Disk Creation Fails

- Verify SYSTEM privileges are available
- Check disk space availability
- Ensure Hyper-V/VHD support is available

### Anti-Forensics Fails

- Verify SYSTEM privileges
- Check file permissions
- Ensure file exists before applying measures

### Files Still Visible

- Verify attributes were set correctly
- Check if "Show hidden files" is enabled
- Ensure SYSTEM privileges are active

## References

- Windows File Attributes: MSDN documentation
- VHD/VHDX Format: Microsoft Virtual Hard Disk documentation
- NTFS Alternate Data Streams: MSDN documentation
- Windows Timestamp Manipulation: Windows API documentation
