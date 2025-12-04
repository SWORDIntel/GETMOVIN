# MADCert Integration Guide

## Overview

MADCert (Microsoft Active Directory Certificate) integration provides certificate generation capabilities for Active Directory environments. This module wraps the MADCert tool to generate valid certificates for various use cases in lateral movement and persistence.

## Installation

1. Clone the MADCert repository:
   ```bash
   git clone https://github.com/NationalSecurityAgency/MADCert
   ```

2. Build MADCert according to the repository instructions

3. Place `madcert.exe` in your PATH or specify the path in the module

## Certificate Types

### CA Certificate
- Root certificate authority for signing other certificates
- Long validity period (default: 3650 days)
- Used as trust anchor

### Server Certificate
- For HTTPS/TLS services (WinRM, web servers)
- Supports Subject Alternative Names (SAN)
- DNS names and IP addresses
- Used for encrypted lateral movement channels

### Client Certificate
- For client authentication
- Certificate-based authentication
- Use with WinRM certificate authentication
- Enable certificate-based lateral movement

### Code Signing Certificate
- Sign DLLs and executables
- Bypass application whitelisting
- Enable DLL sideloading attacks
- Make malicious code appear legitimate

## Usage Examples

### Generate CA Certificate
```
Module 8 → Option 2
CA Name: InternalCA
Validity: 3650 days
Key Size: 2048 bits
```

### Generate Server Certificate for WinRM
```
Module 8 → Option 3
Server Name: winrm-server.example.com
CA: InternalCA
DNS Names: winrm-server.example.com, server.example.com
IP Addresses: 192.168.1.100
Validity: 365 days
```

### Generate Code Signing Certificate
```
Module 8 → Option 5
Signer Name: Microsoft Corporation
CA: InternalCA
Validity: 365 days
```

## Integration with Lateral Movement

### WinRM Certificate Authentication
1. Generate server certificate for target host
2. Install certificate on target
3. Configure WinRM to use certificate authentication
4. Use client certificate for authentication

### Code Signing for Persistence
1. Generate code signing certificate
2. Sign malicious DLLs/executables
3. Deploy signed binaries
4. Bypass application whitelisting

### HTTPS Services
1. Generate server certificates for web services
2. Include all DNS names and IPs in SAN
3. Install on web servers
4. Use for encrypted C2 channels

## OPSEC Considerations

- Use realistic certificate names matching organizational patterns
- Match existing certificate validity periods
- Distribute CA certificates to appropriate certificate stores
- Consider certificate chain validation
- Use appropriate key sizes (2048 or 4096 bits)

## Certificate Storage

Generated certificates are stored in temporary directories with the following structure:
```
madcert_XXXXXX/
├── MyCA_ca.crt
├── MyCA_ca.key
├── server_server.crt
├── server_server.key
└── ...
```

## References

- MADCert Repository: https://github.com/NationalSecurityAgency/MADCert
- Certificate-based Authentication: T1078 (Valid Accounts)
- Code Signing: T1553.002 (Subvert Trust Controls: Code Signing)
