# DSSSL Integration Guide

## Overview

This project integrates **DSSSL** (SWORDIntel's secure OpenSSL fork) for enhanced cryptographic security in TLS operations, particularly for the relay service.

**Repository:** https://github.com/SWORDIntel/DSSSL

## Why DSSSL?

DSSSL provides:
- Enhanced security hardening beyond standard OpenSSL
- Additional security features and mitigations
- Drop-in replacement compatibility
- Active security maintenance by SWORDIntel

## Installation

### Quick Installation (Recommended)

Use the provided installation script:

```bash
# Run the DSSSL installation helper
sudo bash relay/scripts/install_dsssl.sh
```

This script will:
- Clone the DSSSL repository
- Build and install DSSSL
- Set up proper symlinks
- Verify installation

### Manual Installation

#### Prerequisites

```bash
# Required build tools
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev git
```

#### Building DSSSL

```bash
# Clone the repository
git clone https://github.com/SWORDIntel/DSSSL.git
cd DSSSL

# Configure and build
./configure --prefix=/usr/local
make -j$(nproc)

# Install
sudo make install

# Update library cache
sudo ldconfig

# Verify installation
dsssl version
```

### Installation Paths

DSSSL can be installed in several ways:

1. **System-wide installation** (recommended):
   ```bash
   sudo make install
   # Installs to /usr/local/bin/dsssl
   ```

2. **Custom prefix**:
   ```bash
   ./configure --prefix=/opt/dsssl
   make
   sudo make install
   # Installs to /opt/dsssl/bin/dsssl
   ```

3. **Build directory usage**:
   ```bash
   # Use directly from build directory
   ./DSSSL/apps/openssl version
   ```

## Integration Points

### 1. Relay Service Certificate Generation

The relay service installation script (`relay/scripts/install.sh`) automatically detects and uses DSSSL:

```bash
# Script checks for DSSSL in this order:
# 1. `dsssl` command in PATH
# 2. `/usr/local/bin/dsssl`
# 3. Falls back to standard `openssl` if not found
```

### 2. Certificate Generation

**Using DSSSL:**
```bash
dsssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /etc/ai-relay/key.pem \
    -out /etc/ai-relay/cert.pem \
    -days 365 \
    -subj "/CN=ai-relay"
```

**Using Standard OpenSSL (fallback):**
```bash
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /etc/ai-relay/key.pem \
    -out /etc/ai-relay/cert.pem \
    -days 365 \
    -subj "/CN=ai-relay"
```

### 3. Python SSL Module

**Note:** Python's `ssl` module uses the system's OpenSSL library. To use DSSSL with Python:

1. **Replace system OpenSSL** (not recommended - may break other applications)
2. **Use LD_LIBRARY_PATH** (recommended for testing):
   ```bash
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
   ```
3. **Build Python against DSSSL** (advanced):
   - Configure Python with DSSSL library paths during compilation

## Verification

### Check DSSSL Installation

```bash
# Check if DSSSL is available
which dsssl || ls -la /usr/local/bin/dsssl

# Verify version
dsssl version
```

### Verify Relay Service Uses DSSSL

```bash
# Check installation script output
sudo bash relay/scripts/install.sh

# Look for: "Using DSSSL (secure OpenSSL fork) for certificate generation"
```

### Test Certificate Generation

```bash
# Test DSSSL certificate generation
dsssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /tmp/test-key.pem \
    -out /tmp/test-cert.pem \
    -days 365 \
    -subj "/CN=test"

# Verify certificate
dsssl x509 -in /tmp/test-cert.pem -text -noout
```

## Configuration

### Environment Variables

The relay service automatically detects DSSSL. No configuration needed.

### Manual Override

If you need to specify a custom DSSSL path:

```bash
# Edit relay/scripts/install.sh
# Modify the OPENSSL_CMD detection logic to use your custom path
OPENSSL_CMD="/opt/dsssl/bin/dsssl"
```

## Troubleshooting

### DSSSL Not Found

**Problem:** Installation script reports "Using standard OpenSSL"

**Solutions:**
1. Ensure DSSSL is installed: `which dsssl`
2. Add to PATH: `export PATH=/usr/local/bin:$PATH`
3. Create symlink: `sudo ln -s /path/to/dsssl /usr/local/bin/dsssl`

### Python Still Uses Standard OpenSSL

**Problem:** Python's `ssl` module reports standard OpenSSL version

**Solutions:**
1. Use LD_LIBRARY_PATH (see above)
2. Rebuild Python against DSSSL (advanced)
3. Note: Python SSL module compatibility is optional - certificate generation uses DSSSL directly

### Certificate Generation Fails

**Problem:** Certificate generation fails with DSSSL

**Solutions:**
1. Verify DSSSL works: `dsssl version`
2. Check permissions: `ls -la /usr/local/bin/dsssl`
3. Test manually: Run certificate generation command directly
4. Fallback: Script automatically falls back to standard OpenSSL

## Security Considerations

### Production Deployment

For production deployments:

1. **Use DSSSL** for all certificate operations
2. **Use CA-signed certificates** (not self-signed)
3. **Verify DSSSL version** regularly for security updates
4. **Monitor DSSSL repository** for security advisories

### Certificate Management

- DSSSL-generated certificates are fully compatible with standard OpenSSL
- All CNSA 2.0 requirements are met with DSSSL
- Enhanced security features in DSSSL provide additional protection

## References

- **DSSSL Repository:** https://github.com/SWORDIntel/DSSSL
- **Relay Service Documentation:** [docs/remote_guided_relay.md](remote_guided_relay.md)
- **CNSA 2.0 Specifications:** See relay architecture documentation

## Support

For DSSSL-specific issues:
- Check DSSSL repository: https://github.com/SWORDIntel/DSSSL
- Review DSSSL documentation and issues

For integration issues:
- Check relay service logs: `/var/log/ai-relay/relay.log`
- Review installation script output
- Verify DSSSL installation and PATH configuration
