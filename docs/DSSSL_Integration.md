# DSSSL Integration Guide

## Overview

This project integrates **DSSSL** (SWORDIntel's secure OpenSSL fork) directly into the repository for a **self-contained** setup. DSSSL is built locally and referenced from within the repository, ensuring all TLS operations use the secure fork without requiring system-wide installation.

**Repository:** https://github.com/SWORDIntel/DSSSL

## Why DSSSL?

DSSSL provides:
- Enhanced security hardening beyond standard OpenSSL
- Additional security features and mitigations
- Drop-in replacement compatibility
- Active security maintenance by SWORDIntel
- **Self-contained**: No system-wide installation required

## Self-Contained Installation

### Quick Build (Recommended)

DSSSL is included as a git submodule and built locally:

```bash
# Initialize and update submodules (includes DSSSL)
git submodule update --init --recursive

# Build DSSSL locally in the repository
bash scripts/build_dsssl.sh
```

This will:
- Build DSSSL from source in `dsssl/` directory
- Install to `dsssl/install/` (local to repository)
- Create `dsssl/install/bin/dsssl` binary
- All scripts automatically use the local DSSSL

### Verification

After building, verify DSSSL is available:

```bash
# Check local DSSSL
./dsssl/install/bin/dsssl version

# Or use the helper script
python3 scripts/get_dsssl_path.py
```

### Automatic Usage

All scripts automatically detect and use the local DSSSL:
- Relay service installation uses local DSSSL for certificate generation
- Certificate generation scripts prefer local DSSSL
- Falls back to system OpenSSL if local DSSSL not built

## Manual Installation (System-Wide - Optional)

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

### 1. Local DSSSL Path

DSSSL is built and installed locally in the repository:
- **Source:** `dsssl/` (git submodule)
- **Build:** `dsssl/build/` (temporary, gitignored)
- **Install:** `dsssl/install/` (local installation, gitignored)
- **Binary:** `dsssl/install/bin/dsssl`

### 2. Relay Service Certificate Generation

The relay service installation script (`relay/scripts/install.sh`) automatically detects and uses local DSSSL:

```bash
# Script checks for DSSSL in this order:
# 1. Local repository: dsssl/install/bin/dsssl
# 2. System: dsssl command in PATH
# 3. System: /usr/local/bin/dsssl
# 4. Falls back to standard openssl if not found
```

### 3. Certificate Generation

**Using Local DSSSL (Automatic):**
```bash
# Scripts automatically use local DSSSL if built
./dsssl/install/bin/dsssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /etc/ai-relay/key.pem \
    -out /etc/ai-relay/cert.pem \
    -days 365 \
    -subj "/CN=ai-relay"
```

**Using Helper Script:**
```python
# Python helper to get DSSSL path
python3 scripts/get_dsssl_path.py
```

### 4. Python SSL Module

**Note:** Python's `ssl` module uses the system's OpenSSL library. The local DSSSL binary is used for certificate generation commands, but Python's SSL module will still use system OpenSSL unless configured otherwise.

For Python SSL module to use DSSSL libraries:
```bash
# Set library path (for testing)
export LD_LIBRARY_PATH=$(pwd)/dsssl/install/lib:$LD_LIBRARY_PATH
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

**Note:** Certificate generation commands use the local DSSSL binary directly, which is sufficient for most use cases.

## Verification

### Check Local DSSSL Installation

```bash
# Check if local DSSSL is built
ls -la dsssl/install/bin/dsssl

# Verify version
./dsssl/install/bin/dsssl version

# Or use helper script
python3 scripts/get_dsssl_path.py
```

### Verify Relay Service Uses Local DSSSL

```bash
# Build DSSSL first
bash scripts/build_dsssl.sh

# Check installation script output
sudo bash relay/scripts/install.sh

# Look for: "Using DSSSL from local repository: .../dsssl/install/bin/dsssl"
```

### Test Certificate Generation

```bash
# Test local DSSSL certificate generation
./dsssl/install/bin/dsssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /tmp/test-key.pem \
    -out /tmp/test-cert.pem \
    -days 365 \
    -subj "/CN=test"

# Verify certificate
./dsssl/install/bin/dsssl x509 -in /tmp/test-cert.pem -text -noout
```

## Configuration

### Automatic Detection

All scripts automatically detect and use local DSSSL. No configuration needed.

### Manual Override

If you need to specify a custom DSSSL path:

```bash
# Use the helper script to get DSSSL path
DSSSL_CMD=$(python3 scripts/get_dsssl_path.py)

# Or specify directly
DSSSL_CMD="./dsssl/install/bin/dsssl"
```

### Git Submodule Management

DSSSL is included as a git submodule:

```bash
# Initialize submodules (first time)
git submodule update --init --recursive

# Update DSSSL to latest
cd dsssl
git pull origin main
cd ..

# Rebuild after update
bash scripts/build_dsssl.sh
```

## Troubleshooting

### DSSSL Not Built

**Problem:** Installation script reports "Using standard OpenSSL"

**Solutions:**
1. Build local DSSSL: `bash scripts/build_dsssl.sh`
2. Verify build: `ls -la dsssl/install/bin/dsssl`
3. Check build logs for errors

### Submodule Not Initialized

**Problem:** `dsssl/` directory is empty or missing

**Solutions:**
```bash
# Initialize submodules
git submodule update --init --recursive

# If submodule was removed, re-add it
git submodule add https://github.com/SWORDIntel/DSSSL.git dsssl
```

### Build Fails

**Problem:** `scripts/build_dsssl.sh` fails during compilation

**Solutions:**
1. Install build dependencies: `sudo apt-get install build-essential libssl-dev`
2. Check DSSSL source: `ls -la dsssl/`
3. Review build output for specific errors
4. Ensure sufficient disk space (build requires ~500MB)

### Python Still Uses Standard OpenSSL

**Problem:** Python's `ssl` module reports standard OpenSSL version

**Solutions:**
1. This is expected - Python SSL module uses system libraries
2. Certificate generation commands use local DSSSL binary directly
3. For Python SSL module to use DSSSL: `export LD_LIBRARY_PATH=$(pwd)/dsssl/install/lib:$LD_LIBRARY_PATH`

### Certificate Generation Fails

**Problem:** Certificate generation fails with local DSSSL

**Solutions:**
1. Verify DSSSL built: `./dsssl/install/bin/dsssl version`
2. Check binary permissions: `ls -la dsssl/install/bin/dsssl`
3. Test manually: Run certificate generation command directly
4. Fallback: Script automatically falls back to system OpenSSL

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
