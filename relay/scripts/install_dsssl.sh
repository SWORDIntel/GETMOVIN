#!/bin/bash
# DSSSL Installation Helper Script (System-Wide Installation)
# 
# NOTE: DSSSL is now self-contained in the repository.
# For self-contained build, use: bash scripts/build_dsssl.sh
#
# This script is for system-wide installation only.
# Repository: https://github.com/SWORDIntel/DSSSL

set -e

echo "=========================================="
echo "DSSSL System-Wide Installation"
echo "=========================================="
echo ""
echo "NOTE: DSSSL is now self-contained in this repository."
echo "For local build (recommended), use:"
echo "  bash scripts/build_dsssl.sh"
echo ""
echo "This script installs DSSSL system-wide (optional)."
echo "Press Ctrl+C to cancel, or Enter to continue..."
read
echo ""

DSSSL_REPO="https://github.com/SWORDIntel/DSSSL.git"
INSTALL_PREFIX="/usr/local"
BUILD_DIR="/tmp/dsssl-build"

echo "=========================================="
echo "DSSSL (Secure OpenSSL Fork) Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check for required tools
echo "Checking prerequisites..."
if ! command -v git >/dev/null 2>&1; then
    echo "Installing git..."
    apt-get update
    apt-get install -y git
fi

if ! command -v make >/dev/null 2>&1; then
    echo "Installing build tools..."
    apt-get update
    apt-get install -y build-essential
fi

# Install OpenSSL development libraries (for compatibility)
if ! dpkg -l | grep -q libssl-dev; then
    echo "Installing OpenSSL development libraries..."
    apt-get update
    apt-get install -y libssl-dev
fi

# Clone DSSSL repository
echo ""
echo "Cloning DSSSL repository..."
if [ -d "$BUILD_DIR" ]; then
    echo "Removing existing build directory..."
    rm -rf "$BUILD_DIR"
fi

git clone "$DSSSL_REPO" "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure and build
echo ""
echo "Configuring DSSSL..."
./configure --prefix="$INSTALL_PREFIX"

echo ""
echo "Building DSSSL (this may take several minutes)..."
make -j$(nproc)

# Install
echo ""
echo "Installing DSSSL..."
make install

# Create symlink for 'dsssl' command if not exists
if [ ! -f "$INSTALL_PREFIX/bin/dsssl" ] && [ -f "$INSTALL_PREFIX/bin/openssl" ]; then
    echo "Creating 'dsssl' symlink..."
    ln -sf "$INSTALL_PREFIX/bin/openssl" "$INSTALL_PREFIX/bin/dsssl"
fi

# Update library cache
if command -v ldconfig >/dev/null 2>&1; then
    echo "Updating library cache..."
    ldconfig
fi

# Verify installation
echo ""
echo "Verifying installation..."
if command -v dsssl >/dev/null 2>&1 || [ -f "$INSTALL_PREFIX/bin/dsssl" ]; then
    echo "✓ DSSSL installed successfully!"
    echo ""
    echo "Version information:"
    if command -v dsssl >/dev/null 2>&1; then
        dsssl version
    elif [ -f "$INSTALL_PREFIX/bin/dsssl" ]; then
        "$INSTALL_PREFIX/bin/dsssl" version
    fi
else
    echo "⚠ Warning: DSSSL command not found in PATH"
    echo "  Installed to: $INSTALL_PREFIX/bin/"
    echo "  Add to PATH or use full path: $INSTALL_PREFIX/bin/dsssl"
fi

# Cleanup
echo ""
echo "Cleaning up build directory..."
rm -rf "$BUILD_DIR"

echo ""
echo "=========================================="
echo "DSSSL Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Run relay installation: sudo bash relay/scripts/install.sh"
echo "2. The relay installer will automatically detect and use DSSSL"
echo ""
echo "For more information, see:"
echo "  - DSSSL Repository: https://github.com/SWORDIntel/DSSSL"
echo "  - Integration Guide: docs/DSSSL_Integration.md"
echo ""
