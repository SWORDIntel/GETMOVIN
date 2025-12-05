#!/bin/bash
# Build DSSSL (secure OpenSSL fork) from repository
# This builds DSSSL locally within the repository for self-contained operation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DSSSL_DIR="$REPO_ROOT/dsssl"
BUILD_DIR="$DSSSL_DIR/build"
INSTALL_PREFIX="$REPO_ROOT/dsssl/install"

echo "=========================================="
echo "Building DSSSL (Secure OpenSSL Fork)"
echo "=========================================="
echo ""
echo "Repository: $REPO_ROOT"
echo "DSSSL Source: $DSSSL_DIR"
echo "Build Directory: $BUILD_DIR"
echo "Install Prefix: $INSTALL_PREFIX"
echo ""

# Check if DSSSL directory exists
if [ ! -d "$DSSSL_DIR" ]; then
    echo "ERROR: DSSSL directory not found: $DSSSL_DIR"
    echo ""
    echo "Please initialize DSSSL submodule:"
    echo "  git submodule update --init --recursive"
    echo ""
    echo "Or clone DSSSL manually:"
    echo "  git clone https://github.com/SWORDIntel/DSSSL.git $DSSSL_DIR"
    exit 1
fi

# Check if DSSSL is a git submodule (has .git file)
if [ -f "$DSSSL_DIR/.git" ] || [ -d "$DSSSL_DIR/.git" ]; then
    echo "✓ DSSSL submodule detected"
    echo "  Updating submodule (skipping optional/problematic submodules)..."
    cd "$REPO_ROOT"
    # Initialize main DSSSL submodule first
    git submodule update --init dsssl || true
    
    # Try to update submodules, but continue even if some fail
    cd "$DSSSL_DIR"
    # Disable problematic optional submodules before recursive update
    git config submodule.wycheproof.active false 2>/dev/null || true
    
    # Update submodules recursively, but don't fail on errors
    cd "$REPO_ROOT"
    git submodule update --init --recursive dsssl 2>&1 | grep -v "wycheproof" || true
else
    echo "⚠ DSSSL directory exists but may not be a submodule"
fi

cd "$DSSSL_DIR"

# Check for required build tools
echo ""
echo "Checking prerequisites..."
if ! command -v make >/dev/null 2>&1; then
    echo "ERROR: 'make' not found. Please install build-essential:"
    echo "  sudo apt-get install build-essential"
    exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
    echo "ERROR: 'gcc' not found. Please install build-essential:"
    echo "  sudo apt-get install build-essential"
    exit 1
fi

# Check for OpenSSL development libraries (for compatibility)
if ! pkg-config --exists openssl 2>/dev/null && [ ! -f /usr/include/openssl/ssl.h ]; then
    echo "⚠ Warning: OpenSSL development headers not found"
    echo "  Installing libssl-dev..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y libssl-dev || true
    fi
fi

# Configure DSSSL
echo ""
echo "Configuring DSSSL..."
if [ ! -f "Configure" ] && [ ! -f "configure" ]; then
    echo "ERROR: DSSSL source files not found"
    echo "  Please ensure DSSSL is properly cloned"
    exit 1
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with local install prefix
if [ -f "../Configure" ]; then
    # OpenSSL-style Configure script
    ../Configure --prefix="$INSTALL_PREFIX" \
        --openssldir="$INSTALL_PREFIX/ssl" \
        shared \
        no-ssl3 \
        no-ssl3-method \
        no-weak-ssl-ciphers \
        enable-tls1_3 \
        enable-ec_nistp_64_gcc_128
elif [ -f "../configure" ]; then
    # Autotools configure script
    ../configure --prefix="$INSTALL_PREFIX"
else
    echo "ERROR: Could not find Configure or configure script"
    exit 1
fi

# Build DSSSL
echo ""
echo "Building DSSSL (this may take several minutes)..."
make -j$(nproc 2>/dev/null || echo 2)

# Install to local prefix
echo ""
echo "Installing DSSSL to local directory..."
make install_sw

# Create convenience symlink for dsssl command
if [ -f "$INSTALL_PREFIX/bin/openssl" ]; then
    if [ ! -f "$INSTALL_PREFIX/bin/dsssl" ]; then
        ln -sf openssl "$INSTALL_PREFIX/bin/dsssl"
    fi
    chmod +x "$INSTALL_PREFIX/bin/dsssl"
fi

# Verify installation with LD_LIBRARY_PATH
export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib64:$LD_LIBRARY_PATH"
if "$INSTALL_PREFIX/bin/openssl" version > /dev/null 2>&1; then
    echo "✓ DSSSL installation verified"
    "$INSTALL_PREFIX/bin/openssl" version
else
    echo "⚠ Warning: DSSSL binary may need LD_LIBRARY_PATH set to $INSTALL_PREFIX/lib64"
fi
echo ""
echo "Verifying installation..."
if [ -f "$INSTALL_PREFIX/bin/dsssl" ] || [ -f "$INSTALL_PREFIX/bin/openssl" ]; then
    echo "✓ DSSSL built successfully!"
    echo ""
    echo "Installation location: $INSTALL_PREFIX"
    echo ""
    echo "Version information:"
    if [ -f "$INSTALL_PREFIX/bin/dsssl" ]; then
        "$INSTALL_PREFIX/bin/dsssl" version
    elif [ -f "$INSTALL_PREFIX/bin/openssl" ]; then
        "$INSTALL_PREFIX/bin/openssl" version
    fi
else
    echo "⚠ Warning: DSSSL binary not found after installation"
    echo "  Check build logs for errors"
    exit 1
fi

echo ""
echo "=========================================="
echo "DSSSL Build Complete!"
echo "=========================================="
echo ""
echo "Local installation: $INSTALL_PREFIX"
echo "Binary location: $INSTALL_PREFIX/bin/dsssl"
echo ""
echo "To use DSSSL in scripts, reference:"
echo "  $INSTALL_PREFIX/bin/dsssl"
echo ""
