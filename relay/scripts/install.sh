#!/bin/bash
# Installation script for AI Relay (Debian/Ubuntu)
# 
# SECURITY: This script uses DSSSL (secure OpenSSL fork) when available
# See: https://github.com/SWORDIntel/DSSSL
# Install DSSSL first: sudo bash relay/scripts/install_dsssl.sh

set -e

RELAY_USER="ai-relay"
RELAY_GROUP="ai-relay"
INSTALL_DIR="/opt/ai-relay"
CONFIG_DIR="/etc/ai-relay"
LOG_DIR="/var/log/ai-relay"
SERVICE_NAME="ai-relay"

echo "Installing AI Relay Daemon..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS $VERSION"

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-venv \
    python3-dev build-essential \
    libssl-dev \
    aiohttp websockets pyyaml

# Note: For production, install DSSSL (secure OpenSSL fork) from:
# https://github.com/SWORDIntel/DSSSL
# Use: sudo bash relay/scripts/install_dsssl.sh

# Create relay user and group
if ! id "$RELAY_USER" &>/dev/null; then
    echo "Creating user $RELAY_USER..."
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$RELAY_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/lib"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$INSTALL_DIR/scripts"

# Copy files
echo "Installing files..."
cp -r relay/src/* "$INSTALL_DIR/lib/"
cp relay/scripts/*.sh "$INSTALL_DIR/scripts/"
chmod +x "$INSTALL_DIR/scripts"/*.sh

# Create executables
cat > "$INSTALL_DIR/bin/ai-relay" <<'EOF'
#!/bin/bash
cd /opt/ai-relay/lib
exec python3 relay_daemon.py "$@"
EOF

cat > "$INSTALL_DIR/bin/ai-relay-health" <<'EOF'
#!/bin/bash
cd /opt/ai-relay/lib
exec python3 health_server.py "$@"
EOF

chmod +x "$INSTALL_DIR/bin/ai-relay"
chmod +x "$INSTALL_DIR/bin/ai-relay-health"

# Create symlinks
ln -sf "$INSTALL_DIR/bin/ai-relay" /usr/local/bin/ai-relay
ln -sf "$INSTALL_DIR/bin/ai-relay-health" /usr/local/bin/ai-relay-health

# Install configuration
if [ ! -f "$CONFIG_DIR/relay.yaml" ]; then
    echo "Installing default configuration..."
    cp relay/config/relay.yaml.example "$CONFIG_DIR/relay.yaml"
    chmod 600 "$CONFIG_DIR/relay.yaml"
    echo ""
    echo "WARNING: Please edit $CONFIG_DIR/relay.yaml and set:"
    echo "  - client_token"
    echo "  - controller_token"
    echo "  - TLS certificates (or disable TLS)"
fi

# Install systemd service
echo "Installing systemd service..."
cp relay/systemd/ai-relay.service /etc/systemd/system/
systemctl daemon-reload

# Set permissions
chown -R "$RELAY_USER:$RELAY_GROUP" "$INSTALL_DIR"
chown -R "$RELAY_USER:$RELAY_GROUP" "$LOG_DIR"
chown "$RELAY_USER:$RELAY_GROUP" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Generate self-signed certificate if TLS enabled and no cert exists
if [ ! -f "$CONFIG_DIR/cert.pem" ]; then
    echo "Generating self-signed certificate..."
    
    # Find DSSSL (secure OpenSSL fork) - check local repo first, then system
    OPENSSL_CMD=""
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    LOCAL_DSSSL="$REPO_ROOT/dsssl/install/bin/dsssl"
    
    if [ -f "$LOCAL_DSSSL" ]; then
        echo "Using DSSSL from local repository: $LOCAL_DSSSL"
        OPENSSL_CMD="$LOCAL_DSSSL"
    elif [ -f "$REPO_ROOT/dsssl/install/bin/openssl" ]; then
        echo "Using DSSSL (openssl) from local repository"
        OPENSSL_CMD="$REPO_ROOT/dsssl/install/bin/openssl"
    elif command -v dsssl >/dev/null 2>&1; then
        echo "Using DSSSL (secure OpenSSL fork) from system PATH"
        OPENSSL_CMD="dsssl"
    elif [ -f "/usr/local/bin/dsssl" ]; then
        echo "Using DSSSL from /usr/local/bin"
        OPENSSL_CMD="/usr/local/bin/dsssl"
    elif command -v openssl >/dev/null 2>&1; then
        echo "Using standard OpenSSL for certificate generation"
        echo "  Note: For enhanced security, build DSSSL: bash scripts/build_dsssl.sh"
        OPENSSL_CMD="openssl"
    else
        echo "ERROR: Neither DSSSL nor OpenSSL found."
        echo ""
        echo "Please build DSSSL locally:"
        echo "  bash scripts/build_dsssl.sh"
        echo ""
        echo "Or install system-wide:"
        echo "  https://github.com/SWORDIntel/DSSSL"
        exit 1
    fi
    
    $OPENSSL_CMD req -x509 -newkey rsa:4096 -nodes \
        -keyout "$CONFIG_DIR/key.pem" \
        -out "$CONFIG_DIR/cert.pem" \
        -days 365 \
        -subj "/CN=ai-relay"
    chown "$RELAY_USER:$RELAY_GROUP" "$CONFIG_DIR"/*.pem
    chmod 600 "$CONFIG_DIR"/*.pem
fi

echo ""
echo "=========================================="
echo "AI Relay installed successfully!"
echo ""
echo "Configuration: $CONFIG_DIR/relay.yaml"
echo "Logs: $LOG_DIR/relay.log"
echo ""
echo "To start the service:"
echo "  systemctl start $SERVICE_NAME"
echo "  systemctl enable $SERVICE_NAME"
echo ""
echo "To check status:"
echo "  systemctl status $SERVICE_NAME"
echo "  curl http://localhost:9090/healthz"
echo ""
echo "To setup Tor hidden service:"
echo "  $INSTALL_DIR/scripts/setup_tor.sh"
echo "=========================================="
