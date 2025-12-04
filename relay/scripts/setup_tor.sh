#!/bin/bash
# Setup Tor hidden service for AI Relay

set -e

RELAY_USER="ai-relay"
TOR_HIDDEN_SERVICE_DIR="/var/lib/tor/ai-relay"
TOR_CONFIG_DIR="/etc/tor"
RELAY_PORT=8889

echo "Setting up Tor hidden service for AI Relay..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Check if Tor is installed
if ! command -v tor &> /dev/null; then
    echo "Tor is not installed. Installing..."
    apt-get update
    apt-get install -y tor
fi

# Create relay user if it doesn't exist
if ! id "$RELAY_USER" &>/dev/null; then
    useradd -r -s /bin/false "$RELAY_USER"
fi

# Create Tor hidden service directory
mkdir -p "$TOR_HIDDEN_SERVICE_DIR"
chown debian-tor:debian-tor "$TOR_HIDDEN_SERVICE_DIR"
chmod 700 "$TOR_HIDDEN_SERVICE_DIR"

# Create Tor configuration snippet
cat > "$TOR_CONFIG_DIR/torrc.d/ai-relay.conf" <<EOF
# AI Relay Hidden Service Configuration
HiddenServiceDir $TOR_HIDDEN_SERVICE_DIR
HiddenServicePort $RELAY_PORT 127.0.0.1:$RELAY_PORT
EOF

# Restart Tor to generate hidden service
systemctl restart tor

# Wait for hidden service to be created
echo "Waiting for Tor hidden service to be created..."
sleep 5

# Display .onion address
if [ -f "$TOR_HIDDEN_SERVICE_DIR/hostname" ]; then
    ONION_ADDRESS=$(cat "$TOR_HIDDEN_SERVICE_DIR/hostname")
    echo ""
    echo "=========================================="
    echo "Tor hidden service configured!"
    echo "Onion address: $ONION_ADDRESS"
    echo "Port: $RELAY_PORT"
    echo ""
    echo "Update relay.yaml with:"
    echo "  controller:"
    echo "    endpoint: \"ws://$ONION_ADDRESS:$RELAY_PORT\""
    echo "=========================================="
else
    echo "Warning: Hidden service hostname not found. Check Tor logs."
fi

echo ""
echo "Tor setup complete!"
