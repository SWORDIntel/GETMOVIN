#!/bin/bash
# Uninstall script for AI Relay

set -e

SERVICE_NAME="ai-relay"
INSTALL_DIR="/opt/ai-relay"
CONFIG_DIR="/etc/ai-relay"

echo "Uninstalling AI Relay..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Stop and disable service
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "Stopping service..."
    systemctl stop "$SERVICE_NAME"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    echo "Disabling service..."
    systemctl disable "$SERVICE_NAME"
fi

# Remove systemd service file
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
    echo "Removing systemd service..."
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
fi

# Remove binaries
echo "Removing binaries..."
rm -f /usr/local/bin/ai-relay
rm -f /usr/local/bin/ai-relay-health

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
fi

# Ask about config and logs
read -p "Remove configuration directory ($CONFIG_DIR)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$CONFIG_DIR"
fi

read -p "Remove log directory (/var/log/ai-relay)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /var/log/ai-relay
fi

# Remove user (optional)
read -p "Remove ai-relay user? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    userdel ai-relay 2>/dev/null || true
fi

echo ""
echo "AI Relay uninstalled successfully!"
