#!/bin/bash
# Windows Lateral Movement Simulation TUI - Launcher Script
# Red Team / Threat Modeling Tool

set -e

echo ""
echo "========================================"
echo "Windows Lateral Movement Simulation TUI"
echo "Red Team / Threat Modeling Tool"
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed or not in PATH"
    echo "Please install Python 3.8+ from https://www.python.org/downloads/"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1)
echo "[INFO] $PYTHON_VERSION"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[INFO] Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "[INFO] Activating virtual environment..."
source venv/bin/activate

# Check if dependencies are installed
if ! python3 -c "import rich" &> /dev/null; then
    echo "[INFO] Installing dependencies..."
    pip install --upgrade pip --quiet
    pip install -r requirements.txt --quiet
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies"
        exit 1
    fi
    echo "[INFO] Dependencies installed successfully"
fi

# Run the tool
echo ""
echo "[INFO] Starting Windows Lateral Movement Simulation TUI..."
echo ""
python3 main.py
