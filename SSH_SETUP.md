# SSH Setup Guide

## Overview

This toolkit is **designed to be controlled entirely over SSH**. All features work when accessing the tool remotely via SSH connection.

## Quick Start Over SSH

```bash
# 1. SSH into your target system
ssh user@target-host

# 2. Navigate to toolkit directory
cd /path/to/toolkit

# 3. Run the tool
python main.py

# 4. Rich TUI displays perfectly over SSH
#    All menus, colors, and interactive features work
```

## Why Python/Rich Works Over SSH

### Rich TUI is Terminal-Based
- **Designed for terminals** - Rich is built specifically for terminal environments
- **SSH-compatible** - Works perfectly over SSH connections
- **Auto-detection** - Automatically detects terminal capabilities
- **Graceful degradation** - Falls back if advanced features unavailable

### No GUI Required
- **Pure terminal interface** - No X11 forwarding needed
- **Text-based** - Uses standard terminal features
- **ANSI colors** - Supported by all modern terminals
- **Works anywhere** - Any SSH client works (PuTTY, OpenSSH, etc.)

## Terminal Requirements

### Minimum
- Any SSH client
- Terminal with basic color support
- 80+ column width

### Recommended
- Modern SSH client (OpenSSH 7.0+)
- 256-color terminal
- 120+ column width
- UTF-8 encoding

## Setup Steps

### 1. SSH Into System

```bash
ssh user@target-host
```

### 2. Set Terminal Environment (Optional but Recommended)

```bash
# For best experience
export TERM=xterm-256color
export LANG=en_US.UTF-8

# Check terminal size
stty cols 120 rows 30
```

### 3. Run Tool

```bash
python main.py
```

### 4. Use Tool Normally

All features work:
- ✅ Interactive menus
- ✅ Color output
- ✅ Tables and panels
- ✅ Progress bars
- ✅ All modules

## Persistent Sessions

### Using tmux (Recommended)

```bash
# Start tmux session
tmux new -s lateral

# Run tool
python main.py

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t lateral
```

### Using screen

```bash
# Start screen session
screen -S lateral

# Run tool
python main.py

# Detach: Ctrl+A, then D
# Reattach: screen -r lateral
```

## Verification

Test that everything works:

```bash
# Check SSH environment
echo $SSH_CONNECTION
echo $TERM

# Run tool
python main.py

# Should see:
# - Colored banner
# - Interactive menu
# - All features working
```

## Troubleshooting

### Colors Not Showing

```bash
export TERM=xterm-256color
# Or for basic terminals
export TERM=xterm
```

### Menu Display Issues

```bash
# Ensure adequate terminal size
stty cols 120
echo $COLUMNS
```

### Special Characters Issues

```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```

## Technical Notes

### Rich TUI Over SSH

Rich automatically:
- Detects terminal via `TERM` environment variable
- Checks for color support
- Adapts output based on capabilities
- Works with any ANSI-compatible terminal

### Python Over SSH

Python execution:
- Standard input/output work perfectly
- Subprocess execution works normally
- No special configuration needed
- All modules function identically

## Best Practices

1. **Use tmux/screen** for persistent sessions
2. **Set TERM variable** before running
3. **Ensure adequate terminal size** (120+ columns recommended)
4. **Use modern SSH client** for best experience
5. **Test connection** before running operations

## Conclusion

**This tool is fully designed for SSH control.** Rich TUI works perfectly over SSH, and all features are available when accessing remotely. No special configuration needed - just SSH in and run!
