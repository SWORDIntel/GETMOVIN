# Using This Tool Over SSH

## Overview

This toolkit is **designed to be controlled entirely over SSH**. All features work when accessing the tool remotely via SSH.

## How It Works

### Accessing the Tool Over SSH

```bash
# SSH into the target system
ssh user@target-host

# Navigate to tool directory
cd /path/to/toolkit

# Run the tool
python main.py
```

✅ **Everything works** - Rich TUI, interactive menus, all features

### Why Python/Rich Works Over SSH

1. **Rich TUI is Terminal-Based**
   - Designed specifically for terminal environments
   - Works perfectly over SSH connections
   - Automatically detects terminal capabilities
   - Gracefully degrades if advanced features unavailable

2. **No GUI Dependencies**
   - Pure terminal interface
   - No X11 forwarding needed
   - Works with any SSH client (PuTTY, OpenSSH, etc.)

3. **Standard Terminal Features**
   - Uses ANSI color codes (supported by all modern terminals)
   - Text-based menus and prompts
   - Works with basic terminals

## Terminal Requirements

### Minimum Requirements
- **Any SSH client** (OpenSSH, PuTTY, Windows Terminal, etc.)
- **Terminal with color support** (most modern terminals)
- **UTF-8 encoding** (standard on modern systems)

### Recommended
- **256-color terminal** (for best visual experience)
- **Modern SSH client** (OpenSSH 7.0+)
- **Terminal width**: 80+ columns

## Usage Examples

### Example 1: Basic SSH Access

```bash
# From your local machine
ssh admin@192.168.1.100

# On remote system
cd /opt/lateral-movement-toolkit
python main.py

# Tool displays Rich TUI over SSH
# All menus, prompts, and visualizations work
```

### Example 2: SSH with Port Forwarding

```bash
# SSH with port forwarding for other services
ssh -L 8888:localhost:8888 admin@target-host

# Run tool
python main.py

# Tool works normally, can access forwarded ports
```

### Example 3: SSH Through Jump Host

```bash
# SSH through jump host
ssh -J jump-host admin@target-host

# Run tool
python main.py

# All features work normally
```

## Rich TUI Over SSH

### What Works
✅ **All menus and navigation**
✅ **Color output and formatting**
✅ **Tables and panels**
✅ **Progress bars**
✅ **Interactive prompts**
✅ **Tree views**
✅ **Layouts and columns**

### Automatic Detection
Rich automatically detects:
- Terminal capabilities
- Color support
- Terminal size
- SSH environment

### Fallback Behavior
If advanced features unavailable:
- Falls back to basic text
- Still fully functional
- All features work (just less visual)

## Command Execution

### Local Execution (Default)
When you SSH into a system and run the tool:
- Commands execute **on that remote system**
- `execute_cmd("whoami")` runs on the SSH'd-into host
- All modules work normally

### Remote Execution (Optional)
If you want to execute commands on OTHER systems:
- Use SSH Session Management (option 15)
- Create SSH session to target
- Commands execute on that target

## Environment Variables

The tool detects SSH environment:

```bash
# Automatically detected
SSH_CONNECTION
SSH_CLIENT
SSH_TTY

# Tool adapts behavior automatically
```

## Troubleshooting

### Issue: Colors Not Displaying

**Solution:**
```bash
# Set terminal type
export TERM=xterm-256color

# Or for basic terminals
export TERM=xterm
```

### Issue: Menu Not Displaying Correctly

**Solution:**
```bash
# Ensure terminal width is adequate
stty cols 120

# Check terminal size
echo $COLUMNS x $LINES
```

### Issue: Special Characters Not Showing

**Solution:**
```bash
# Set UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```

### Issue: Tool Runs Slowly Over SSH

**Solution:**
- This is normal - network latency affects display updates
- Tool is still fully functional
- Consider using `tmux` or `screen` for persistent sessions

## Best Practices

1. **Use tmux/screen** for persistent sessions
   ```bash
   tmux new -s lateral
   python main.py
   # Detach: Ctrl+B, D
   # Reattach: tmux attach -t lateral
   ```

2. **Set proper terminal** before running
   ```bash
   export TERM=xterm-256color
   ```

3. **Ensure adequate terminal size**
   ```bash
   # Minimum: 80 columns
   # Recommended: 120+ columns
   ```

4. **Use modern SSH client**
   - OpenSSH 7.0+ recommended
   - Windows: Use Windows Terminal or PuTTY with UTF-8

## Technical Details

### Rich TUI SSH Compatibility

Rich library:
- Detects terminal via `TERM` environment variable
- Checks for color support automatically
- Adapts output based on capabilities
- Works with any terminal that supports ANSI codes

### Python Over SSH

Python execution:
- Runs normally over SSH
- No special configuration needed
- Standard input/output work perfectly
- Subprocess execution works normally

### Command Execution Flow

```
SSH Connection
    ↓
Python Process Started
    ↓
Rich TUI Initialized
    ↓
Detects Terminal Capabilities
    ↓
Renders Interface
    ↓
User Interacts
    ↓
Commands Execute (on remote system)
    ↓
Results Displayed
```

## Verification

Test SSH compatibility:

```bash
# SSH into system
ssh user@host

# Check terminal
echo $TERM
echo $SSH_CONNECTION

# Run tool
python main.py

# Should see Rich TUI with colors and formatting
```

## Conclusion

**This tool is fully compatible with SSH control.** All features work when accessing over SSH. Rich TUI is specifically designed for terminal environments and works perfectly in SSH sessions.
