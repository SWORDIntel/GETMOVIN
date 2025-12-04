# Project Structure

Complete overview of the Windows Lateral Movement Simulation TUI project structure.

## Root Directory

```
.
├── main.py                 # Main entry point - launches the TUI
├── run.bat                 # Windows launcher script (double-click to run)
├── run.sh                  # Linux/Mac launcher script
├── requirements.txt        # Python dependencies (only rich library)
├── setup.py               # Python package setup script
├── VERSION                 # Version file
├── LICENSE                 # MIT License (for authorized use only)
├── .gitignore             # Git ignore rules
│
├── README.md              # Main documentation
├── INSTALL.md             # Installation guide
├── QUICKSTART.md          # Quick start guide
├── CHANGELOG.md           # Version history
├── PROJECT_STRUCTURE.md   # This file
│
└── modules/               # Core modules directory
    ├── __init__.py
    ├── utils.py           # Utility functions (command execution, IP validation)
    ├── foothold.py        # Module 1: Foothold & Starting Point
    ├── orientation.py      # Module 2: Local Orientation
    ├── identity.py         # Module 3: Identity Acquisition
    ├── lateral.py          # Module 4: Lateral Movement Channels
    ├── consolidation.py    # Module 5: Consolidation & Dominance
    ├── opsec.py            # Module 6: OPSEC Considerations
    ├── llm_agent.py        # Module 7: LLM Remote Agent
    ├── madcert_integration.py  # Module 8: MADCert Integration
    ├── lolbins_reference.py    # Module 9: LOLBins Reference
    ├── auto_enumerate.py      # Module 10: Auto-Enumeration
    ├── loghunter_integration.py # Module 11: LogHunter & Moonwalk
    ├── memshadow_protocol.py   # MEMSHADOW MRAC Protocol
    └── memshadow_client.py     # MEMSHADOW Client Library
│
├── docs/                  # Documentation directory
    ├── Auto_Enumeration.md
    ├── LOLBins_Reference.md
    └── MADCert_Integration.md
│
└── docs/
    └── examples/          # Example scripts
        └── llm_agent_example.py
```

## Key Files

### Entry Points

- **`main.py`**: Main application entry point
  - Initializes TUI
  - Loads all modules
  - Handles configuration flags
  - Manages main menu loop

- **`run.bat`**: Windows launcher
  - Checks Python installation
  - Creates virtual environment
  - Installs dependencies
  - Launches tool

- **`run.sh`**: Linux/Mac launcher
  - Same functionality as run.bat
  - Unix-compatible

### Configuration

- **`requirements.txt`**: Python dependencies
  - Only one dependency: `rich>=13.0.0`
  - Can be installed offline

- **`main.py`**: Configuration flags
  - `LAB_USE`: Lab mode flag
  - `AUTO_ENUMERATE`: Auto-enumeration flag
  - `AUTO_ENUMERATE_DEPTH`: Lateral movement depth

### Modules

Each module is self-contained and follows a consistent structure:

```python
class ModuleName:
    def __init__(self):
        # Initialize module-specific components
        pass
    
    def run(self, console: Console, session_data: dict):
        # Main module loop
        # Display menu
        # Handle user choices
        # Execute functions
        pass
    
    def _function_name(self, console: Console, session_data: dict):
        # Module-specific functions
        pass
```

### Utilities

- **`modules/utils.py`**: Shared utility functions
  - `execute_cmd()`: Execute Windows commands
  - `execute_powershell()`: Execute PowerShell commands
  - `is_local_ip()`: IP address validation
  - `validate_target()`: Target validation

## Module Dependencies

```
main.py
├── All modules (1-11)
│
modules/utils.py (used by all modules)
│
modules/auto_enumerate.py
├── Uses: foothold, orientation, identity, lateral, consolidation
├── Uses: loghunter_integration (LogHunter, Moonwalk)
│
modules/loghunter_integration.py
├── WindowsMoonwalk (used by all modules)
└── LogHunter (standalone)
│
modules/llm_agent.py
├── memshadow_protocol.py
└── memshadow_client.py
│
modules/lolbins_reference.py
└── Can integrate with madcert_integration.py
```

## Data Flow

1. **User launches tool** → `run.bat`/`run.sh`
2. **Script sets up environment** → Virtual env, dependencies
3. **Launches main.py** → Initializes TUI
4. **User selects module** → Module's `run()` method called
5. **Module executes functions** → Uses `utils.py` for execution
6. **Results displayed** → Rich console output
7. **Moonwalk cleanup** → Optional trace clearing

## File Sizes

- **Main code**: ~15,000 lines total
- **Dependencies**: Single library (rich)
- **Total size**: ~500 KB (without venv)

## Self-Contained Design

- ✅ No online dependencies
- ✅ All code included
- ✅ Single dependency (rich)
- ✅ Can run completely offline
- ✅ Simple run scripts
- ✅ Virtual environment isolation

## Extension Points

To add new modules:

1. Create `modules/new_module.py`
2. Follow module structure pattern
3. Import in `main.py`
4. Add to modules dictionary
5. Update menu choices

## Build Artifacts

Generated files (in .gitignore):
- `__pycache__/`: Python bytecode
- `venv/`: Virtual environment
- `*.pyc`: Compiled Python files
- `enumeration_report_*`: Generated reports
- `*.log`: Log files

## Distribution

To distribute the tool:

1. Include all files except `venv/` and `__pycache__/`
2. Include `requirements.txt`
3. Include `run.bat` and `run.sh`
4. User runs `run.bat`/`run.sh` to set up

---

**This tool is completely self-contained and requires no online access.**
