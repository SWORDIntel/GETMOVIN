@echo off
REM Windows Lateral Movement Simulation TUI - Launcher Script
REM Red Team / Threat Modeling Tool

echo.
echo ========================================
echo Windows Lateral Movement Simulation TUI
echo Red Team / Threat Modeling Tool
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Python version: %PYTHON_VERSION%

REM Check if virtual environment exists
if not exist "venv\" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if dependencies are installed
python -c "import rich" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    pip install --upgrade pip --quiet
    pip install -r requirements.txt --quiet
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    echo [INFO] Dependencies installed successfully
)

REM Run the tool
echo.
echo [INFO] Starting Windows Lateral Movement Simulation TUI...
echo.
python main.py

REM Keep window open on error
if errorlevel 1 (
    echo.
    echo [ERROR] Tool exited with error code: %errorlevel%
    pause
)
