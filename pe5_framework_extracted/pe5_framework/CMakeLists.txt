# PE5 Exploit Framework - CMake Build System
#
# RECONSTRUCTED FROM SECURITY ANALYSIS
# Classification: TLP:RED - Security Research Only
#
# Usage:
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64
#   cmake --build . --config Release
#
# Or with MinGW:
#   cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
#   cmake --build .

cmake_minimum_required(VERSION 3.16)
project(PE5_Framework VERSION 1.0.0 LANGUAGES C ASM_MASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Common include directory
include_directories(${CMAKE_SOURCE_DIR}/common)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX /GS- /O2)
    add_compile_definitions(WIN32 NDEBUG _WINDOWS)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

#=============================================================================
# PE #5 - KERNEL EXPLOIT
#=============================================================================

set(PE5_SOURCES
    pe5_exploit/exploit.c
    pe5_exploit/token_manipulation.c
    pe5_exploit/decryption.c
)

if(MSVC)
    set(PE5_ASM pe5_exploit/exploit_asm.asm)
    set_source_files_properties(${PE5_ASM} PROPERTIES LANGUAGE ASM_MASM)
    list(APPEND PE5_SOURCES ${PE5_ASM})
endif()

# PE #5 DLL
add_library(pe5_exploit SHARED ${PE5_SOURCES})
target_link_libraries(pe5_exploit kernel32 ntdll)
set_target_properties(pe5_exploit PROPERTIES
    OUTPUT_NAME "pe5_exploit"
    SUFFIX ".dll"
)

# PE #5 EXE
add_executable(pe5_exploit_exe ${PE5_SOURCES})
target_link_libraries(pe5_exploit_exe kernel32 ntdll)
set_target_properties(pe5_exploit_exe PROPERTIES
    OUTPUT_NAME "pe5_exploit"
)

#=============================================================================
# PE #4 - STUB LAUNCHER
#=============================================================================

set(PE4_SOURCES
    pe4_stub/stub.c
    pe4_stub/injector.c
)

# PE #4 DLL
add_library(pe4_stub SHARED ${PE4_SOURCES})
target_link_libraries(pe4_stub kernel32 ntdll)
set_target_properties(pe4_stub PROPERTIES
    OUTPUT_NAME "pe4_stub"
    SUFFIX ".dll"
)

# PE #4 EXE
add_executable(pe4_stub_exe ${PE4_SOURCES})
target_link_libraries(pe4_stub_exe kernel32 ntdll)
set_target_properties(pe4_stub_exe PROPERTIES
    OUTPUT_NAME "pe4_stub"
)

#=============================================================================
# PE #1 - MAIN LOADER
#=============================================================================

set(PE1_SOURCES
    pe1_loader/loader.c
    pe1_loader/persistence.c
    pe1_loader/c2_client.c
)

# PE #1 DLL
add_library(pe1_loader SHARED ${PE1_SOURCES})
target_link_libraries(pe1_loader kernel32 ntdll advapi32 winhttp)
set_target_properties(pe1_loader PROPERTIES
    OUTPUT_NAME "pe1_loader"
    SUFFIX ".dll"
)

#=============================================================================
# PE #2 - DNS TUNNEL
#=============================================================================

set(PE2_SOURCES
    pe2_dns_tunnel/dns_tunnel.c
)

add_library(pe2_dns SHARED ${PE2_SOURCES})
target_link_libraries(pe2_dns kernel32 dnsapi crypt32)
set_target_properties(pe2_dns PROPERTIES
    OUTPUT_NAME "pe2_dns"
    SUFFIX ".dll"
)

#=============================================================================
# PE #3 - CONTAINER
#=============================================================================

set(PE3_SOURCES
    pe3_container/container.c
)

add_library(pe3_container SHARED ${PE3_SOURCES})
target_link_libraries(pe3_container kernel32)
set_target_properties(pe3_container PROPERTIES
    OUTPUT_NAME "pe3_container"
    SUFFIX ".dll"
)

#=============================================================================
# COMMON UTILITIES (Static Library)
#=============================================================================

set(COMMON_SOURCES
    common/xor_crypto.c
)

add_library(common_utils STATIC ${COMMON_SOURCES})

#=============================================================================
# INSTALL TARGETS
#=============================================================================

install(TARGETS 
    pe5_exploit pe5_exploit_exe 
    pe4_stub pe4_stub_exe 
    pe1_loader 
    pe2_dns 
    pe3_container
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

install(FILES
    common/ntdefs.h
    DESTINATION include
)

#=============================================================================
# SUMMARY
#=============================================================================

message(STATUS "")
message(STATUS "PE5 Exploit Framework Configuration:")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Output Dir: ${CMAKE_BINARY_DIR}/bin")
message(STATUS "")
