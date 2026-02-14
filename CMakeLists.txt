# dlltools - Windows DLL Inspection & Analysis Toolkit
cmake_minimum_required(VERSION 3.25)

project(dlltools
    VERSION 0.1.0
    LANGUAGES CXX
    DESCRIPTION "Windows DLL Inspection & Analysis Toolkit"
)

# C++23 required for std::expected
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# MSVC-specific settings
if(MSVC)
    # High warning level with strict conformance
    add_compile_options(
        /W4           # Warning level 4
        /WX           # Treat warnings as errors
        /permissive-  # Strict conformance mode
        /Zc:__cplusplus  # Correct __cplusplus value
        /Zc:preprocessor  # Conforming preprocessor
        /EHsc         # Exception handling
    )
    
    # Debug configuration
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi /RTC1")
    
    # Release configuration with optimizations
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
endif()

# Define output directories - use platform-specific configuration folders
if(MSVC)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_BINARY_DIR}/bin/RelWithDebInfo)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_BINARY_DIR}/bin/MinSizeRel)
    
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib/Debug)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib/Release)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_BINARY_DIR}/lib/RelWithDebInfo)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_BINARY_DIR}/lib/MinSizeRel)
    
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib/Debug)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib/Release)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_BINARY_DIR}/lib/RelWithDebInfo)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_BINARY_DIR}/lib/MinSizeRel)
else()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# =============================================================================
# Core Library - PE parsing and analysis
# =============================================================================
add_library(dlltools_core STATIC
    src/core/pe_parser.cpp
    src/core/section.cpp
    src/core/import.cpp
    src/core/export.cpp
    src/core/rva.cpp
    src/core/entropy.cpp
    src/core/security.cpp
    src/core/resource.cpp
    src/core/rich.cpp
    src/utils/file_mapping.cpp
    src/utils/string_utils.cpp
)

target_include_directories(dlltools_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

# Link Windows libraries for PE parsing
target_link_libraries(dlltools_core
    PRIVATE
        kernel32
        imagehlp  # For checksum calculation and other PE helpers
)

# =============================================================================
# CLI Executable
# =============================================================================
add_executable(dlltools
    src/cli/main.cpp
    src/cli/cli_parser.cpp
    src/cli/commands.cpp
    src/cli/output.cpp
)

target_link_libraries(dlltools
    PRIVATE
        dlltools_core
)

# Set the output name to be just 'dlltools' without 'd' suffix in debug
set_target_properties(dlltools PROPERTIES
    DEBUG_POSTFIX ""
)

# =============================================================================
# Testing
# =============================================================================
option(DLLTOOLS_BUILD_TESTS "Build unit tests" ON)

if(DLLTOOLS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# =============================================================================
# Installation
# =============================================================================
include(GNUInstallDirs)

install(TARGETS dlltools
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(TARGETS dlltools_core
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install headers
install(DIRECTORY src/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dlltools
    FILES_MATCHING PATTERN "*.hpp"
)

# =============================================================================
# Package configuration
# =============================================================================
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/dlltoolsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# =============================================================================
# Summary
# =============================================================================
message(STATUS "")
message(STATUS "dlltools v${PROJECT_VERSION}")
message(STATUS "========================")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Build Tests: ${DLLTOOLS_BUILD_TESTS}")
message(STATUS "")
