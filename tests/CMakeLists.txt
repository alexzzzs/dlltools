# dlltools Unit Tests
cmake_minimum_required(VERSION 3.25)

# Try to find Catch2, download if not found
find_package(Catch2 3 QUIET)

if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found, fetching from GitHub...")
    include(FetchContent)
    
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.6.0
    )
    
    FetchContent_MakeAvailable(Catch2)
    
    # Include Catch2 CMake scripts for test discovery
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
endif()

# =============================================================================
# Test Executable
# =============================================================================
add_executable(dlltools_tests
    test_pe_parser.cpp
    test_section.cpp
    test_import.cpp
    test_export.cpp
    test_entropy.cpp
    test_rva.cpp
    test_file_mapping.cpp
    test_resource.cpp
    test_integration.cpp
    test_rich.cpp
)

target_link_libraries(dlltools_tests
    PRIVATE
        dlltools_core
        Catch2::Catch2WithMain
)

# Set C++23 for tests
target_compile_features(dlltools_tests PRIVATE cxx_std_23)

# =============================================================================
# Test Data
# =============================================================================
# Create test_data directory if it doesn't exist
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_data)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test_data)
endif()

# Copy test data to build directory (if it exists and has content)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_data)
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_data
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

# =============================================================================
# Test Discovery
# =============================================================================
include(Catch)

# Discover tests from the executable
catch_discover_tests(dlltools_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    PROPERTIES
        LABELS "unit"
)

# =============================================================================
# Custom Test Targets
# =============================================================================
add_custom_target(run_tests
    COMMAND dlltools_tests --reporter console
    DEPENDS dlltools_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running dlltools unit tests..."
)

# Verbose test output
add_custom_target(run_tests_verbose
    COMMAND dlltools_tests --reporter console --verbosity high
    DEPENDS dlltools_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running dlltools unit tests (verbose)..."
)
