#include <catch2/catch_test_macros.hpp>
#include "core/pe_parser.hpp"
#include "core/section.hpp"
#include "core/import.hpp"
#include "core/export.hpp"
#include "core/security.hpp"
#include "core/entropy.hpp"
#include <filesystem>
#include <windows.h>

using namespace dlltools;

namespace {

// Get path to a system DLL for testing
std::filesystem::path get_system_dll_path() {
    char system_dir[MAX_PATH];
    GetSystemDirectoryA(system_dir, MAX_PATH);
    return std::filesystem::path(system_dir) / "kernel32.dll";
}

std::filesystem::path get_ntdll_path() {
    char system_dir[MAX_PATH];
    GetSystemDirectoryA(system_dir, MAX_PATH);
    return std::filesystem::path(system_dir) / "ntdll.dll";
}

} // anonymous namespace

// =============================================================================
// Integration Tests with Real PE Files
// =============================================================================

TEST_CASE("Integration: Parse kernel32.dll", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    // Skip if file doesn't exist (shouldn't happen on Windows)
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    
    // Basic validation
    REQUIRE(pe.is_valid());
    REQUIRE(pe.is_pe32_plus());  // kernel32.dll is 64-bit on 64-bit Windows
    
    // Check headers
    REQUIRE(pe.machine_type() == IMAGE_FILE_MACHINE_AMD64);
    REQUIRE(pe.section_count() > 0);
    REQUIRE(pe.size_of_image() > 0);
}

TEST_CASE("Integration: Parse kernel32.dll sections", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    const auto& sections = pe.sections();
    
    REQUIRE(sections.count() > 0);
    
    // Should have .text section
    bool has_text = false;
    for (const auto& section : sections) {
        if (section.name == ".text") {
            has_text = true;
            REQUIRE(section.is_executable());
            REQUIRE(section.is_readable());
            REQUIRE(section.is_code());
        }
    }
    REQUIRE(has_text);
}

TEST_CASE("Integration: Parse kernel32.dll imports", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    auto imports_result = pe.imports();
    REQUIRE(imports_result);
    
    const auto& imports = imports_result->get();
    REQUIRE(imports.dll_count() > 0);
    
    // kernel32.dll should import from ntdll.dll
    const auto* ntdll = imports.find_dll("ntdll.dll");
    REQUIRE(ntdll != nullptr);
    REQUIRE(ntdll->functions.size() > 0);
}

TEST_CASE("Integration: Parse kernel32.dll exports", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    auto exports_result = pe.exports();
    REQUIRE(exports_result);
    
    const auto& exports = exports_result->get();
    REQUIRE(exports.count() > 0);
    
    // kernel32.dll should export CreateFile
    auto idx = exports.find_index_by_name("CreateFileW");
    REQUIRE(idx.has_value());
    
    const auto& func = exports[*idx];
    REQUIRE(func.name == "CreateFileW");
    REQUIRE(func.rva > 0);
}

TEST_CASE("Integration: Parse ntdll.dll", "[integration]") {
    auto dll_path = get_ntdll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("ntdll.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    REQUIRE(pe.is_valid());
    
    // ntdll.dll should have exports
    auto exports_result = pe.exports();
    REQUIRE(exports_result);
    REQUIRE(exports_result->get().count() > 0);
}

TEST_CASE("Integration: Security features analysis", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    auto features = pe.security_features();
    
    // Modern system DLLs should have ASLR and DEP
    REQUIRE(features.aslr_compatible);
    REQUIRE(features.dep_compatible);
}

TEST_CASE("Integration: Entropy calculation", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    const auto& sections = pe.sections();
    
    for (const auto& section : sections) {
        double entropy = section.calculate_entropy(pe);
        
        // Entropy should be between 0 and 8
        REQUIRE(entropy >= 0.0);
        REQUIRE(entropy <= 8.0);
    }
}

TEST_CASE("Integration: RVA conversion", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    const auto& sections = pe.sections();
    
    // Test RVA conversion for each section
    for (const auto& section : sections) {
        uint32_t rva = section.virtual_address;
        auto offset = pe.rva_to_offset(rva);
        REQUIRE(offset.has_value());
        REQUIRE(*offset == section.raw_offset);
    }
}

TEST_CASE("Integration: Data directory access", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    
    // Should have import directory
    REQUIRE(pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT));
    
    // Should have export directory
    REQUIRE(pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT));
}

TEST_CASE("Integration: Image base and entry point", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    
    // Image base should be non-zero
    REQUIRE(pe.image_base() != 0);
    
    // DLL should have an entry point
    REQUIRE(pe.entry_point_rva() != 0);
}

TEST_CASE("Integration: File alignment", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    
    // File alignment should be a power of 2
    uint32_t file_align = pe.file_alignment();
    REQUIRE(file_align > 0);
    REQUIRE((file_align & (file_align - 1)) == 0);  // Power of 2 check
    
    // Section alignment should be a power of 2
    uint32_t section_align = pe.section_alignment();
    REQUIRE(section_align > 0);
    REQUIRE((section_align & (section_align - 1)) == 0);  // Power of 2 check
}

TEST_CASE("Integration: Section characteristics", "[integration]") {
    auto dll_path = get_system_dll_path();
    
    if (!std::filesystem::exists(dll_path)) {
        SKIP("kernel32.dll not found");
    }
    
    auto result = PEParser::parse(dll_path);
    REQUIRE(result);
    
    const auto& pe = *result;
    const auto& sections = pe.sections();
    
    // Find .text section and verify it's executable code
    bool found_text = false;
    for (const auto& section : sections) {
        if (section.name == ".text") {
            found_text = true;
            REQUIRE(section.is_executable());
            REQUIRE(section.is_readable());
            REQUIRE(section.is_code());
            REQUIRE_FALSE(section.is_writable());
        }
        else if (section.name == ".data") {
            // Data section should be readable and writable
            REQUIRE(section.is_readable());
            REQUIRE(section.is_writable());
        }
    }
    REQUIRE(found_text);
}
