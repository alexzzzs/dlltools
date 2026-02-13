/**
 * @file test_resource.cpp
 * @brief Unit tests for resource directory parsing.
 */

#include <catch2/catch_test_macros.hpp>
#include "core/pe_parser.hpp"
#include "core/resource.hpp"
#include <filesystem>

using namespace dlltools;

TEST_CASE("ResourceTable parsing", "[resource]") {
    // Use a system DLL that should have resources
    std::filesystem::path kernel32 = "C:\\Windows\\System32\\kernel32.dll";
    
    if (!std::filesystem::exists(kernel32)) {
        SKIP("kernel32.dll not found for testing");
    }
    
    auto pe_result = PEParser::parse(kernel32);
    REQUIRE(pe_result);
    
    const auto& pe = *pe_result;
    
    SECTION("Parse resources") {
        auto resources_result = pe.resources();
        REQUIRE(resources_result);
        
        const auto& resources = resources_result->get();
        
        // kernel32.dll should have resources
        CHECK(resources.has_resources());
        CHECK(resources.type_count() > 0);
    }
    
    SECTION("Resource types") {
        auto resources_result = pe.resources();
        REQUIRE(resources_result);
        
        const auto& resources = resources_result->get();
        
        // Check that we can iterate over types
        for (const auto& type : resources) {
            // Each type should have a valid ID or name
            if (!type.is_named) {
                CHECK(type.type_id > 0);
            } else {
                CHECK(!type.type_name.empty());
            }
        }
    }
    
    SECTION("Type ID to string conversion") {
        CHECK(ResourceTable::type_id_to_string(1) == "CURSOR");
        CHECK(ResourceTable::type_id_to_string(2) == "BITMAP");
        CHECK(ResourceTable::type_id_to_string(3) == "ICON");
        CHECK(ResourceTable::type_id_to_string(16) == "VERSION");
        CHECK(ResourceTable::type_id_to_string(24) == "MANIFEST");
        CHECK(ResourceTable::type_id_to_string(9999) == "Unknown");
    }
}

TEST_CASE("ResourceTable with no resources", "[resource]") {
    // Test default-constructed ResourceTable behavior
    ResourceTable resources;
    
    SECTION("Default state") {
        CHECK(resources.type_count() == 0);
        CHECK(resources.entry_count() == 0);
        CHECK(resources.empty());
        CHECK(!resources.has_resources());
        CHECK(resources.directory_rva() == 0);
        CHECK(resources.directory_size() == 0);
    }
    
    SECTION("Iterator on empty table") {
        CHECK(resources.begin() == resources.end());
        CHECK(resources.cbegin() == resources.cend());
    }
    
    SECTION("At on empty table") {
        CHECK(resources.at(0) == nullptr);
        CHECK(resources.at(1) == nullptr);
    }
    
    SECTION("Find on empty table") {
        CHECK(resources.find_by_type(1) == nullptr);
        CHECK(resources.find_by_type_name("CURSOR") == nullptr);
    }
    
    SECTION("Get entries on empty table") {
        auto entries = resources.get_entries_by_type(1);
        CHECK(entries.empty());
    }
}

TEST_CASE("ResourceEntry validation", "[resource]") {
    ResourceEntry entry;
    
    SECTION("Default values") {
        CHECK(entry.name.empty());
        CHECK(entry.id == 0);
        CHECK(entry.is_named == false);
        CHECK(entry.offset == 0);
        CHECK(entry.rva == 0);
        CHECK(entry.size == 0);
        CHECK(entry.code_page == 0);
        CHECK(entry.language_id == 0);
        CHECK(entry.sublanguage_id == 0);
    }
}

TEST_CASE("ResourceType validation", "[resource]") {
    ResourceType type;
    
    SECTION("Default values") {
        CHECK(type.type_id == 0);
        CHECK(type.type_name.empty());
        CHECK(type.is_named == false);
        CHECK(type.entries.empty());
    }
}
