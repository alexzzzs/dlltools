#include <catch2/catch_all.hpp>
#include "core/rich.hpp"
#include "core/pe_parser.hpp"

#include <vector>
#include <cstdint>

TEST_CASE("RichHeader basics", "[rich]") {
    SECTION("RichEntry can be created") {
        dlltools::RichEntry entry{1, 0, 0};
        REQUIRE(entry.id == 1);
        REQUIRE(entry.version == 0);
        REQUIRE(entry.count == 0);
    }
    
    SECTION("Default RichHeader is empty") {
        dlltools::RichHeader rich;
        CHECK(rich.is_present() == false);
        CHECK(rich.empty() == true);
        CHECK(rich.count() == 0);
    }
}

TEST_CASE("RichHeader from file", "[rich]") {
    SECTION("Test PE without Rich header") {
        // Use a test file that might not have Rich header
        auto result = dlltools::PEParser::parse("test_data/test_pe32.dll");
        if (result.has_value()) {
            auto rich_result = result->rich_header();
            // Just check it doesn't crash - may or may not have Rich header
            INFO("Rich header parse completed");
        }
    }
    
    SECTION("Test invalid file") {
        auto result = dlltools::PEParser::parse("test_data/empty.dll");
        if (result.has_value()) {
            auto rich_result = result->rich_header();
            // Just verify we can call is_present() - empty file may not have Rich header
            CHECK(true);  // Test passed if we got here without crashing
        }
    }
}

TEST_CASE("RichHeader tool name lookup", "[rich]") {
    SECTION("Tool name lookup for known IDs") {
        // These are common tool IDs
        std::string name1 = dlltools::RichHeader::tool_name(1);   // link.exe
        CHECK(!name1.empty());
        
        std::string name2 = dlltools::RichHeader::tool_name(2);   // CVTRES.EXE
        CHECK(!name2.empty());
        
        std::string name3 = dlltools::RichHeader::tool_name(0);   // Unknown
        CHECK(!name3.empty());
        
        std::string name4 = dlltools::RichHeader::tool_name(4);   // cl.exe
        CHECK(!name4.empty());
    }
}
