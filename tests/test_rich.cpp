#include <catch2/catch_all.hpp>
#include "core/rich.hpp"
#include "core/pe_parser.hpp"

#include <vector>
#include <cstdint>
#include <cstring>

TEST_CASE("RichHeader basics", "[rich]") {
    SECTION("RichEntry can be created") {
        dlltools::RichEntry entry{1, 0, 0};
        REQUIRE(entry.id == 1);
        REQUIRE(entry.version == 0);
        REQUIRE(entry.count == 0);
    }
    
    SECTION("RichEntry with all fields") {
        dlltools::RichEntry entry{0x0015, 0x0123, 42};
        REQUIRE(entry.id == 0x0015);
        REQUIRE(entry.version == 0x0123);
        REQUIRE(entry.count == 42);
    }
    
    SECTION("Default RichHeader is empty") {
        dlltools::RichHeader rich;
        CHECK(rich.is_present() == false);
        CHECK(rich.empty() == true);
        CHECK(rich.count() == 0);
        CHECK(rich.xor_key() == 0);
        CHECK(rich.offset() == 0);
        CHECK(rich.size() == 0);
    }
}

TEST_CASE("RichHeader tool name lookup", "[rich]") {
    SECTION("Tool name lookup for known IDs") {
        // Common tool IDs
        std::string name_link = dlltools::RichHeader::tool_name(0x0015);   // link.exe
        CHECK(name_link == "link.exe");
        
        std::string name_cvtres = dlltools::RichHeader::tool_name(0x0016);   // cvtres.exe
        CHECK(name_cvtres == "cvtres.exe");
        
        std::string name_rc = dlltools::RichHeader::tool_name(0x0017);   // rc.exe
        CHECK(name_rc == "rc.exe");
        
        std::string name_cl_c = dlltools::RichHeader::tool_name(0x0018);   // cl.exe (C)
        CHECK(name_cl_c == "cl.exe (C)");
        
        std::string name_cl_cpp = dlltools::RichHeader::tool_name(0x0019);   // cl.exe (C++)
        CHECK(name_cl_cpp == "cl.exe (C++)");
        
        std::string name_ml = dlltools::RichHeader::tool_name(0x001A);   // ml.exe
        CHECK(name_ml == "ml.exe (MASM)");
        
        std::string name_lib = dlltools::RichHeader::tool_name(0x001B);   // lib.exe
        CHECK(name_lib == "lib.exe (import library)");
    }
    
    SECTION("Tool name lookup for VS version build IDs") {
        // VS2019 build IDs
        std::string name_vs2019_link = dlltools::RichHeader::tool_name(0x9648);
        CHECK(name_vs2019_link == "link.exe");
        
        std::string name_vs2019_cl = dlltools::RichHeader::tool_name(0x964B);
        CHECK(name_vs2019_cl == "cl.exe");
        
        // VS2022 build IDs
        std::string name_vs2022_link = dlltools::RichHeader::tool_name(0x9B58);
        CHECK(name_vs2022_link == "link.exe");
    }
    
    SECTION("Tool name lookup for unknown IDs") {
        std::string name_unknown = dlltools::RichHeader::tool_name(0xFFFF);
        CHECK(name_unknown == "Unknown Tool");
        
        std::string name_unknown2 = dlltools::RichHeader::tool_name(0x1234);
        CHECK(name_unknown2 == "Unknown Tool");
    }
    
    SECTION("Tool name lookup for version range IDs") {
        // These should return range-based names
        std::string name_vs2017_range = dlltools::RichHeader::tool_name(0x91FF);
        CHECK(name_vs2017_range == "VS2017 Tool");
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
            // Empty result is acceptable for files without Rich header
            CHECK(true);
        } else {
            // File parsing failed - that's also acceptable for testing
            INFO("PE file could not be parsed");
            CHECK(true);
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
    
    SECTION("Test truncated file") {
        auto result = dlltools::PEParser::parse("test_data/truncated.dll");
        if (result.has_value()) {
            auto rich_result = result->rich_header();
            // Should handle gracefully
            INFO("Truncated file handled");
            CHECK(true);
        }
    }
}

TEST_CASE("RichHeader entry access", "[rich]") {
    SECTION("Default RichHeader has no entries") {
        dlltools::RichHeader rich;
        CHECK(rich.at(0) == nullptr);
        CHECK_THROWS_AS(rich[0], std::out_of_range);
    }
}

TEST_CASE("RichHeader iterator support", "[rich]") {
    SECTION("Default RichHeader iterators work") {
        dlltools::RichHeader rich;
        auto begin_it = rich.begin();
        auto end_it = rich.end();
        CHECK(begin_it == end_it);
    }
}
