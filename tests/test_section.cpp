#include <catch2/catch_test_macros.hpp>
#include "core/section.hpp"
#include "core/pe_parser.hpp"

using namespace dlltools;

TEST_CASE("SectionHeader - default construction", "[section]") {
    SectionHeader header;
    
    REQUIRE(header.name.empty());
    REQUIRE(header.virtual_address == 0);
    REQUIRE(header.virtual_size == 0);
    REQUIRE(header.raw_size == 0);
    REQUIRE(header.raw_offset == 0);
    REQUIRE(header.characteristics == 0);
}

TEST_CASE("SectionHeader - flag checks", "[section]") {
    SectionHeader header;
    
    SECTION("executable flag") {
        header.characteristics = IMAGE_SCN_MEM_EXECUTE;
        REQUIRE(header.is_executable());
        REQUIRE_FALSE(header.is_readable());
        REQUIRE_FALSE(header.is_writable());
    }
    
    SECTION("readable flag") {
        header.characteristics = IMAGE_SCN_MEM_READ;
        REQUIRE(header.is_readable());
        REQUIRE_FALSE(header.is_executable());
    }
    
    SECTION("writable flag") {
        header.characteristics = IMAGE_SCN_MEM_WRITE;
        REQUIRE(header.is_writable());
        REQUIRE_FALSE(header.is_readable());
    }
    
    SECTION("code flag") {
        header.characteristics = IMAGE_SCN_CNT_CODE;
        REQUIRE(header.is_code());
    }
    
    SECTION("initialized data flag") {
        header.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA;
        REQUIRE(header.is_initialized_data());
    }
    
    SECTION("uninitialized data flag") {
        header.characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        REQUIRE(header.is_uninitialized_data());
    }
    
    SECTION("discardable flag") {
        header.characteristics = IMAGE_SCN_MEM_DISCARDABLE;
        REQUIRE(header.is_discardable());
    }
    
    SECTION("shared flag") {
        header.characteristics = IMAGE_SCN_MEM_SHARED;
        REQUIRE(header.is_shared());
    }
}

TEST_CASE("SectionHeader - contains_rva", "[section]") {
    SectionHeader header;
    header.virtual_address = 0x1000;
    header.virtual_size = 0x1000;
    
    REQUIRE(header.contains_rva(0x1000));
    REQUIRE(header.contains_rva(0x1500));
    REQUIRE(header.contains_rva(0x1FFF));
    REQUIRE_FALSE(header.contains_rva(0x0FFF));
    REQUIRE_FALSE(header.contains_rva(0x2000));
}

TEST_CASE("SectionHeader - rva_to_offset", "[section]") {
    SectionHeader header;
    header.virtual_address = 0x1000;
    header.virtual_size = 0x1000;
    header.raw_offset = 0x400;
    
    auto offset = header.rva_to_offset(0x1500);
    REQUIRE(offset.has_value());
    REQUIRE(*offset == 0x900);
    
    // RVA not in section
    auto invalid = header.rva_to_offset(0x2000);
    REQUIRE_FALSE(invalid.has_value());
}

TEST_CASE("SectionTable - empty", "[section]") {
    SectionTable table;
    
    REQUIRE(table.empty());
    REQUIRE(table.count() == 0);
}
