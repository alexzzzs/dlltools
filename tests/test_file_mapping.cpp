#include <catch2/catch_test_macros.hpp>
#include "utils/file_mapping.hpp"

using namespace dlltools::utils;

TEST_CASE("FileMapping - default construction", "[file_mapping]") {
    FileMapping mapping;
    
    REQUIRE_FALSE(mapping.is_valid());
    REQUIRE(mapping.data() == nullptr);
    REQUIRE(mapping.size() == 0);
}

TEST_CASE("FileMapping - map non-existent file", "[file_mapping]") {
    auto result = FileMapping::map("non_existent_file.dll");
    
    REQUIRE_FALSE(result);
}

TEST_CASE("FileMapping - in_bounds", "[file_mapping]") {
    FileMapping mapping;
    
    // Empty mapping should fail bounds check
    REQUIRE_FALSE(mapping.in_bounds(0, 1));
    REQUIRE_FALSE(mapping.in_bounds(0, 0));
}
