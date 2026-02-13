#include <catch2/catch_test_macros.hpp>
#include "core/import.hpp"

using namespace dlltools;

TEST_CASE("ImportedFunction - default construction", "[import]") {
    ImportedFunction func;
    
    REQUIRE(func.name.empty());
    REQUIRE(func.ordinal == 0);
    REQUIRE_FALSE(func.is_by_ordinal);
    REQUIRE(func.thunk_rva == 0);
    REQUIRE(func.hint == 0);
}

TEST_CASE("ImportedDll - default construction", "[import]") {
    ImportedDll dll;
    
    REQUIRE(dll.name.empty());
    REQUIRE(dll.functions.empty());
    REQUIRE(dll.first_thunk_rva == 0);
    REQUIRE(dll.original_first_thunk_rva == 0);
    REQUIRE_FALSE(dll.is_delay_load);
}

TEST_CASE("ImportTable - empty", "[import]") {
    ImportTable table;
    
    REQUIRE(table.empty());
    REQUIRE(table.dll_count() == 0);
    REQUIRE(table.function_count() == 0);
}
