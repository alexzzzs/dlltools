#include <catch2/catch_test_macros.hpp>
#include "core/export.hpp"

using namespace dlltools;

TEST_CASE("ExportedFunction - default construction", "[export]") {
    ExportedFunction func;
    
    REQUIRE(func.name.empty());
    REQUIRE(func.ordinal == 0);
    REQUIRE(func.rva == 0);
    REQUIRE_FALSE(func.is_forwarded);
    REQUIRE(func.forward_target.empty());
}

TEST_CASE("ExportTable - empty", "[export]") {
    ExportTable table;
    
    REQUIRE(table.empty());
    REQUIRE(table.count() == 0);
    REQUIRE(table.dll_name().empty());
    REQUIRE(table.ordinal_base() == 0);
}
