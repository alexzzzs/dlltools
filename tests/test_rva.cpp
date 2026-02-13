#include <catch2/catch_test_macros.hpp>
#include "core/rva.hpp"
#include "core/pe_parser.hpp"

using namespace dlltools;

// Note: These tests require a valid PE file to test properly
// For now, we test the standalone functions

TEST_CASE("rva_to_file_offset - null check", "[rva]") {
    // This would require a PE file to test properly
    // Placeholder for future tests
}
