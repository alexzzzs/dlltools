#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include "core/entropy.hpp"
#include <vector>

using namespace dlltools;
using Catch::Approx;

TEST_CASE("calculate_shannon_entropy - empty data", "[entropy]") {
    REQUIRE(calculate_shannon_entropy(nullptr, 0) == 0.0);
}

TEST_CASE("calculate_shannon_entropy - single byte", "[entropy]") {
    uint8_t data[] = { 0x00 };
    double entropy = calculate_shannon_entropy(data, 1);
    REQUIRE(entropy == 0.0);  // No entropy with single value
}

TEST_CASE("calculate_shannon_entropy - uniform data", "[entropy]") {
    std::vector<uint8_t> data(1000, 0x00);  // All zeros
    double entropy = calculate_shannon_entropy(data.data(), data.size());
    REQUIRE(entropy == Approx(0.0).margin(0.001));
}

TEST_CASE("calculate_shannon_entropy - random-like data", "[entropy]") {
    // Create data with all byte values equally represented
    std::vector<uint8_t> data;
    for (int i = 0; i < 256; ++i) {
        data.push_back(static_cast<uint8_t>(i));
    }
    
    double entropy = calculate_shannon_entropy(data.data(), data.size());
    REQUIRE(entropy == Approx(8.0).margin(0.001));  // Maximum entropy
}

TEST_CASE("is_high_entropy", "[entropy]") {
    REQUIRE_FALSE(is_high_entropy(0.0));
    REQUIRE_FALSE(is_high_entropy(5.0));
    REQUIRE_FALSE(is_high_entropy(6.9));
    REQUIRE(is_high_entropy(7.0));
    REQUIRE(is_high_entropy(7.5));
    REQUIRE(is_high_entropy(8.0));
}

TEST_CASE("entropy_classification", "[entropy]") {
    REQUIRE(std::string(entropy_classification(0.5)) == "Very Low");
    REQUIRE(std::string(entropy_classification(2.0)) == "Low");
    REQUIRE(std::string(entropy_classification(4.0)) == "Medium");
    REQUIRE(std::string(entropy_classification(6.0)) == "High");
    REQUIRE(std::string(entropy_classification(7.5)) == "Very High (possibly packed/encrypted)");
}
