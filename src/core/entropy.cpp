#include "core/entropy.hpp"
#include <cmath>
#include <array>

namespace dlltools {

double calculate_shannon_entropy(const uint8_t* data, size_t size) noexcept {
    if (!data || size == 0) {
        return 0.0;
    }

    // Count byte frequencies
    std::array<size_t, 256> frequencies{};
    frequencies.fill(0);
    
    for (size_t i = 0; i < size; ++i) {
        ++frequencies[data[i]];
    }

    // Calculate entropy
    double entropy = 0.0;
    const double log2 = std::log(2.0);
    
    for (size_t i = 0; i < 256; ++i) {
        if (frequencies[i] > 0) {
            double probability = static_cast<double>(frequencies[i]) / static_cast<double>(size);
            entropy -= probability * (std::log(probability) / log2);
        }
    }

    return entropy;
}

double calculate_entropy(std::span<const uint8_t> data) noexcept {
    return calculate_shannon_entropy(data.data(), data.size());
}

const char* entropy_classification(double entropy) noexcept {
    if (entropy < 1.0) {
        return "Very Low";
    } else if (entropy < 3.0) {
        return "Low";
    } else if (entropy < 5.0) {
        return "Medium";
    } else if (entropy < 7.0) {
        return "High";
    } else {
        return "Very High (possibly packed/encrypted)";
    }
}

} // namespace dlltools
