#pragma once

#include <cstdint>
#include <cstddef>
#include <span>

namespace dlltools {

/// Calculate Shannon entropy of a byte buffer
/// @param data Pointer to the data buffer
/// @param size Size of the data buffer in bytes
/// @return Entropy value between 0.0 and 8.0
///   - 0.0: All bytes are the same (no entropy)
///   - 8.0: Maximum entropy (random data)
[[nodiscard]] double calculate_shannon_entropy(const uint8_t* data, size_t size) noexcept;

/// Calculate entropy of a byte buffer (span version)
/// @param data Span of bytes
/// @return Entropy value between 0.0 and 8.0
[[nodiscard]] double calculate_entropy(std::span<const uint8_t> data) noexcept;

/// Check if entropy indicates possible packed/encrypted data
/// @param entropy Entropy value
/// @param threshold Threshold for high entropy (default 7.0)
/// @return true if entropy is above threshold
[[nodiscard]] inline bool is_high_entropy(double entropy, double threshold = 7.0) noexcept {
    return entropy >= threshold;
}

/// Get entropy classification string
/// @param entropy Entropy value
/// @return Classification string (e.g., "Low", "Medium", "High")
[[nodiscard]] const char* entropy_classification(double entropy) noexcept;

} // namespace dlltools
