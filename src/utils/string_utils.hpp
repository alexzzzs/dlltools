#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace dlltools::utils {

// =============================================================================
// UTF-8 / UTF-16 Conversion Utilities
// =============================================================================

/// Convert UTF-8 string to UTF-16 wide string
/// @param str UTF-8 encoded string
/// @return UTF-16 wide string
[[nodiscard]] std::wstring utf8_to_wide(std::string_view str);

/// Convert UTF-16 wide string to UTF-8 string
/// @param wstr UTF-16 encoded wide string
/// @return UTF-8 string
[[nodiscard]] std::string wide_to_utf8(std::wstring_view wstr);

// =============================================================================
// String Formatting Utilities
// =============================================================================

/// Convert a value to hexadecimal string
/// @param value The value to convert
/// @param width Minimum width (padded with zeros)
/// @return Hexadecimal string representation
template<typename T>
[[nodiscard]] std::string to_hex(T value, int width = sizeof(T) * 2) {
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    std::string result;
    result.reserve(width + 2);
    
    const char* hex_chars = "0123456789ABCDEF";
    
    // Build hex string in reverse
    bool leading = true;
    for (int i = sizeof(T) * 2 - 1; i >= 0; --i) {
        int nibble = (value >> (i * 4)) & 0xF;
        if (nibble != 0 || !leading || i < width) {
            result.push_back(hex_chars[nibble]);
            leading = false;
        }
    }
    
    // Pad with zeros if needed
    while (static_cast<int>(result.size()) < width) {
        result.insert(result.begin(), '0');
    }
    
    return result;
}

/// Convert a value to hexadecimal string with 0x prefix
/// @param value The value to convert
/// @param width Minimum width (padded with zeros)
/// @return Hexadecimal string with 0x prefix
template<typename T>
[[nodiscard]] std::string to_hex_prefixed(T value, int width = sizeof(T) * 2) {
    return "0x" + to_hex(value, width);
}

// =============================================================================
// String Trimming Utilities
// =============================================================================

/// Trim whitespace from the start of a string
/// @param str String to trim
/// @return Trimmed string view
[[nodiscard]] std::string_view trim_left(std::string_view str);

/// Trim whitespace from the end of a string
/// @param str String to trim
/// @return Trimmed string view
[[nodiscard]] std::string_view trim_right(std::string_view str);

/// Trim whitespace from both ends of a string
/// @param str String to trim
/// @return Trimmed string view
[[nodiscard]] std::string_view trim(std::string_view str);

// =============================================================================
// PE-Specific String Utilities
// =============================================================================

/// Extract a null-terminated string from a buffer
/// @param data Pointer to string data
/// @param max_length Maximum length to read
/// @return String view of the null-terminated string
[[nodiscard]] std::string_view extract_string(
    const char* data,
    size_t max_length
);

/// Extract a fixed-length PE string (e.g., section name)
/// PE strings are 8 bytes, may not be null-terminated
/// @param data Pointer to string data
/// @param length Fixed length of the string field
/// @return Extracted string
[[nodiscard]] std::string extract_pe_string(
    const char* data,
    size_t length
);

/// Convert PE timestamp (Unix epoch) to human-readable string
/// @param timestamp PE timestamp (seconds since Unix epoch)
/// @return Formatted date/time string
[[nodiscard]] std::string format_timestamp(uint32_t timestamp);

/// Convert machine type to human-readable string
/// @param machine Machine type value from IMAGE_FILE_HEADER
/// @return Human-readable machine type name
[[nodiscard]] std::string machine_type_name(uint16_t machine);

/// Convert subsystem type to human-readable string
/// @param subsystem Subsystem value from IMAGE_OPTIONAL_HEADER
/// @return Human-readable subsystem name
[[nodiscard]] std::string subsystem_name(uint16_t subsystem);

/// Convert section characteristics to human-readable flags
/// @param characteristics Section characteristics value
/// @return Vector of flag names
[[nodiscard]] std::vector<std::string> section_characteristics_flags(uint32_t characteristics);

/// Convert DLL characteristics to human-readable flags
/// @param characteristics DLL characteristics value
/// @return Vector of flag names
[[nodiscard]] std::vector<std::string> dll_characteristics_flags(uint16_t characteristics);

// =============================================================================
// Size Formatting Utilities
// =============================================================================

/// Format a size in bytes to human-readable string
/// @param bytes Size in bytes
/// @return Human-readable size string (e.g., "1.5 MB")
[[nodiscard]] std::string format_size(uint64_t bytes);

/// Format an entropy value to string with appropriate precision
/// @param entropy Entropy value (0.0 - 8.0)
/// @return Formatted entropy string
[[nodiscard]] std::string format_entropy(double entropy);

/// Case-insensitive string comparison
/// @param a First string
/// @param b Second string
/// @return true if strings are equal (case-insensitive)
[[nodiscard]] bool string_equals_case_insensitive(
    std::string_view a, 
    std::string_view b
) noexcept;

/// Case-insensitive substring search
/// @param haystack String to search in
/// @param needle Substring to search for
/// @return true if needle is found in haystack (case-insensitive)
[[nodiscard]] bool string_contains_case_insensitive(
    std::string_view haystack,
    std::string_view needle
) noexcept;

} // namespace dlltools::utils
