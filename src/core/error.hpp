/**
 * @file error.hpp
 * @brief Error handling infrastructure for the dlltools library.
 * 
 * This file provides a comprehensive error handling system using C++23's
 * std::expected type. It includes error categories, the Error struct,
 * and convenience macros for error propagation.
 * 
 * @example
 * @code
 * // Creating a Result type
 * dlltools::Result<int> parse_int(std::string_view str) {
 *     if (str.empty()) {
 *         return std::unexpected(dlltools::Error::invalid_argument(str, "empty string"));
 *     }
 *     return std::stoi(std::string(str));
 * }
 * 
 * // Using the TRY macro for error propagation
 * dlltools::Result<int> compute() {
 *     auto value = DLLTOOLS_TRY(parse_int("42"));
 *     return value * 2;
 * }
 * @endcode
 */

#pragma once

#include <expected>
#include <string>
#include <source_location>
#include <format>
#include <filesystem>

namespace dlltools {

/**
 * @brief Error categories for classification.
 * 
 * Used to group errors by their source for easier filtering and handling.
 */
enum class ErrorCategory {
    FileIO,         ///< File I/O errors (not found, access denied, etc.)
    PEValidation,   ///< PE validation errors (invalid signatures, malformed headers)
    BoundsCheck,    ///< Bounds check failures (out-of-bounds access attempts)
    Parsing,        ///< General parsing failures
    ProcessAccess,  ///< Live process access errors
    CLI             ///< Command-line argument errors
};

/**
 * @brief Convert error category to string representation.
 * @param cat The error category to convert.
 * @return A string view of the category name.
 */
[[nodiscard]] constexpr std::string_view error_category_name(ErrorCategory cat) noexcept {
    switch (cat) {
        case ErrorCategory::FileIO:        return "FileIO";
        case ErrorCategory::PEValidation:  return "PEValidation";
        case ErrorCategory::BoundsCheck:   return "BoundsCheck";
        case ErrorCategory::Parsing:       return "Parsing";
        case ErrorCategory::ProcessAccess: return "ProcessAccess";
        case ErrorCategory::CLI:           return "CLI";
        default:                           return "Unknown";
    }
}

/**
 * @brief Error type with category, message, and source location.
 * 
 * Provides rich error information including automatic source location
 * capture for debugging. Includes factory methods for common error types.
 * 
 * @note All factory methods automatically capture the source location.
 */
struct Error {
    ErrorCategory category;     ///< The error category
    std::string message;        ///< Human-readable error message
    std::source_location location; ///< Source location where error occurred

    /**
     * @brief Create an error with explicit values.
     * @param cat The error category.
     * @param msg The error message.
     * @param loc Source location (automatically captured).
     */
    Error(
        ErrorCategory cat,
        std::string msg,
        std::source_location loc = std::source_location::current()
    ) : category(cat), message(std::move(msg)), location(loc) {}

    /**
     * @brief Get formatted error string.
     * @return A formatted string with category, message, and location.
     */
    [[nodiscard]] std::string format() const {
        return std::format("[{}] {} ({}:{})",
            error_category_name(category),
            message,
            location.file_name(),
            location.line()
        );
    }

    // =========================================================================
    // Factory methods for common errors
    // =========================================================================

    /// File not found error
    [[nodiscard]] static Error file_not_found(
        const std::filesystem::path& path,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::FileIO,
            std::format("File not found: {}", path.string()),
            loc
        );
    }

    /// File access denied error
    [[nodiscard]] static Error access_denied(
        const std::filesystem::path& path,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::FileIO,
            std::format("Access denied: {}", path.string()),
            loc
        );
    }

    /// File mapping failed error
    [[nodiscard]] static Error mapping_failed(
        const std::filesystem::path& path,
        std::string_view reason,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::FileIO,
            std::format("Failed to map file '{}': {}", path.string(), reason),
            loc
        );
    }

    /// Invalid DOS signature (MZ magic)
    [[nodiscard]] static Error invalid_dos_signature(
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::PEValidation,
            "Invalid DOS signature (expected 'MZ')",
            loc
        );
    }

    /// Invalid PE signature (PE\0\0)
    [[nodiscard]] static Error invalid_pe_signature(
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::PEValidation,
            "Invalid PE signature (expected 'PE\\0\\0')",
            loc
        );
    }

    /// File too small for PE structure
    [[nodiscard]] static Error file_too_small(
        size_t actual_size,
        size_t required_size,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::PEValidation,
            std::format("File too small: {} bytes, need at least {} bytes", actual_size, required_size),
            loc
        );
    }

    /// Out of bounds access
    [[nodiscard]] static Error out_of_bounds(
        size_t offset,
        size_t size,
        size_t file_size,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::BoundsCheck,
            std::format("Out of bounds access: offset {} + size {} exceeds file size {}", offset, size, file_size),
            loc
        );
    }

    /// Invalid RVA
    [[nodiscard]] static Error invalid_rva(
        uint32_t rva,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::BoundsCheck,
            std::format("Invalid RVA: 0x{:08X}", rva),
            loc
        );
    }

    /// Invalid section index
    [[nodiscard]] static Error invalid_section_index(
        size_t index,
        size_t count,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::BoundsCheck,
            std::format("Invalid section index: {} (have {} sections)", index, count),
            loc
        );
    }

    /// Section not found
    [[nodiscard]] static Error section_not_found(
        std::string_view name,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::Parsing,
            std::format("Section not found: {}", name),
            loc
        );
    }

    /// Missing data directory
    [[nodiscard]] static Error missing_data_directory(
        size_t index,
        std::string_view name,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::Parsing,
            std::format("Data directory {} ({}) not present", index, name),
            loc
        );
    }

    /// Process access denied
    [[nodiscard]] static Error process_access_denied(
        uint32_t pid,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::ProcessAccess,
            std::format("Access denied to process {}", pid),
            loc
        );
    }

    /// Process not found
    [[nodiscard]] static Error process_not_found(
        uint32_t pid,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::ProcessAccess,
            std::format("Process {} not found", pid),
            loc
        );
    }

    /// Invalid argument
    [[nodiscard]] static Error invalid_argument(
        std::string_view arg,
        std::string_view reason,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::CLI,
            std::format("Invalid argument '{}': {}", arg, reason),
            loc
        );
    }

    /// Missing argument
    [[nodiscard]] static Error missing_argument(
        std::string_view arg,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::CLI,
            std::format("Missing required argument: {}", arg),
            loc
        );
    }

    /// Unknown command
    [[nodiscard]] static Error unknown_command(
        std::string_view cmd,
        std::source_location loc = std::source_location::current()
    ) {
        return Error(
            ErrorCategory::CLI,
            std::format("Unknown command: {}", cmd),
            loc
        );
    }
};

/// Result type using C++23 std::expected
template<typename T>
using Result = std::expected<T, Error>;

/// Unexpected type for error construction
using Unexpected = std::unexpected<Error>;

/// Convenience function to create an unexpected error
[[nodiscard]] inline Unexpected make_unexpected(Error error) {
    return Unexpected(std::move(error));
}

} // namespace dlltools

// =============================================================================
// TRY macro for error propagation (MSVC-compatible)
// =============================================================================

/// Propagate errors from a Result type
/// Usage: auto value = TRY(some_function_returning_result());
/// Note: Uses lambda for MSVC compatibility instead of statement expressions
#define DLLTOOLS_TRY(expr)                                             \
    [&]() -> decltype(auto) {                                          \
        auto _result = (expr);                                         \
        if (!_result) {                                                \
            return ::dlltools::make_unexpected(std::move(_result).error()); \
        }                                                              \
        return std::move(*_result);                                    \
    }()

/// Alternative name for clarity
#define TRY DLLTOOLS_TRY
