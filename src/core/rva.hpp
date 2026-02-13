/**
 * @file rva.hpp
 * @brief RVA (Relative Virtual Address) conversion utilities.
 * 
 * Provides functions for converting RVAs to file offsets and pointers,
 * with comprehensive bounds checking for safe PE parsing.
 * 
 * @example
 * @code
 * // Safe RVA conversion with bounds checking
 * if (auto ptr = dlltools::rva_to_ptr(pe, rva, sizeof(MyStruct))) {
 *     const auto* data = reinterpret_cast<const MyStruct*>(ptr);
 *     // Use data safely
 * }
 * 
 * // Using Result-based safe access
 * auto result = dlltools::safe_rva_to_ptr<MyStruct>(pe, rva);
 * if (result) {
 *     const auto* data = *result;
 *     // Use data safely
 * }
 * @endcode
 */

#pragma once

#include "core/pe_parser.hpp"
#include "core/error.hpp"
#include <optional>
#include <span>

namespace dlltools {

/**
 * @brief Convert RVA to file offset.
 * @param pe PE file to use for conversion.
 * @param rva Relative virtual address to convert.
 * @return File offset or nullopt if RVA is invalid.
 */
[[nodiscard]] std::optional<uint32_t> rva_to_file_offset(
    const PEFile& pe, 
    uint32_t rva
) noexcept;

/**
 * @brief Convert RVA to pointer.
 * @param pe PE file to use for conversion.
 * @param rva Relative virtual address to convert.
 * @return Pointer to data or nullptr if RVA is invalid.
 */
[[nodiscard]] const uint8_t* rva_to_ptr(
    const PEFile& pe, 
    uint32_t rva
) noexcept;

/**
 * @brief Convert RVA to pointer with size check.
 * @param pe PE file to use for conversion.
 * @param rva Relative virtual address to convert.
 * @param size Required size at the RVA.
 * @return Pointer to data or nullptr if RVA range is invalid.
 */
[[nodiscard]] const uint8_t* rva_to_ptr(
    const PEFile& pe, 
    uint32_t rva, 
    size_t size
) noexcept;

/**
 * @brief Check if RVA is valid (within image bounds).
 * @param pe PE file to check against.
 * @param rva Relative virtual address to validate.
 * @return true if RVA is valid, false otherwise.
 */
[[nodiscard]] bool is_valid_rva(const PEFile& pe, uint32_t rva) noexcept;

/**
 * @brief Check if RVA range is valid.
 * @param pe PE file to check against.
 * @param rva Starting RVA.
 * @param size Size of range in bytes.
 * @return true if entire RVA range is valid, false otherwise.
 */
[[nodiscard]] bool is_valid_rva_range(
    const PEFile& pe, 
    uint32_t rva, 
    size_t size
) noexcept;

/**
 * @brief Safe RVA to pointer conversion with Result type.
 * @param pe PE file to use for conversion.
 * @param rva Relative virtual address to convert.
 * @param size Required size at the RVA.
 * @return Result containing pointer to data or Error.
 */
[[nodiscard]] Result<const uint8_t*> safe_rva_to_ptr(
    const PEFile& pe,
    uint32_t rva,
    size_t size
) noexcept;

/**
 * @brief Safe RVA to typed pointer conversion.
 * @tparam T Type to cast the pointer to.
 * @param pe PE file to use for conversion.
 * @param rva Relative virtual address to convert.
 * @return Result containing typed pointer or Error.
 */
template<typename T>
[[nodiscard]] Result<const T*> safe_rva_to_ptr(
    const PEFile& pe,
    uint32_t rva
) noexcept {
    auto ptr_result = safe_rva_to_ptr(pe, rva, sizeof(T));
    if (!ptr_result) {
        return std::unexpected(std::move(ptr_result).error());
    }
    return reinterpret_cast<const T*>(*ptr_result);
}

/**
 * @brief Safe RVA to array conversion.
 * @tparam T Element type.
 * @param pe PE file to use for conversion.
 * @param rva Relative virtual address to convert.
 * @param count Number of elements.
 * @return Result containing span or Error.
 */
template<typename T>
[[nodiscard]] Result<std::span<const T>> safe_rva_to_array(
    const PEFile& pe,
    uint32_t rva,
    size_t count
) noexcept {
    if (count == 0) {
        return std::span<const T>{};
    }
    
    // Check for overflow
    size_t size;
    if (count > SIZE_MAX / sizeof(T)) {
        return std::unexpected(Error::out_of_bounds(rva, count * sizeof(T), pe.size()));
    }
    size = count * sizeof(T);
    
    auto ptr_result = safe_rva_to_ptr(pe, rva, size);
    if (!ptr_result) {
        return std::unexpected(std::move(ptr_result).error());
    }
    
    return std::span<const T>(reinterpret_cast<const T*>(*ptr_result), count);
}

/**
 * @brief Read a null-terminated string from RVA.
 * @param pe PE file to read from.
 * @param rva Relative virtual address of the string.
 * @param max_length Maximum length to read (to prevent overflow).
 * @return Result containing the string or Error.
 */
[[nodiscard]] Result<std::string> read_string_at_rva(
    const PEFile& pe,
    uint32_t rva,
    size_t max_length = 4096
);

} // namespace dlltools
