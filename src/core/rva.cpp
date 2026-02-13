/**
 * @file rva.cpp
 * @brief Implementation of RVA conversion utilities.
 */

#include "core/rva.hpp"
#include "core/section.hpp"
#include <algorithm>

namespace dlltools {

std::optional<uint32_t> rva_to_file_offset(
    const PEFile& pe, 
    uint32_t rva
) noexcept {
    return pe.rva_to_offset(rva);
}

const uint8_t* rva_to_ptr(
    const PEFile& pe, 
    uint32_t rva
) noexcept {
    return pe.rva_to_ptr(rva);
}

const uint8_t* rva_to_ptr(
    const PEFile& pe, 
    uint32_t rva, 
    size_t size
) noexcept {
    return pe.rva_to_ptr(rva, size);
}

bool is_valid_rva(const PEFile& pe, uint32_t rva) noexcept {
    if (rva == 0) {
        return false;
    }
    
    // Check if within headers
    if (rva < pe.size_of_headers()) {
        return true;
    }
    
    // Check if within a section
    const auto& sections = pe.sections();
    for (const auto& section : sections) {
        if (section.contains_rva(rva)) {
            return true;
        }
    }
    
    return false;
}

bool is_valid_rva_range(
    const PEFile& pe, 
    uint32_t rva, 
    size_t size
) noexcept {
    if (rva == 0 || size == 0) {
        return false;
    }
    
    // Check for overflow
    if (static_cast<uint64_t>(rva) + size > UINT32_MAX) {
        return false;
    }
    
    uint32_t end_rva = rva + static_cast<uint32_t>(size);
    
    // Check if within headers
    if (rva < pe.size_of_headers()) {
        return end_rva <= pe.size_of_headers();
    }
    
    // Check if within a single section
    const auto& sections = pe.sections();
    for (const auto& section : sections) {
        if (section.contains_rva(rva)) {
            uint32_t section_end = section.virtual_address + section.virtual_size;
            return end_rva <= section_end;
        }
    }
    
    return false;
}

Result<const uint8_t*> safe_rva_to_ptr(
    const PEFile& pe,
    uint32_t rva,
    size_t size
) noexcept {
    // Validate RVA is not null
    if (rva == 0) {
        return std::unexpected(Error::invalid_rva(rva));
    }
    
    // Validate size is not zero
    if (size == 0) {
        return std::unexpected(Error::out_of_bounds(rva, size, pe.size()));
    }
    
    // Check for overflow
    if (static_cast<uint64_t>(rva) + size > UINT32_MAX) {
        return std::unexpected(Error::out_of_bounds(rva, size, pe.size()));
    }
    
    // Get the file offset
    auto offset_opt = pe.rva_to_offset(rva);
    if (!offset_opt) {
        return std::unexpected(Error::invalid_rva(rva));
    }
    
    uint32_t offset = *offset_opt;
    
    // Bounds check against file size
    if (static_cast<uint64_t>(offset) + size > pe.size()) {
        return std::unexpected(Error::out_of_bounds(offset, size, pe.size()));
    }
    
    // Return pointer
    return pe.data() + offset;
}

Result<std::string> read_string_at_rva(
    const PEFile& pe,
    uint32_t rva,
    size_t max_length
) {
    if (rva == 0) {
        return std::unexpected(Error::invalid_rva(rva));
    }
    
    // Get the file offset
    auto offset_opt = pe.rva_to_offset(rva);
    if (!offset_opt) {
        return std::unexpected(Error::invalid_rva(rva));
    }
    
    uint32_t offset = *offset_opt;
    const uint8_t* data = pe.data();
    size_t file_size = pe.size();
    
    // Read string character by character until null or max_length
    std::string result;
    result.reserve((std::min)(max_length, static_cast<size_t>(64)));
    
    size_t pos = offset;
    while (pos < file_size && result.size() < max_length) {
        char c = static_cast<char>(data[pos]);
        if (c == '\0') {
            break;
        }
        result.push_back(c);
        ++pos;
    }
    
    // Check if we hit the end of file without finding null terminator
    if (pos >= file_size && result.size() < max_length) {
        // String was truncated by end of file - still return what we have
        // but this might indicate a malformed PE
    }
    
    return result;
}

} // namespace dlltools
