#pragma once

#include "core/error.hpp"
#include <vector>
#include <string>
#include <optional>
#include <cstdint>

// Windows PE structures
#include <windows.h>

namespace dlltools {

// Forward declaration
class PEFile;

/// Section header information
struct SectionHeader {
    std::string name;                   ///< Section name (up to 8 characters)
    uint32_t virtual_address = 0;       ///< RVA of section in memory
    uint32_t virtual_size = 0;          ///< Size of section in memory
    uint32_t raw_size = 0;              ///< Size of section on disk
    uint32_t raw_offset = 0;            ///< File offset of section data
    uint32_t characteristics = 0;       ///< Section flags
    
    /// Check if section is executable
    [[nodiscard]] bool is_executable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
    
    /// Check if section is readable
    [[nodiscard]] bool is_readable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_READ) != 0;
    }
    
    /// Check if section is writable
    [[nodiscard]] bool is_writable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }
    
    /// Check if section contains code
    [[nodiscard]] bool is_code() const noexcept {
        return (characteristics & IMAGE_SCN_CNT_CODE) != 0;
    }
    
    /// Check if section contains initialized data
    [[nodiscard]] bool is_initialized_data() const noexcept {
        return (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
    }
    
    /// Check if section contains uninitialized data
    [[nodiscard]] bool is_uninitialized_data() const noexcept {
        return (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
    }
    
    /// Check if section is discardable
    [[nodiscard]] bool is_discardable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
    }
    
    /// Check if section is shareable
    [[nodiscard]] bool is_shared() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_SHARED) != 0;
    }
    
    /// Calculate entropy of section data
    /// @param pe PE file containing the section
    /// @return Shannon entropy value (0.0 - 8.0)
    [[nodiscard]] double calculate_entropy(const PEFile& pe) const;
    
    /// Check if an RVA is within this section
    /// @param rva RVA to check
    /// @return true if RVA is within this section
    [[nodiscard]] bool contains_rva(uint32_t rva) const noexcept {
        return rva >= virtual_address && rva < virtual_address + virtual_size;
    }
    
    /// Convert RVA to file offset within this section
    /// @param rva RVA to convert
    /// @return File offset or nullopt if RVA not in section
    [[nodiscard]] std::optional<uint32_t> rva_to_offset(uint32_t rva) const noexcept {
        if (!contains_rva(rva)) {
            return std::nullopt;
        }
        return raw_offset + (rva - virtual_address);
    }
};

/// Section table container
class SectionTable {
public:
    /// Default constructor
    SectionTable() = default;
    
    /// Parse section table from PE file
    explicit SectionTable(const PEFile& pe);
    
    /// Get number of sections
    [[nodiscard]] size_t count() const noexcept { return sections_.size(); }
    
    /// Check if table is empty
    [[nodiscard]] bool empty() const noexcept { return sections_.empty(); }
    
    /// Get section by index
    /// @param index Section index (0-based)
    /// @return Reference to section header
    /// @throws std::out_of_range if index is invalid
    [[nodiscard]] const SectionHeader& operator[](size_t index) const;
    
    /// Get section by index with bounds checking
    /// @param index Section index (0-based)
    /// @return Pointer to section header or nullptr if invalid
    [[nodiscard]] const SectionHeader* at(size_t index) const noexcept;
    
    /// Find section by name
    /// @param name Section name to find
    /// @return Pointer to section header or nullptr if not found
    [[nodiscard]] const SectionHeader* find_by_name(std::string_view name) const noexcept;
    
    /// Find section index by name
    /// @param name Section name to find
    /// @return Section index or nullopt if not found
    [[nodiscard]] std::optional<size_t> find_index_by_name(std::string_view name) const noexcept;
    
    /// Find section containing an RVA
    /// @param rva RVA to find
    /// @return Pointer to section header or nullptr if not found
    [[nodiscard]] const SectionHeader* find_by_rva(uint32_t rva) const noexcept;
    
    /// Find section index containing an RVA
    /// @param rva RVA to find
    /// @return Section index or nullopt if not found
    [[nodiscard]] std::optional<size_t> find_index_by_rva(uint32_t rva) const noexcept;
    
    /// Iterator support
    [[nodiscard]] auto begin() const noexcept { return sections_.begin(); }
    [[nodiscard]] auto end() const noexcept { return sections_.end(); }
    [[nodiscard]] auto cbegin() const noexcept { return sections_.cbegin(); }
    [[nodiscard]] auto cend() const noexcept { return sections_.cend(); }
    
private:
    std::vector<SectionHeader> sections_;
};

} // namespace dlltools
