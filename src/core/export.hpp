#pragma once

#include "core/error.hpp"
#include <vector>
#include <string>
#include <optional>
#include <unordered_map>
#include <cstdint>

// Windows PE structures
#include <windows.h>

namespace dlltools {

// Forward declaration
class PEFile;

/// Exported function information
struct ExportedFunction {
    std::string name;           ///< Function name (may be empty for ordinal-only exports)
    uint16_t ordinal = 0;       ///< Export ordinal
    uint32_t rva = 0;           ///< Export RVA (address relative to image base)
    bool is_forwarded = false;  ///< True if this is a forwarded export
    std::string forward_target; ///< Forward target (e.g., "KERNEL32.GetProcAddress")
};

/// Export table container
class ExportTable {
public:
    /// Default constructor
    ExportTable() = default;
    
    /// Parse export table from PE file
    /// @param pe PE file to parse
    /// @return Result containing ExportTable or Error
    [[nodiscard]] static Result<ExportTable> parse(const PEFile& pe);
    
    /// Get number of exported functions
    [[nodiscard]] size_t count() const noexcept { return exports_.size(); }
    
    /// Check if table is empty
    [[nodiscard]] bool empty() const noexcept { return exports_.empty(); }
    
    /// Get exported function by index
    /// @param index Function index (0-based)
    /// @return Reference to exported function
    /// @throws std::out_of_range if index is invalid
    [[nodiscard]] const ExportedFunction& operator[](size_t index) const;
    
    /// Get exported function by index with bounds checking
    /// @param index Function index (0-based)
    /// @return Pointer to exported function or nullptr if invalid
    [[nodiscard]] const ExportedFunction* at(size_t index) const noexcept;
    
    /// Find function by name
    /// @param name Function name to find
    /// @return Pointer to exported function or nullptr if not found
    [[nodiscard]] const ExportedFunction* find_by_name(std::string_view name) const noexcept;
    
    /// Find function index by name
    /// @param name Function name to find
    /// @return Function index or nullopt if not found
    [[nodiscard]] std::optional<size_t> find_index_by_name(std::string_view name) const noexcept;
    
    /// Find function by ordinal
    /// @param ordinal Ordinal to find
    /// @return Pointer to exported function or nullptr if not found
    [[nodiscard]] const ExportedFunction* find_by_ordinal(uint16_t ordinal) const noexcept;
    
    /// Find function index by ordinal
    /// @param ordinal Ordinal to find
    /// @return Function index or nullopt if not found
    [[nodiscard]] std::optional<size_t> find_index_by_ordinal(uint16_t ordinal) const noexcept;
    
    /// Get the DLL name from export directory
    [[nodiscard]] const std::string& dll_name() const noexcept { return dll_name_; }
    
    /// Get the base ordinal
    [[nodiscard]] uint32_t ordinal_base() const noexcept { return ordinal_base_; }
    
    /// Iterator support
    [[nodiscard]] auto begin() const noexcept { return exports_.begin(); }
    [[nodiscard]] auto end() const noexcept { return exports_.end(); }
    [[nodiscard]] auto cbegin() const noexcept { return exports_.cbegin(); }
    [[nodiscard]] auto cend() const noexcept { return exports_.cend(); }
    
private:
    ExportTable(
        std::vector<ExportedFunction>&& exports,
        std::string dll_name,
        uint32_t ordinal_base
    );
    
    std::vector<ExportedFunction> exports_;
    std::string dll_name_;
    uint32_t ordinal_base_ = 0;
    
    // Index maps for fast lookup
    std::unordered_map<std::string, size_t> name_index_;
    std::unordered_map<uint16_t, size_t> ordinal_index_;
};

} // namespace dlltools
