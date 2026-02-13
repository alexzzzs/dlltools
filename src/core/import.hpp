#pragma once

#include "core/error.hpp"
#include <vector>
#include <string>
#include <optional>
#include <cstdint>

// Windows PE structures
#include <windows.h>

// Delay-load descriptor structure (may not be defined in all Windows SDK versions)
#ifndef ImgDelayDescr
typedef struct _ImgDelayDescr {
    DWORD           grAttrs;        // attributes
    DWORD           rvaDLLName;     // RVA to dll name
    DWORD           rvaHmod;        // RVA of module handle
    DWORD           rvaIAT;         // RVA of the IAT
    DWORD           rvaINT;         // RVA of the INT
    DWORD           rvaBoundIAT;    // RVA of the bound IAT
    DWORD           rvaUnloadIAT;   // RVA of copy of original IAT
    DWORD           dwTimeStamp;    // 0 if not bound,
                                    // O.W. date/time stamp of DLL bound to (Old BIND)
} ImgDelayDescr, * PImgDelayDescr;
#endif

namespace dlltools {

// Forward declaration
class PEFile;

/// Imported function information
struct ImportedFunction {
    std::string name;           ///< Function name (empty if imported by ordinal)
    uint16_t ordinal = 0;       ///< Ordinal number
    bool is_by_ordinal = false; ///< True if imported by ordinal
    uint32_t thunk_rva = 0;     ///< Original thunk RVA (FirstThunk)
    uint32_t hint = 0;          ///< Name hint for lookup (by-name imports only)
};

/// Imported DLL information
struct ImportedDll {
    std::string name;                       ///< DLL name
    std::vector<ImportedFunction> functions;///< Imported functions
    uint32_t first_thunk_rva = 0;           ///< FirstThunk RVA
    uint32_t original_first_thunk_rva = 0;  ///< OriginalFirstThunk RVA
    bool is_delay_load = false;             ///< True if delay-load import
};

/// Import table container
class ImportTable {
public:
    /// Default constructor
    ImportTable() = default;
    
    /// Parse import table from PE file
    /// @param pe PE file to parse
    /// @return Result containing ImportTable or Error
    [[nodiscard]] static Result<ImportTable> parse(const PEFile& pe);
    
    /// Get number of imported DLLs
    [[nodiscard]] size_t dll_count() const noexcept { return imports_.size(); }
    
    /// Get total number of imported functions
    [[nodiscard]] size_t function_count() const noexcept;
    
    /// Check if table is empty
    [[nodiscard]] bool empty() const noexcept { return imports_.empty(); }
    
    /// Get imported DLL by index
    /// @param index DLL index (0-based)
    /// @return Reference to imported DLL
    /// @throws std::out_of_range if index is invalid
    [[nodiscard]] const ImportedDll& operator[](size_t index) const;
    
    /// Get imported DLL by index with bounds checking
    /// @param index DLL index (0-based)
    /// @return Pointer to imported DLL or nullptr if invalid
    [[nodiscard]] const ImportedDll* at(size_t index) const noexcept;
    
    /// Find DLL by name
    /// @param name DLL name to find (case-insensitive)
    /// @return Pointer to imported DLL or nullptr if not found
    [[nodiscard]] const ImportedDll* find_dll(std::string_view name) const noexcept;
    
    /// Find all imports of a specific function name
    /// @param name Function name to find
    /// @return Vector of (dll_index, function_index) pairs
    [[nodiscard]] std::vector<std::pair<size_t, size_t>> 
    find_function(std::string_view name) const;
    
    /// Iterator support
    [[nodiscard]] auto begin() const noexcept { return imports_.begin(); }
    [[nodiscard]] auto end() const noexcept { return imports_.end(); }
    [[nodiscard]] auto cbegin() const noexcept { return imports_.cbegin(); }
    [[nodiscard]] auto cend() const noexcept { return imports_.cend(); }
    
private:
    ImportTable(std::vector<ImportedDll>&& imports) : imports_(std::move(imports)) {}
    
    /// Parse import descriptor table
    [[nodiscard]] static Result<std::vector<ImportedDll>> 
    parse_imports(const PEFile& pe);
    
    /// Parse delay-load imports
    [[nodiscard]] static Result<void>
    parse_delay_loads(const PEFile& pe, std::vector<ImportedDll>& imports);
    
    /// Parse thunk data for a single import descriptor
    [[nodiscard]] static Result<std::vector<ImportedFunction>>
    parse_thunks(
        const PEFile& pe,
        uint32_t thunk_rva,
        bool is_pe32_plus
    );
    
    /// Read import name from hint/name table
    [[nodiscard]] static std::optional<std::pair<std::string, uint16_t>>
    read_import_name(const PEFile& pe, uint32_t rva);
    
    std::vector<ImportedDll> imports_;
};

} // namespace dlltools
