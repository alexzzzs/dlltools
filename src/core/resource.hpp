#pragma once

#include "core/error.hpp"
#include <vector>
#include <string>
#include <optional>
#include <cstdint>
#include <span>

// Windows PE structures
// Define NOMINMAX to avoid min/max macro conflicts with std::min/std::max
#define NOMINMAX
#include <windows.h>

namespace dlltools {

// Forward declaration
class PEFile;

/// Resource type constants - using Windows-defined RT_* macros from winuser.h
/// These are defined as MAKEINTRESOURCE(i) which creates pointer values
namespace resource_types {
    // Windows already defines RT_CURSOR, RT_BITMAP, etc. as macros
    // We provide constexpr integer equivalents for comparison purposes
    constexpr uint32_t CURSOR_ID       = 1;
    constexpr uint32_t BITMAP_ID       = 2;
    constexpr uint32_t ICON_ID         = 3;
    constexpr uint32_t MENU_ID         = 4;
    constexpr uint32_t DIALOG_ID       = 5;
    constexpr uint32_t STRING_ID       = 6;
    constexpr uint32_t FONTDIR_ID      = 7;
    constexpr uint32_t FONT_ID         = 8;
    constexpr uint32_t ACCELERATOR_ID  = 9;
    constexpr uint32_t RCDATA_ID       = 10;
    constexpr uint32_t MESSAGETABLE_ID = 11;
    constexpr uint32_t GROUP_CURSOR_ID = 12;
    constexpr uint32_t GROUP_ICON_ID   = 14;
    constexpr uint32_t VERSION_ID      = 16;
    constexpr uint32_t DLGINCLUDE_ID   = 17;
    constexpr uint32_t PLUGPLAY_ID     = 19;
    constexpr uint32_t VXD_ID          = 20;
    constexpr uint32_t ANICURSOR_ID    = 21;
    constexpr uint32_t ANIICON_ID      = 22;
    constexpr uint32_t HTML_ID         = 23;
    constexpr uint32_t MANIFEST_ID     = 24;
}

/// Resource entry information
struct ResourceEntry {
    std::string name;           ///< Resource name (if named)
    uint32_t id = 0;            ///< Resource ID (if numeric)
    bool is_named = false;      ///< True if resource has a name instead of ID
    uint32_t offset = 0;        ///< File offset to resource data
    uint32_t rva = 0;           ///< RVA of resource data
    uint32_t size = 0;          ///< Size of resource data
    uint32_t code_page = 0;     ///< Code page for resource data
    std::string type_name;      ///< Type name (if named type)
    uint32_t type_id = 0;       ///< Type ID (if numeric type)
    bool is_typed_named = false;///< True if type has a name instead of ID
    uint16_t language_id = 0;   ///< Language ID
    uint16_t sublanguage_id = 0;///< Sublanguage ID
};

/// Resource type information
struct ResourceType {
    uint32_t type_id = 0;       ///< Type ID (if numeric)
    std::string type_name;      ///< Type name (if named)
    bool is_named = false;      ///< True if type has a name
    std::vector<ResourceEntry> entries; ///< Resources of this type
};

/// Resource directory container
class ResourceTable {
public:
    /// Default constructor
    ResourceTable() = default;
    
    /// Parse resource directory from PE file
    /// @param pe PE file to parse
    /// @return Result containing ResourceTable or Error
    [[nodiscard]] static Result<ResourceTable> parse(const PEFile& pe);
    
    /// Get number of resource types
    [[nodiscard]] size_t type_count() const noexcept { return types_.size(); }
    
    /// Get total number of resource entries
    [[nodiscard]] size_t entry_count() const noexcept;
    
    /// Check if table is empty
    [[nodiscard]] bool empty() const noexcept { return types_.empty(); }
    
    /// Get resource type by index
    /// @param index Type index (0-based)
    /// @return Reference to resource type
    /// @throws std::out_of_range if index is invalid
    [[nodiscard]] const ResourceType& operator[](size_t index) const;
    
    /// Get resource type by index with bounds checking
    /// @param index Type index (0-based)
    /// @return Pointer to resource type or nullptr if invalid
    [[nodiscard]] const ResourceType* at(size_t index) const noexcept;
    
    /// Find resources by type ID
    /// @param type_id Type ID to find
    /// @return Pointer to resource type or nullptr if not found
    [[nodiscard]] const ResourceType* find_by_type(uint32_t type_id) const noexcept;
    
    /// Find resources by type name
    /// @param name Type name to find (case-insensitive)
    /// @return Pointer to resource type or nullptr if not found
    [[nodiscard]] const ResourceType* find_by_type_name(std::string_view name) const noexcept;
    
    /// Get all entries of a specific type
    /// @param type_id Type ID to find
    /// @return Vector of resource entries
    [[nodiscard]] std::vector<ResourceEntry> get_entries_by_type(uint32_t type_id) const;
    
    /// Get human-readable type name from type ID
    /// @param type_id Type ID
    /// @return Human-readable name or "Unknown"
    [[nodiscard]] static std::string type_id_to_string(uint32_t type_id);
    
    /// Check if PE file has resources
    [[nodiscard]] bool has_resources() const noexcept { return !types_.empty(); }
    
    /// Get the resource directory RVA
    [[nodiscard]] uint32_t directory_rva() const noexcept { return directory_rva_; }
    
    /// Get the resource directory size
    [[nodiscard]] uint32_t directory_size() const noexcept { return directory_size_; }
    
    /// Iterator support
    [[nodiscard]] auto begin() const noexcept { return types_.begin(); }
    [[nodiscard]] auto end() const noexcept { return types_.end(); }
    [[nodiscard]] auto cbegin() const noexcept { return types_.cbegin(); }
    [[nodiscard]] auto cend() const noexcept { return types_.cend(); }
    
private:
    ResourceTable(
        std::vector<ResourceType>&& types,
        uint32_t directory_rva,
        uint32_t directory_size
    );
    
    /// Parse resource directory recursively
    [[nodiscard]] static Result<std::vector<ResourceType>> 
    parse_directory(const PEFile& pe, uint32_t rva, uint32_t size);
    
    /// Parse a single directory entry
    [[nodiscard]] static Result<void>
    parse_entry(
        const PEFile& pe,
        const IMAGE_RESOURCE_DIRECTORY_ENTRY& entry,
        bool is_type_level,
        ResourceType& type_info,
        uint32_t base_rva
    );
    
    /// Read Unicode string from resource directory
    [[nodiscard]] static std::optional<std::string>
    read_unicode_string(const PEFile& pe, uint32_t rva);
    
    std::vector<ResourceType> types_;
    uint32_t directory_rva_ = 0;
    uint32_t directory_size_ = 0;
};

} // namespace dlltools
