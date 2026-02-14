/**
 * @file rich.hpp
 * @brief Rich Header parsing for PE files.
 * 
 * The Rich Header is a Microsoft-specific PE structure located immediately
 * after the DOS header. It contains information about the tools used to
 * compile/link the PE file, along with checksums for anti-tamper detection.
 * 
 * @see https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 */

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

/// Rich Header entry representing a tool used during compilation
struct RichEntry {
    uint16_t id = 0;           ///< Tool ID (e.g., link.exe, cvtres.exe, cl.exe)
    uint16_t version = 0;      ///< Tool version
    uint32_t count = 0;        ///< Number of times this tool was used
};

/// Known tool IDs for Rich Header
enum class RichToolId : uint16_t {
    Unknown = 0,
    Linker = 1,           ///< link.exe
    Cvtres = 2,           ///< cvtres.exe
    ResourceCompiler = 3, ///< rc.exe
    CCompiler = 4,        ///< cl.exe (C compiler)
    CppCompiler = 5,      ///< cl.exe (C++ compiler)
    Masm = 6,             ///< ml.exe (MASM assembler)
    ImportLibrary = 7,    ///< Generated import library
    ExportTable = 8,      ///< Export table generation
    ImpLib = 9,           ///< lib.exe (import library tool)
    // Common Visual Studio tool IDs
    VS2003 = 0x0000,
    VS2005 = 0x0001,
    VS2008 = 0x0002,
    VS2010 = 0x0003,
    VS2012 = 0x0004,
    VS2013 = 0x0005,
    VS2015 = 0x0006,
    VS2017 = 0x0007,
    VS2019 = 0x0008,
    VS2022 = 0x0009,
};

/// Rich Header class following existing patterns (like ExportTable)
class RichHeader {
public:
    /// Default constructor - creates an empty Rich Header
    RichHeader() = default;
    
    /// Parse Rich Header from PE file
    /// @param pe PE file to parse
    /// @return Result containing RichHeader or Error
    [[nodiscard]] static Result<RichHeader> parse(const PEFile& pe);
    
    /// Check if Rich Header is present
    [[nodiscard]] bool is_present() const noexcept { return present_; }
    
    /// Get number of entries
    [[nodiscard]] size_t count() const noexcept { return entries_.size(); }
    
    /// Check if header is empty
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    
    /// Get XOR key used for encoding
    [[nodiscard]] uint32_t xor_key() const noexcept { return xor_key_; }
    
    /// Get entries
    [[nodiscard]] const std::vector<RichEntry>& entries() const noexcept { return entries_; }
    
    /// Get entry by index
    /// @param index Entry index (0-based)
    /// @return Reference to entry
    /// @throws std::out_of_range if index is invalid
    [[nodiscard]] const RichEntry& operator[](size_t index) const;
    
    /// Get entry by index with bounds checking
    /// @param index Entry index (0-based)
    /// @return Pointer to entry or nullptr if invalid
    [[nodiscard]] const RichEntry* at(size_t index) const noexcept;
    
    /// Validate the Rich Header checksum
    /// @return true if checksum is valid, false otherwise
    [[nodiscard]] bool validate_checksum() const noexcept { return checksum_valid_; }
    
    /// Get the offset of the Rich Header in the file
    [[nodiscard]] uint32_t offset() const noexcept { return offset_; }
    
    /// Get the size of the Rich Header in bytes
    [[nodiscard]] uint32_t size() const noexcept { return size_; }
    
    /// Get tool name for a given tool ID
    /// @param id Tool ID
    /// @return Human-readable tool name
    [[nodiscard]] static std::string tool_name(uint16_t id);
    
    /// Iterator support
    [[nodiscard]] auto begin() const noexcept { return entries_.begin(); }
    [[nodiscard]] auto end() const noexcept { return entries_.end(); }
    [[nodiscard]] auto cbegin() const noexcept { return entries_.cbegin(); }
    [[nodiscard]] auto cend() const noexcept { return entries_.cend(); }
    
private:
    RichHeader(
        std::vector<RichEntry>&& entries,
        uint32_t xor_key,
        uint32_t offset,
        uint32_t size,
        bool checksum_valid
    );
    
    std::vector<RichEntry> entries_;
    uint32_t xor_key_ = 0;
    uint32_t offset_ = 0;
    uint32_t size_ = 0;
    bool present_ = false;
    bool checksum_valid_ = false;
    
    /// Magic marker "Rich" as uint32_t (0x68636952)
    static constexpr uint32_t RICH_MAGIC = 0x68636952;
    
    /// End marker "DanS" as uint32_t (0x536E6144)
    static constexpr uint32_t DAN_MAGIC = 0x536E6144;
};

} // namespace dlltools
