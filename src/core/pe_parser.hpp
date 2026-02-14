/**
 * @file pe_parser.hpp
 * @brief Main PE file parser interface for the dlltools library.
 * 
 * This file provides the core PEFile and PEParser classes for parsing
 * and inspecting Windows Portable Executable (PE) files, including
 * DLLs and EXEs.
 * 
 * @example
 * @code
 * auto result = dlltools::PEParser::parse("kernel32.dll");
 * if (result) {
 *     const auto& pe = *result;
 *     std::cout << "Sections: " << pe.section_count() << "\n";
 *     std::cout << "Image Base: 0x" << std::hex << pe.image_base() << "\n";
 * }
 * @endcode
 */

#pragma once

#include "core/error.hpp"
#include "utils/file_mapping.hpp"
#include <filesystem>
#include <memory>
#include <optional>
#include <functional>

// Windows PE structures
#include <windows.h>

namespace dlltools {

// Forward declarations
class SectionTable;
class ImportTable;
class ExportTable;
class ResourceTable;
struct SecurityFeatures;

/**
 * @brief PE file format type enumeration.
 * 
 * Distinguishes between 32-bit (PE32) and 64-bit (PE32+) executable formats.
 */
enum class PEFormat {
    PE32,   ///< 32-bit PE format (IMAGE_NT_HEADERS32)
    PE32Plus ///< 64-bit PE format (IMAGE_NT_HEADERS64)
};

/**
 * @brief Main PE file representation class.
 * 
 * Provides access to PE headers, sections, imports, exports, resources,
 * and security features. Uses lazy loading for expensive operations.
 * 
 * @note This class is non-copyable but movable.
 * @note All parsing operations use bounds checking for safety.
 */
class PEFile {
public:
    /// Default constructor - creates an invalid PEFile
    PEFile() = default;

    /// Destructor - defined in implementation for unique_ptr with incomplete types
    ~PEFile();

    /// Move constructor
    PEFile(PEFile&&) = default;

    /// Move assignment operator
    PEFile& operator=(PEFile&&) = default;

    /// Deleted copy constructor
    PEFile(const PEFile&) = delete;
    /// Deleted copy assignment operator
    PEFile& operator=(const PEFile&) = delete;

    /**
     * @brief Check if PE file is valid.
     * @return true if the PE file was successfully parsed, false otherwise.
     */
    [[nodiscard]] bool is_valid() const noexcept { return mapping_.is_valid(); }

    /**
     * @brief Get the PE format (PE32 or PE32+).
     * @return The format of this PE file.
     */
    [[nodiscard]] PEFormat format() const noexcept { return format_; }

    /**
     * @brief Check if this is a 64-bit PE.
     * @return true if PE32+ (64-bit), false otherwise.
     */
    [[nodiscard]] bool is_pe32_plus() const noexcept { return format_ == PEFormat::PE32Plus; }

    /**
     * @brief Check if this is a 32-bit PE.
     * @return true if PE32 (32-bit), false otherwise.
     */
    [[nodiscard]] bool is_pe32() const noexcept { return format_ == PEFormat::PE32; }

    // =========================================================================
    // DOS Header Access
    // =========================================================================

    /**
     * @brief Get DOS header.
     * @return Reference to the IMAGE_DOS_HEADER structure.
     * @warning Only call this on a valid PEFile (check is_valid() first).
     */
    [[nodiscard]] const IMAGE_DOS_HEADER& dos_header() const noexcept {
        return *dos_header_;
    }

    /**
     * @brief Get e_lfanew (offset to NT headers).
     * @return The file offset to the NT headers.
     */
    [[nodiscard]] int32_t e_lfanew() const noexcept {
        return dos_header_->e_lfanew;
    }

    // =========================================================================
    // File Header Access (common to PE32 and PE32+)
    // =========================================================================

    /**
     * @brief Get file header (IMAGE_FILE_HEADER).
     * @return Reference to the file header structure.
     */
    [[nodiscard]] const IMAGE_FILE_HEADER& file_header() const noexcept;

    /**
     * @brief Get machine type.
     * @return The target machine architecture (e.g., IMAGE_FILE_MACHINE_AMD64).
     */
    [[nodiscard]] uint16_t machine_type() const noexcept {
        return file_header().Machine;
    }

    /**
     * @brief Get number of sections.
     * @return The number of sections in the PE file.
     */
    [[nodiscard]] uint16_t section_count() const noexcept {
        return file_header().NumberOfSections;
    }

    /**
     * @brief Get timestamp.
     * @return The compilation timestamp (Unix epoch).
     */
    [[nodiscard]] uint32_t timestamp() const noexcept {
        return file_header().TimeDateStamp;
    }

    /**
     * @brief Get file characteristics.
     * @return The characteristics flags (e.g., IMAGE_FILE_DLL).
     */
    [[nodiscard]] uint16_t characteristics() const noexcept {
        return file_header().Characteristics;
    }

    // =========================================================================
    // Optional Header Access
    // =========================================================================

    /// Get optional header magic
    [[nodiscard]] uint16_t optional_header_magic() const noexcept;

    /// Get subsystem
    [[nodiscard]] uint16_t subsystem() const noexcept;

    /// Get DLL characteristics
    [[nodiscard]] uint16_t dll_characteristics() const noexcept;

    /// Get image base address
    [[nodiscard]] uint64_t image_base() const noexcept;

    /// Get entry point RVA
    [[nodiscard]] uint32_t entry_point_rva() const noexcept;

    /// Get section alignment
    [[nodiscard]] uint32_t section_alignment() const noexcept;

    /// Get file alignment
    [[nodiscard]] uint32_t file_alignment() const noexcept;

    /// Get size of image
    [[nodiscard]] uint32_t size_of_image() const noexcept;

    /// Get size of headers
    [[nodiscard]] uint32_t size_of_headers() const noexcept;

    /// Get size of code section
    [[nodiscard]] uint32_t size_of_code() const noexcept;

    /// Get size of initialized data
    [[nodiscard]] uint32_t size_of_initialized_data() const noexcept;

    /// Get size of uninitialized data
    [[nodiscard]] uint32_t size_of_uninitialized_data() const noexcept;

    // =========================================================================
    // Data Directory Access
    // =========================================================================

    /// Get number of data directories
    [[nodiscard]] uint32_t data_directory_count() const noexcept;

    /// Get data directory entry
    /// @param index Data directory index (0-15)
    /// @return Pointer to data directory or nullptr if index is invalid
    [[nodiscard]] const IMAGE_DATA_DIRECTORY* data_directory(uint32_t index) const noexcept;

    /// Check if data directory is present
    [[nodiscard]] bool has_data_directory(uint32_t index) const noexcept;

    // =========================================================================
    // Section Table Access
    // =========================================================================

    /// Get section table
    [[nodiscard]] const SectionTable& sections() const;

    /// Get pointer to raw section headers
    [[nodiscard]] const IMAGE_SECTION_HEADER* section_headers() const noexcept;

    // =========================================================================
    // Import/Export Table Access
    // =========================================================================

    /// Get import table (lazy-loaded)
    [[nodiscard]] Result<std::reference_wrapper<const ImportTable>> imports() const;

    /// Get export table (lazy-loaded)
    [[nodiscard]] Result<std::reference_wrapper<const ExportTable>> exports() const;

    /// Get resource table (lazy-loaded)
    [[nodiscard]] Result<std::reference_wrapper<const ResourceTable>> resources() const;

    // =========================================================================
    // Security Analysis
    // =========================================================================

    /// Get security features
    [[nodiscard]] SecurityFeatures security_features() const;

    // =========================================================================
    // Raw Data Access
    // =========================================================================

    /// Get raw file data
    [[nodiscard]] const uint8_t* data() const noexcept { return mapping_.data(); }

    /// Get file size
    [[nodiscard]] size_t size() const noexcept { return mapping_.size(); }

    /// Get file mapping
    [[nodiscard]] const utils::FileMapping& mapping() const noexcept { return mapping_; }

    /// Convert RVA to file offset
    /// @param rva Relative virtual address
    /// @return File offset or nullopt if invalid
    [[nodiscard]] std::optional<uint32_t> rva_to_offset(uint32_t rva) const noexcept;

    /// Get pointer at RVA
    /// @param rva Relative virtual address
    /// @return Pointer to data or nullptr if invalid
    [[nodiscard]] const uint8_t* rva_to_ptr(uint32_t rva) const noexcept;

    /// Get pointer at RVA with size check
    /// @param rva Relative virtual address
    /// @param size Size of data to access
    /// @return Pointer to data or nullptr if invalid
    [[nodiscard]] const uint8_t* rva_to_ptr(uint32_t rva, size_t size) const noexcept;

    /// Explicit bool conversion
    explicit operator bool() const noexcept { return is_valid(); }

private:
    friend class PEParser;

    PEFile(utils::FileMapping&& mapping, PEFormat format);

    utils::FileMapping mapping_;
    PEFormat format_ = PEFormat::PE32;

    // Cached header pointers
    const IMAGE_DOS_HEADER* dos_header_ = nullptr;
    union {
        const IMAGE_NT_HEADERS32* nt_headers32_;
        const IMAGE_NT_HEADERS64* nt_headers64_;
    };

    // Private helper methods to reduce code duplication
    [[nodiscard]] const IMAGE_NT_HEADERS32* nt_headers32() const noexcept {
        return nt_headers32_;
    }
    [[nodiscard]] const IMAGE_NT_HEADERS64* nt_headers64() const noexcept {
        return nt_headers64_;
    }
    [[nodiscard]] const IMAGE_OPTIONAL_HEADER32* optional_header32() const noexcept {
        return &nt_headers32_->OptionalHeader;
    }
    [[nodiscard]] const IMAGE_OPTIONAL_HEADER64* optional_header64() const noexcept {
        return &nt_headers64_->OptionalHeader;
    }

    // Lazy-loaded tables (using unique_ptr for incomplete types)
    mutable std::unique_ptr<SectionTable> sections_;
    mutable std::unique_ptr<ImportTable> imports_;
    mutable std::unique_ptr<ExportTable> exports_;
    mutable std::unique_ptr<ResourceTable> resources_;
};

/// PE Parser - static factory for creating PEFile instances
class PEParser {
public:
    /// Parse a PE file from disk
    /// @param path Path to the PE file
    /// @return Result containing PEFile or Error
    [[nodiscard]] static Result<PEFile> parse(const std::filesystem::path& path);

    /// Parse a PE file from memory (for live process inspection)
    /// @param data Pointer to PE data
    /// @param size Size of data
    /// @return Result containing PEFile or Error
    [[nodiscard]] static Result<PEFile> parse_from_memory(const uint8_t* data, size_t size);

private:
    PEParser() = delete;

    /// Validate DOS header
    [[nodiscard]] static Result<void> validate_dos_header(const uint8_t* data, size_t size);

    /// Validate NT headers
    [[nodiscard]] static Result<void> validate_nt_headers(
        const uint8_t* data,
        size_t size,
        int32_t e_lfanew
    );

    /// Determine PE format from optional header magic
    [[nodiscard]] static PEFormat determine_format(const uint8_t* nt_headers);
};

} // namespace dlltools
