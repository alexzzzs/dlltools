#include "core/pe_parser.hpp"
#include "core/section.hpp"
#include "core/import.hpp"
#include "core/export.hpp"
#include "core/resource.hpp"
#include "core/security.hpp"
#include "core/rich.hpp"

namespace dlltools {

// =============================================================================
// PEFile Implementation
// =============================================================================

PEFile::PEFile(utils::FileMapping&& mapping, PEFormat format)
    : mapping_(std::move(mapping))
    , format_(format)
{
    // Set up header pointers
    dos_header_ = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapping_.data());
    
    if (format_ == PEFormat::PE32Plus) {
        nt_headers64_ = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            mapping_.data() + dos_header_->e_lfanew
        );
    } else {
        nt_headers32_ = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
            mapping_.data() + dos_header_->e_lfanew
        );
    }
}

PEFile::~PEFile() = default;

// =============================================================================
// File Header Access
// =============================================================================

const IMAGE_FILE_HEADER& PEFile::file_header() const noexcept {
    return (format_ == PEFormat::PE32Plus) 
        ? nt_headers64_->FileHeader 
        : nt_headers32_->FileHeader;
}

// =============================================================================
// Optional Header Access
// =============================================================================

uint16_t PEFile::optional_header_magic() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.Magic
        : nt_headers32_->OptionalHeader.Magic;
}

uint16_t PEFile::subsystem() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.Subsystem
        : nt_headers32_->OptionalHeader.Subsystem;
}

uint16_t PEFile::dll_characteristics() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.DllCharacteristics
        : nt_headers32_->OptionalHeader.DllCharacteristics;
}

uint64_t PEFile::image_base() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.ImageBase
        : nt_headers32_->OptionalHeader.ImageBase;
}

uint32_t PEFile::entry_point_rva() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.AddressOfEntryPoint
        : nt_headers32_->OptionalHeader.AddressOfEntryPoint;
}

uint32_t PEFile::section_alignment() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.SectionAlignment
        : nt_headers32_->OptionalHeader.SectionAlignment;
}

uint32_t PEFile::file_alignment() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.FileAlignment
        : nt_headers32_->OptionalHeader.FileAlignment;
}

uint32_t PEFile::size_of_image() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.SizeOfImage
        : nt_headers32_->OptionalHeader.SizeOfImage;
}

uint32_t PEFile::size_of_headers() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.SizeOfHeaders
        : nt_headers32_->OptionalHeader.SizeOfHeaders;
}

uint32_t PEFile::size_of_code() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.SizeOfCode
        : nt_headers32_->OptionalHeader.SizeOfCode;
}

uint32_t PEFile::size_of_initialized_data() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.SizeOfInitializedData
        : nt_headers32_->OptionalHeader.SizeOfInitializedData;
}

uint32_t PEFile::size_of_uninitialized_data() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.SizeOfUninitializedData
        : nt_headers32_->OptionalHeader.SizeOfUninitializedData;
}

// =============================================================================
// Data Directory Access
// =============================================================================

uint32_t PEFile::data_directory_count() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? nt_headers64_->OptionalHeader.NumberOfRvaAndSizes
        : nt_headers32_->OptionalHeader.NumberOfRvaAndSizes;
}

const IMAGE_DATA_DIRECTORY* PEFile::data_directory(uint32_t index) const noexcept {
    const uint32_t count = data_directory_count();
    if (index >= count) {
        return nullptr;
    }
    
    return (format_ == PEFormat::PE32Plus)
        ? &nt_headers64_->OptionalHeader.DataDirectory[index]
        : &nt_headers32_->OptionalHeader.DataDirectory[index];
}

bool PEFile::has_data_directory(uint32_t index) const noexcept {
    const auto* dir = data_directory(index);
    return dir != nullptr && dir->VirtualAddress != 0 && dir->Size != 0;
}

// =============================================================================
// Section Table Access
// =============================================================================

const SectionTable& PEFile::sections() const {
    if (!sections_) {
        sections_ = std::make_unique<SectionTable>(*this);
    }
    return *sections_;
}

const IMAGE_SECTION_HEADER* PEFile::section_headers() const noexcept {
    return (format_ == PEFormat::PE32Plus)
        ? IMAGE_FIRST_SECTION(nt_headers64_)
        : IMAGE_FIRST_SECTION(nt_headers32_);
}

// =============================================================================
// Import/Export Table Access
// =============================================================================

Result<std::reference_wrapper<const ImportTable>> PEFile::imports() const {
    if (!imports_) {
        auto result = ImportTable::parse(*this);
        if (!result) {
            return std::unexpected(std::move(result).error());
        }
        imports_ = std::make_unique<ImportTable>(std::move(*result));
    }
    return std::cref(*imports_);
}

Result<std::reference_wrapper<const ExportTable>> PEFile::exports() const {
    if (!exports_) {
        auto result = ExportTable::parse(*this);
        if (!result) {
            return std::unexpected(std::move(result).error());
        }
        exports_ = std::make_unique<ExportTable>(std::move(*result));
    }
    return std::cref(*exports_);
}

Result<std::reference_wrapper<const ResourceTable>> PEFile::resources() const {
    if (!resources_) {
        auto result = ResourceTable::parse(*this);
        if (!result) {
            return std::unexpected(std::move(result).error());
        }
        resources_ = std::make_unique<ResourceTable>(std::move(*result));
    }
    return std::cref(*resources_);
}

Result<std::reference_wrapper<const RichHeader>> PEFile::rich_header() const {
    if (!rich_header_) {
        auto result = RichHeader::parse(*this);
        if (!result) {
            return std::unexpected(std::move(result).error());
        }
        rich_header_ = std::make_unique<RichHeader>(std::move(*result));
    }
    return std::cref(*rich_header_);
}

// =============================================================================
// Security Analysis
// =============================================================================

SecurityFeatures PEFile::security_features() const {
    return analyze_security(*this);
}

// =============================================================================
// RVA Conversion
// =============================================================================

std::optional<uint32_t> PEFile::rva_to_offset(uint32_t rva) const noexcept {
    // Get section table
    const auto* sections = section_headers();
    const auto count = section_count();
    
    for (uint16_t i = 0; i < count; ++i) {
        const auto& section = sections[i];
        
        // Check if RVA falls within the section's virtual memory region
        const uint32_t virtual_size = std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + virtual_size) {
            // RVA is within the section - calculate offset
            uint32_t offset = rva - section.VirtualAddress;
            
            // Ensure we don't go beyond the raw data
            if (offset < section.SizeOfRawData) {
                return section.PointerToRawData + offset;
            }
        }
    }
    
    return std::nullopt;
}

const uint8_t* PEFile::rva_to_ptr(uint32_t rva) const noexcept {
    auto offset = rva_to_offset(rva);
    if (!offset) {
        return nullptr;
    }
    return mapping_.data() + *offset;
}

const uint8_t* PEFile::rva_to_ptr(uint32_t rva, size_t size) const noexcept {
    auto offset = rva_to_offset(rva);
    if (!offset) {
        return nullptr;
    }
    return mapping_.ptr_at(*offset, size);
}

// =============================================================================
// PEParser Implementation
// =============================================================================

Result<PEFile> PEParser::parse(const std::filesystem::path& path) {
    // Map the file
    auto mapping_result = utils::FileMapping::map(path);
    if (!mapping_result) {
        return std::unexpected(std::move(mapping_result).error());
    }
    auto mapping = std::move(*mapping_result);

    // Validate headers
    auto dos_result = validate_dos_header(mapping.data(), mapping.size());
    if (!dos_result) {
        return std::unexpected(std::move(dos_result).error());
    }
    
    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapping.data());
    auto nt_result = validate_nt_headers(mapping.data(), mapping.size(), dos_header->e_lfanew);
    if (!nt_result) {
        return std::unexpected(std::move(nt_result).error());
    }

    // Determine format and create PEFile
    PEFormat format = determine_format(mapping.data() + dos_header->e_lfanew);
    
    return PEFile(std::move(mapping), format);
}

Result<PEFile> PEParser::parse_from_memory(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return std::unexpected(Error::invalid_argument("data", "null or empty buffer"));
    }

    // Validate headers
    auto dos_result = validate_dos_header(data, size);
    if (!dos_result) {
        return std::unexpected(std::move(dos_result).error());
    }
    
    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    auto nt_result = validate_nt_headers(data, size, dos_header->e_lfanew);
    if (!nt_result) {
        return std::unexpected(std::move(nt_result).error());
    }

    // Create a copy of the data for the PEFile
    // Note: For live process inspection, we might want a different approach
    auto mapping = utils::FileMapping(); // Empty mapping for now
    
    // TODO: Implement memory-based PEFile construction
    // This requires a different approach than file mapping
    
    return std::unexpected(Error::invalid_argument(
        "parse_from_memory",
        "not yet implemented - use parse() for file-based PE files"
    ));
}

Result<void> PEParser::validate_dos_header(const uint8_t* data, size_t size) {
    // Check minimum size for DOS header
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        return std::unexpected(Error::file_too_small(size, sizeof(IMAGE_DOS_HEADER)));
    }

    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);

    // Validate DOS signature (MZ)
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::unexpected(Error::invalid_dos_signature());
    }

    // Check that e_lfanew is within bounds
    if (dos_header->e_lfanew < 0 ||
        static_cast<size_t>(dos_header->e_lfanew) >= size) {
        return std::unexpected(Error::invalid_pe_signature());
    }

    return {};
}

Result<void> PEParser::validate_nt_headers(const uint8_t* data, size_t size, int32_t e_lfanew) {
    // Check minimum size for PE signature
    const size_t pe_sig_offset = static_cast<size_t>(e_lfanew);
    if (pe_sig_offset + 4 > size) {
        return std::unexpected(Error::file_too_small(size, pe_sig_offset + 4));
    }

    // Validate PE signature
    const uint32_t* pe_sig = reinterpret_cast<const uint32_t*>(data + pe_sig_offset);
    if (*pe_sig != IMAGE_NT_SIGNATURE) {
        return std::unexpected(Error::invalid_pe_signature());
    }

    // Check minimum size for FILE_HEADER
    const size_t file_header_offset = pe_sig_offset + 4;
    if (file_header_offset + sizeof(IMAGE_FILE_HEADER) > size) {
        return std::unexpected(Error::file_too_small(size, file_header_offset + sizeof(IMAGE_FILE_HEADER)));
    }

    // Get file header to determine optional header size
    const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(data + file_header_offset);
    
    // Check minimum size for optional header
    const size_t optional_header_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    if (optional_header_offset + file_header->SizeOfOptionalHeader > size) {
        return std::unexpected(Error::file_too_small(size, optional_header_offset + file_header->SizeOfOptionalHeader));
    }

    // Validate optional header magic
    const uint16_t* magic = reinterpret_cast<const uint16_t*>(data + optional_header_offset);
    if (*magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && *magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return std::unexpected(Error(
            ErrorCategory::PEValidation,
            "Invalid optional header magic"
        ));
    }

    // Validate section table bounds
    const size_t section_table_offset = optional_header_offset + file_header->SizeOfOptionalHeader;
    const size_t section_table_size = static_cast<size_t>(file_header->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    
    if (section_table_offset + section_table_size > size) {
        return std::unexpected(Error::file_too_small(size, section_table_offset + section_table_size));
    }

    return {};
}

PEFormat PEParser::determine_format(const uint8_t* nt_headers) {
    // Skip PE signature (4 bytes) + FILE_HEADER (20 bytes) to get to optional header magic
    const uint16_t* magic = reinterpret_cast<const uint16_t*>(
        nt_headers + 4 + sizeof(IMAGE_FILE_HEADER)
    );
    
    if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return PEFormat::PE32Plus;
    }
    return PEFormat::PE32;
}

} // namespace dlltools
