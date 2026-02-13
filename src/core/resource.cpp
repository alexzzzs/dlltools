#include "core/resource.hpp"
#include "core/pe_parser.hpp"
#include "utils/string_utils.hpp"
#include <algorithm>

namespace dlltools {

// =============================================================================
// ResourceTable Implementation
// =============================================================================

ResourceTable::ResourceTable(
    std::vector<ResourceType>&& types,
    uint32_t directory_rva,
    uint32_t directory_size
) : types_(std::move(types)),
    directory_rva_(directory_rva),
    directory_size_(directory_size) {}

Result<ResourceTable> ResourceTable::parse(const PEFile& pe) {
    // Check if resource directory exists
    if (!pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)) {
        return ResourceTable{};  // No resources
    }
    
    const auto* dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if (!dir || dir->VirtualAddress == 0) {
        return ResourceTable{};
    }
    
    auto types_result = parse_directory(pe, dir->VirtualAddress, dir->Size);
    if (!types_result) {
        return std::unexpected(std::move(types_result).error());
    }
    
    return ResourceTable(std::move(*types_result), dir->VirtualAddress, dir->Size);
}

size_t ResourceTable::entry_count() const noexcept {
    size_t count = 0;
    for (const auto& type : types_) {
        count += type.entries.size();
    }
    return count;
}

const ResourceType& ResourceTable::operator[](size_t index) const {
    if (index >= types_.size()) {
        throw std::out_of_range("ResourceTable::operator[] - index out of range");
    }
    return types_[index];
}

const ResourceType* ResourceTable::at(size_t index) const noexcept {
    if (index >= types_.size()) {
        return nullptr;
    }
    return &types_[index];
}

const ResourceType* ResourceTable::find_by_type(uint32_t type_id) const noexcept {
    auto it = std::find_if(types_.begin(), types_.end(),
        [type_id](const ResourceType& type) {
            return !type.is_named && type.type_id == type_id;
        });
    
    return it != types_.end() ? &(*it) : nullptr;
}

const ResourceType* ResourceTable::find_by_type_name(std::string_view name) const noexcept {
    auto it = std::find_if(types_.begin(), types_.end(),
        [name](const ResourceType& type) {
            return type.is_named && utils::string_equals_case_insensitive(type.type_name, name);
        });
    
    return it != types_.end() ? &(*it) : nullptr;
}

std::vector<ResourceEntry> ResourceTable::get_entries_by_type(uint32_t type_id) const {
    std::vector<ResourceEntry> result;
    
    const auto* type = find_by_type(type_id);
    if (type) {
        result = type->entries;
    }
    
    return result;
}

std::string ResourceTable::type_id_to_string(uint32_t type_id) {
    switch (type_id) {
        case 1:  return "CURSOR";
        case 2:  return "BITMAP";
        case 3:  return "ICON";
        case 4:  return "MENU";
        case 5:  return "DIALOG";
        case 6:  return "STRING";
        case 7:  return "FONTDIR";
        case 8:  return "FONT";
        case 9:  return "ACCELERATOR";
        case 10: return "RCDATA";
        case 11: return "MESSAGETABLE";
        case 12: return "GROUP_CURSOR";
        case 14: return "GROUP_ICON";
        case 16: return "VERSION";
        case 17: return "DLGINCLUDE";
        case 19: return "PLUGPLAY";
        case 20: return "VXD";
        case 21: return "ANICURSOR";
        case 22: return "ANIICON";
        case 23: return "HTML";
        case 24: return "MANIFEST";
        default: return "Unknown";
    }
}

Result<std::vector<ResourceType>> ResourceTable::parse_directory(
    const PEFile& pe,
    uint32_t rva,
    uint32_t size
) {
    const uint8_t* base_ptr = pe.rva_to_ptr(rva);
    if (!base_ptr) {
        return std::unexpected(Error::invalid_rva(rva));
    }
    
    // Bounds check for minimum directory size
    if (size < sizeof(IMAGE_RESOURCE_DIRECTORY)) {
        return std::unexpected(Error(
            ErrorCategory::BoundsCheck,
            std::format("Resource directory too small at RVA {:#x}: {} bytes, minimum required is {} bytes", 
                rva, size, sizeof(IMAGE_RESOURCE_DIRECTORY))
        ));
    }
    
    std::vector<ResourceType> types;
    
    // Parse the root directory (type level)
    const auto* root_dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(base_ptr);
    
    // Calculate number of entries
    size_t num_entries = root_dir->NumberOfNamedEntries + root_dir->NumberOfIdEntries;
    
    // Bounds check for entries
    size_t entries_size = num_entries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    if (entries_size > size - sizeof(IMAGE_RESOURCE_DIRECTORY)) {
        return std::unexpected(Error(
            ErrorCategory::BoundsCheck,
            std::format("Resource directory entries overflow at RVA {:#x}: {} entries exceed available space", 
                rva, num_entries)
        ));
    }
    
    const auto* entries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
        base_ptr + sizeof(IMAGE_RESOURCE_DIRECTORY)
    );
    
    for (size_t i = 0; i < num_entries; ++i) {
        const auto& entry = entries[i];
        ResourceType type_info;
        
        // Check if type is named or numeric
        if (entry.Name & 0x80000000) {
            // Named type - high bit is set
            type_info.is_named = true;
            uint32_t name_rva = entry.Name & 0x7FFFFFFF;
            auto name_opt = read_unicode_string(pe, rva + name_rva);
            if (name_opt) {
                type_info.type_name = *name_opt;
            }
        } else {
            // Numeric type ID
            type_info.is_named = false;
            type_info.type_id = entry.Name;
        }
        
        // Parse name/language levels
        uint32_t entry_offset = entry.OffsetToData & 0x7FFFFFFF;
        bool is_directory = (entry.OffsetToData & 0x80000000) != 0;
        
        if (is_directory) {
            // Parse name level
            const uint8_t* name_dir_ptr = base_ptr + entry_offset;
            const auto* name_dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(name_dir_ptr);
            
            size_t name_entries = name_dir->NumberOfNamedEntries + name_dir->NumberOfIdEntries;
            const auto* name_entries_ptr = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
                name_dir_ptr + sizeof(IMAGE_RESOURCE_DIRECTORY)
            );
            
            for (size_t j = 0; j < name_entries; ++j) {
                const auto& name_entry = name_entries_ptr[j];
                ResourceEntry res_entry;
                res_entry.type_id = type_info.type_id;
                res_entry.type_name = type_info.type_name;
                res_entry.is_typed_named = type_info.is_named;
                
                // Parse name/ID
                if (name_entry.Name & 0x80000000) {
                    res_entry.is_named = true;
                    uint32_t name_rva = name_entry.Name & 0x7FFFFFFF;
                    auto name_opt = read_unicode_string(pe, rva + name_rva);
                    if (name_opt) {
                        res_entry.name = *name_opt;
                    }
                } else {
                    res_entry.is_named = false;
                    res_entry.id = name_entry.Name;
                }
                
                // Parse language level
                uint32_t lang_offset = name_entry.OffsetToData & 0x7FFFFFFF;
                bool lang_is_dir = (name_entry.OffsetToData & 0x80000000) != 0;
                
                if (lang_is_dir) {
                    const uint8_t* lang_dir_ptr = base_ptr + lang_offset;
                    const auto* lang_dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(lang_dir_ptr);
                    
                    size_t lang_entries = lang_dir->NumberOfNamedEntries + lang_dir->NumberOfIdEntries;
                    const auto* lang_entries_ptr = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
                        lang_dir_ptr + sizeof(IMAGE_RESOURCE_DIRECTORY)
                    );
                    
                    for (size_t k = 0; k < lang_entries; ++k) {
                        const auto& lang_entry = lang_entries_ptr[k];
                        
                        // This should be a data entry, not a directory
                        if (!(lang_entry.OffsetToData & 0x80000000)) {
                            ResourceEntry lang_res = res_entry;
                            lang_res.language_id = static_cast<uint16_t>(lang_entry.Name & 0xFFFF);
                            lang_res.sublanguage_id = static_cast<uint16_t>((lang_entry.Name >> 10) & 0x3F);
                            
                            // Get data entry
                            const uint8_t* data_entry_ptr = base_ptr + lang_entry.OffsetToData;
                            const auto* data_entry = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(data_entry_ptr);
                            
                            lang_res.rva = data_entry->OffsetToData;
                            lang_res.size = data_entry->Size;
                            lang_res.code_page = data_entry->CodePage;
                            
                            // Convert RVA to file offset
                            auto offset_opt = pe.rva_to_offset(lang_res.rva);
                            if (offset_opt) {
                                lang_res.offset = *offset_opt;
                            }
                            
                            type_info.entries.push_back(lang_res);
                        }
                    }
                } else {
                    // Direct data entry
                    const uint8_t* data_entry_ptr = base_ptr + lang_offset;
                    const auto* data_entry = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(data_entry_ptr);
                    
                    res_entry.rva = data_entry->OffsetToData;
                    res_entry.size = data_entry->Size;
                    res_entry.code_page = data_entry->CodePage;
                    
                    auto offset_opt = pe.rva_to_offset(res_entry.rva);
                    if (offset_opt) {
                        res_entry.offset = *offset_opt;
                    }
                    
                    type_info.entries.push_back(res_entry);
                }
            }
        }
        
        types.push_back(std::move(type_info));
    }
    
    return types;
}

std::optional<std::string> ResourceTable::read_unicode_string(
    const PEFile& pe,
    uint32_t rva
) {
    const uint8_t* ptr = pe.rva_to_ptr(rva);
    if (!ptr) {
        return std::nullopt;
    }
    
    // First WORD is the length in characters
    uint16_t length = *reinterpret_cast<const uint16_t*>(ptr);
    if (length == 0) {
        return std::string{};
    }
    
    // Bounds check
    if (length > 256) {
        length = 256;  // Limit string length
    }
    
    // Read Unicode characters
    const wchar_t* chars = reinterpret_cast<const wchar_t*>(ptr + sizeof(uint16_t));
    
    // Convert to UTF-8
    std::string result;
    result.reserve(length);
    
    for (uint16_t i = 0; i < length; ++i) {
        wchar_t wc = chars[i];
        if (wc < 0x80) {
            result.push_back(static_cast<char>(wc));
        } else if (wc < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (wc >> 6)));
            result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (wc >> 12)));
            result.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        }
    }
    
    return result;
}

} // namespace dlltools
