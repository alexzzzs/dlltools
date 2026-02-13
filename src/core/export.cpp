#include "core/export.hpp"
#include "core/pe_parser.hpp"
#include "utils/string_utils.hpp"
#include <stdexcept>

namespace dlltools {

ExportTable::ExportTable(
    std::vector<ExportedFunction>&& exports,
    std::string dll_name,
    uint32_t ordinal_base
) : exports_(std::move(exports))
  , dll_name_(std::move(dll_name))
  , ordinal_base_(ordinal_base)
{
    // Build index maps
    for (size_t i = 0; i < exports_.size(); ++i) {
        if (!exports_[i].name.empty()) {
            name_index_[exports_[i].name] = i;
        }
        ordinal_index_[exports_[i].ordinal] = i;
    }
}

Result<ExportTable> ExportTable::parse(const PEFile& pe) {
    // Check if export directory exists
    if (!pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)) {
        return ExportTable{};  // No exports
    }
    
    const auto* dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!dir || dir->VirtualAddress == 0) {
        return ExportTable{};
    }
    
    // Get export directory
    const uint8_t* export_data = pe.rva_to_ptr(dir->VirtualAddress);
    if (!export_data) {
        return std::unexpected(Error::invalid_rva(dir->VirtualAddress));
    }
    
    const IMAGE_EXPORT_DIRECTORY* export_dir = 
        reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(export_data);
    
    // Get DLL name
    std::string dll_name;
    if (export_dir->Name != 0) {
        const char* name_ptr = reinterpret_cast<const char*>(
            pe.rva_to_ptr(export_dir->Name)
        );
        if (name_ptr) {
            dll_name = utils::extract_string(name_ptr, 260).data();
        }
    }
    
    uint32_t ordinal_base = export_dir->Base;
    uint32_t num_functions = export_dir->NumberOfFunctions;
    uint32_t num_names = export_dir->NumberOfNames;
    
    // Get tables
    const uint32_t* address_table = nullptr;
    const uint32_t* name_table = nullptr;
    const uint16_t* ordinal_table = nullptr;
    
    if (export_dir->AddressOfFunctions != 0) {
        address_table = reinterpret_cast<const uint32_t*>(
            pe.rva_to_ptr(export_dir->AddressOfFunctions)
        );
    }
    
    if (export_dir->AddressOfNames != 0) {
        name_table = reinterpret_cast<const uint32_t*>(
            pe.rva_to_ptr(export_dir->AddressOfNames)
        );
    }
    
    if (export_dir->AddressOfNameOrdinals != 0) {
        ordinal_table = reinterpret_cast<const uint16_t*>(
            pe.rva_to_ptr(export_dir->AddressOfNameOrdinals)
        );
    }
    
    if (!address_table) {
        return ExportTable{};
    }
    
    // Create exports vector with all functions
    std::vector<ExportedFunction> exports;
    exports.reserve(num_functions);
    
    // First, create entries for all functions by ordinal
    for (uint32_t i = 0; i < num_functions; ++i) {
        ExportedFunction func;
        func.ordinal = static_cast<uint16_t>(ordinal_base + i);
        func.rva = address_table[i];
        
        // Check if forwarded (RVA points into export section)
        if (func.rva >= dir->VirtualAddress && 
            func.rva < dir->VirtualAddress + dir->Size) {
            func.is_forwarded = true;
            const char* forward_ptr = reinterpret_cast<const char*>(
                pe.rva_to_ptr(func.rva)
            );
            if (forward_ptr) {
                func.forward_target = utils::extract_string(forward_ptr, 260).data();
            }
        }
        
        exports.push_back(std::move(func));
    }
    
    // Now add names to the functions
    if (name_table && ordinal_table) {
        for (uint32_t i = 0; i < num_names; ++i) {
            uint32_t name_rva = name_table[i];
            uint16_t ordinal_index = ordinal_table[i];
            
            if (ordinal_index < num_functions) {
                const char* name_ptr = reinterpret_cast<const char*>(
                    pe.rva_to_ptr(name_rva)
                );
                if (name_ptr) {
                    exports[ordinal_index].name = 
                        utils::extract_string(name_ptr, 256).data();
                }
            }
        }
    }
    
    return ExportTable(std::move(exports), std::move(dll_name), ordinal_base);
}

const ExportedFunction& ExportTable::operator[](size_t index) const {
    if (index >= exports_.size()) {
        throw std::out_of_range("ExportTable::operator[] - index out of range");
    }
    return exports_[index];
}

const ExportedFunction* ExportTable::at(size_t index) const noexcept {
    if (index >= exports_.size()) {
        return nullptr;
    }
    return &exports_[index];
}

const ExportedFunction* ExportTable::find_by_name(std::string_view name) const noexcept {
    auto it = name_index_.find(std::string(name));
    if (it != name_index_.end()) {
        return &exports_[it->second];
    }
    return nullptr;
}

std::optional<size_t> ExportTable::find_index_by_name(std::string_view name) const noexcept {
    auto it = name_index_.find(std::string(name));
    if (it != name_index_.end()) {
        return it->second;
    }
    return std::nullopt;
}

const ExportedFunction* ExportTable::find_by_ordinal(uint16_t ordinal) const noexcept {
    auto it = ordinal_index_.find(ordinal);
    if (it != ordinal_index_.end()) {
        return &exports_[it->second];
    }
    return nullptr;
}

std::optional<size_t> ExportTable::find_index_by_ordinal(uint16_t ordinal) const noexcept {
    auto it = ordinal_index_.find(ordinal);
    if (it != ordinal_index_.end()) {
        return it->second;
    }
    return std::nullopt;
}

} // namespace dlltools
