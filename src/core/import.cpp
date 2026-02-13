#include "core/import.hpp"
#include "core/pe_parser.hpp"
#include "utils/string_utils.hpp"
#include <algorithm>

namespace dlltools {

// =============================================================================
// ImportTable Implementation
// =============================================================================

Result<ImportTable> ImportTable::parse(const PEFile& pe) {
    // Check if import directory exists
    if (!pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)) {
        return ImportTable{};  // No imports
    }
    
    auto imports_result = parse_imports(pe);
    if (!imports_result) {
        return std::unexpected(std::move(imports_result).error());
    }
    auto imports = std::move(*imports_result);
    
    // Parse delay-load imports
    if (pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)) {
        auto delay_result = parse_delay_loads(pe, imports);
        if (!delay_result) {
            return std::unexpected(std::move(delay_result).error());
        }
    }
    
    return ImportTable(std::move(imports));
}

size_t ImportTable::function_count() const noexcept {
    size_t count = 0;
    for (const auto& dll : imports_) {
        count += dll.functions.size();
    }
    return count;
}

const ImportedDll& ImportTable::operator[](size_t index) const {
    if (index >= imports_.size()) {
        throw std::out_of_range("ImportTable::operator[] - index out of range");
    }
    return imports_[index];
}

const ImportedDll* ImportTable::at(size_t index) const noexcept {
    if (index >= imports_.size()) {
        return nullptr;
    }
    return &imports_[index];
}

const ImportedDll* ImportTable::find_dll(std::string_view name) const noexcept {
    // Case-insensitive search
    auto it = std::find_if(imports_.begin(), imports_.end(), 
        [name](const ImportedDll& dll) {
            return utils::string_equals_case_insensitive(dll.name, name);
        });
    
    return it != imports_.end() ? &(*it) : nullptr;
}

std::vector<std::pair<size_t, size_t>> 
ImportTable::find_function(std::string_view name) const {
    std::vector<std::pair<size_t, size_t>> results;
    
    for (size_t dll_idx = 0; dll_idx < imports_.size(); ++dll_idx) {
        const auto& dll = imports_[dll_idx];
        for (size_t func_idx = 0; func_idx < dll.functions.size(); ++func_idx) {
            if (dll.functions[func_idx].name == name) {
                results.emplace_back(dll_idx, func_idx);
            }
        }
    }
    
    return results;
}

Result<std::vector<ImportedDll>> ImportTable::parse_imports(const PEFile& pe) {
    const auto* dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!dir || dir->VirtualAddress == 0) {
        return std::vector<ImportedDll>{};
    }
    
    // Get import directory
    const uint8_t* import_data = pe.rva_to_ptr(dir->VirtualAddress);
    if (!import_data) {
        return std::unexpected(Error::invalid_rva(dir->VirtualAddress));
    }
    
    std::vector<ImportedDll> imports;
    bool is_pe32_plus = pe.is_pe32_plus();
    
    // Iterate through import descriptors
    const IMAGE_IMPORT_DESCRIPTOR* descriptor = 
        reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(import_data);
    
    while (descriptor->Name != 0) {
        ImportedDll dll;
        dll.original_first_thunk_rva = descriptor->OriginalFirstThunk;
        dll.first_thunk_rva = descriptor->FirstThunk;
        
        // Get DLL name
        const char* name_ptr = reinterpret_cast<const char*>(
            pe.rva_to_ptr(descriptor->Name)
        );
        if (name_ptr) {
            dll.name = utils::extract_string(name_ptr, 260).data();
        }
        
        // Parse thunks
        uint32_t thunk_rva = descriptor->OriginalFirstThunk != 0 
            ? descriptor->OriginalFirstThunk 
            : descriptor->FirstThunk;
        
        auto functions_result = parse_thunks(pe, thunk_rva, is_pe32_plus);
        if (!functions_result) {
            return std::unexpected(std::move(functions_result).error());
        }
        dll.functions = std::move(*functions_result);
        
        imports.push_back(std::move(dll));
        ++descriptor;
    }
    
    return imports;
}

Result<void> ImportTable::parse_delay_loads(
    const PEFile& pe, 
    std::vector<ImportedDll>& imports
) {
    const auto* dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (!dir || dir->VirtualAddress == 0) {
        return {};
    }
    
    const uint8_t* delay_data = pe.rva_to_ptr(dir->VirtualAddress);
    if (!delay_data) {
        return {};
    }
    
    bool is_pe32_plus = pe.is_pe32_plus();
    
    // Iterate through delay-load descriptors
    const ImgDelayDescr* descriptor = 
        reinterpret_cast<const ImgDelayDescr*>(delay_data);
    
    while (descriptor->rvaDLLName != 0) {
        ImportedDll dll;
        dll.is_delay_load = true;
        
        // Get DLL name
        const char* name_ptr = reinterpret_cast<const char*>(
            pe.rva_to_ptr(descriptor->rvaDLLName)
        );
        if (name_ptr) {
            dll.name = utils::extract_string(name_ptr, 260).data();
        }
        
        // Parse thunks
        auto functions_result = parse_thunks(
            pe, 
            descriptor->rvaINT, 
            is_pe32_plus
        );
        if (!functions_result) {
            return std::unexpected(std::move(functions_result).error());
        }
        dll.functions = std::move(*functions_result);
        
        imports.push_back(std::move(dll));
        ++descriptor;
    }
    
    return {};
}

Result<std::vector<ImportedFunction>> ImportTable::parse_thunks(
    const PEFile& pe,
    uint32_t thunk_rva,
    bool is_pe32_plus
) {
    std::vector<ImportedFunction> functions;
    
    if (thunk_rva == 0) {
        return functions;
    }
    
    const uint8_t* thunk_data = pe.rva_to_ptr(thunk_rva);
    if (!thunk_data) {
        return functions;
    }
    
    if (is_pe32_plus) {
        // PE32+ uses 64-bit thunks
        const uint64_t* thunks = reinterpret_cast<const uint64_t*>(thunk_data);
        
        while (*thunks != 0) {
            ImportedFunction func;
            func.thunk_rva = thunk_rva + 
                static_cast<uint32_t>((thunks - reinterpret_cast<const uint64_t*>(thunk_data)) * sizeof(uint64_t));
            
            if (*thunks & IMAGE_ORDINAL_FLAG64) {
                // Import by ordinal
                func.is_by_ordinal = true;
                func.ordinal = static_cast<uint16_t>(*thunks & 0xFFFF);
            } else {
                // Import by name
                uint32_t hint_name_rva = static_cast<uint32_t>(*thunks);
                auto name_result = read_import_name(pe, hint_name_rva);
                if (name_result) {
                    func.name = name_result->first;
                    func.hint = name_result->second;
                }
            }
            
            functions.push_back(std::move(func));
            ++thunks;
        }
    } else {
        // PE32 uses 32-bit thunks
        const uint32_t* thunks = reinterpret_cast<const uint32_t*>(thunk_data);
        
        while (*thunks != 0) {
            ImportedFunction func;
            func.thunk_rva = thunk_rva + 
                static_cast<uint32_t>((thunks - reinterpret_cast<const uint32_t*>(thunk_data)) * sizeof(uint32_t));
            
            if (*thunks & IMAGE_ORDINAL_FLAG32) {
                // Import by ordinal
                func.is_by_ordinal = true;
                func.ordinal = static_cast<uint16_t>(*thunks & 0xFFFF);
            } else {
                // Import by name
                uint32_t hint_name_rva = *thunks;
                auto name_result = read_import_name(pe, hint_name_rva);
                if (name_result) {
                    func.name = name_result->first;
                    func.hint = name_result->second;
                }
            }
            
            functions.push_back(std::move(func));
            ++thunks;
        }
    }
    
    return functions;
}

std::optional<std::pair<std::string, uint16_t>> 
ImportTable::read_import_name(const PEFile& pe, uint32_t rva) {
    const uint8_t* data = pe.rva_to_ptr(rva, 2);  // At minimum, need hint (2 bytes)
    if (!data) {
        return std::nullopt;
    }
    
    // Read hint (2 bytes)
    uint16_t hint = static_cast<uint16_t>(data[0]) | 
                    (static_cast<uint16_t>(data[1]) << 8);
    
    // Read name (null-terminated string after hint)
    const char* name_start = reinterpret_cast<const char*>(data + 2);
    std::string name = utils::extract_string(name_start, 256).data();
    
    return std::make_pair(std::move(name), hint);
}

} // namespace dlltools
