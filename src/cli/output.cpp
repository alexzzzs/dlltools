#include "cli/output.hpp"
#include "core/entropy.hpp"
#include "utils/string_utils.hpp"
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace dlltools::cli {

OutputFormatter::OutputFormatter(bool json, bool verbose, const std::string& filter, bool use_colour)
    : json_(json), verbose_(verbose), filter_(filter), use_colour_(use_colour)
{
}

bool OutputFormatter::matches_filter(std::string_view str) const noexcept {
    if (filter_.empty()) return true;
    return utils::string_contains_case_insensitive(str, filter_);
}

void OutputFormatter::print_kv(const char* key, const char* value, int indent) {
    if (json_) {
        std::cout << std::string(indent, ' ') << "\"" << key << "\": \"" << value << "\"";
    } else {
        std::cout << std::string(indent, ' ') << std::left << std::setw(20) << key << ": " << value << "\n";
    }
}

void OutputFormatter::print_kv(const char* key, const std::string& value, int indent) {
    print_kv(key, value.c_str(), indent);
}

void OutputFormatter::print_kv(const char* key, uint64_t value, int indent) {
    if (json_) {
        std::cout << std::string(indent, ' ') << "\"" << key << "\": " << value;
    } else {
        std::cout << std::string(indent, ' ') << std::left << std::setw(20) << key 
                  << ": " << value << " (0x" << std::hex << value << std::dec << ")\n";
    }
}

void OutputFormatter::print_kv(const char* key, uint32_t value, int indent, bool hex) {
    if (json_) {
        std::cout << std::string(indent, ' ') << "\"" << key << "\": " << value;
    } else {
        if (hex) {
            std::cout << std::string(indent, ' ') << std::left << std::setw(20) << key 
                      << ": 0x" << std::hex << std::setfill('0') << std::setw(8) << value 
                      << std::dec << std::setfill(' ') << "\n";
        } else {
            std::cout << std::string(indent, ' ') << std::left << std::setw(20) << key 
                      << ": " << value << "\n";
        }
    }
}

void OutputFormatter::print_kv(const char* key, uint16_t value, int indent, bool hex) {
    if (json_) {
        std::cout << std::string(indent, ' ') << "\"" << key << "\": " << value;
    } else {
        if (hex) {
            std::cout << std::string(indent, ' ') << std::left << std::setw(20) << key 
                      << ": 0x" << std::hex << std::setfill('0') << std::setw(4) << value 
                      << std::dec << std::setfill(' ') << "\n";
        } else {
            std::cout << std::string(indent, ' ') << std::left << std::setw(20) << key 
                      << ": " << value << "\n";
        }
    }
}

void OutputFormatter::print_section_header(const char* title) {
    if (!json_) {
        std::cout << "\n=== " << title << " ===\n";
    }
}

void OutputFormatter::print_json_string(std::ostream& os, std::string_view str) {
    os << "\"";
    for (char c : str) {
        switch (c) {
            case '"':  os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b"; break;
            case '\f': os << "\\f"; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    os << "\\u" << std::hex << std::setw(4) << std::setfill('0') 
                       << static_cast<int>(c) << std::dec;
                } else {
                    os << c;
                }
        }
    }
    os << "\"";
}

void OutputFormatter::print_inspect(const PEFile& pe) {
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"file\": {\n";
        std::cout << "    \"size\": " << pe.size() << ",\n";
        std::cout << "    \"format\": \"" << (pe.is_pe32_plus() ? "PE32+" : "PE32") << "\"\n";
        std::cout << "  },\n";
        
        std::cout << "  \"headers\": {\n";
        std::cout << "    \"machine\": \"" << utils::machine_type_name(pe.machine_type()) << "\",\n";
        std::cout << "    \"timestamp\": \"" << utils::format_timestamp(pe.timestamp()) << "\",\n";
        std::cout << "    \"imageBase\": " << pe.image_base() << ",\n";
        std::cout << "    \"entryPoint\": " << pe.entry_point_rva() << ",\n";
        std::cout << "    \"subsystem\": \"" << utils::subsystem_name(pe.subsystem()) << "\",\n";
        std::cout << "    \"sections\": " << pe.section_count() << "\n";
        std::cout << "  }\n";
        std::cout << "}\n";
    } else {
        std::cout << "PE File Overview\n";
        std::cout << "================\n\n";
        
        print_kv("Format", pe.is_pe32_plus() ? "PE32+ (64-bit)" : "PE32 (32-bit)");
        print_kv("File Size", utils::format_size(pe.size()));
        print_kv("Machine", utils::machine_type_name(pe.machine_type()));
        print_kv("Timestamp", utils::format_timestamp(pe.timestamp()));
        print_kv("Image Base", pe.image_base(), 0);
        print_kv("Entry Point", pe.entry_point_rva(), 0, true);
        print_kv("Subsystem", utils::subsystem_name(pe.subsystem()));
        print_kv("Sections", pe.section_count());
        
        if (verbose_) {
            print_section_header("Section Summary");
            const auto& sections = pe.sections();
            for (const auto& section : sections) {
                std::cout << "  " << std::left << std::setw(10) << section.name
                          << " VA: 0x" << std::hex << std::setfill('0') << std::setw(8) 
                          << section.virtual_address
                          << " Size: " << std::dec << utils::format_size(section.virtual_size)
                          << "\n";
            }
        }
    }
}

void OutputFormatter::print_headers(const PEFile& pe) {
    if (json_) {
        std::cout << "{\n";
        
        // DOS Header
        std::cout << "  \"dosHeader\": {\n";
        std::cout << "    \"e_magic\": \"MZ\",\n";
        std::cout << "    \"e_lfanew\": " << pe.e_lfanew() << "\n";
        std::cout << "  },\n";
        
        // File Header
        std::cout << "  \"fileHeader\": {\n";
        std::cout << "    \"machine\": " << pe.machine_type() << ",\n";
        std::cout << "    \"numberOfSections\": " << pe.section_count() << ",\n";
        std::cout << "    \"timeDateStamp\": " << pe.timestamp() << ",\n";
        std::cout << "    \"characteristics\": " << pe.characteristics() << "\n";
        std::cout << "  },\n";
        
        // Optional Header
        std::cout << "  \"optionalHeader\": {\n";
        std::cout << "    \"magic\": " << pe.optional_header_magic() << ",\n";
        std::cout << "    \"imageBase\": " << pe.image_base() << ",\n";
        std::cout << "    \"entryPoint\": " << pe.entry_point_rva() << ",\n";
        std::cout << "    \"subsystem\": " << pe.subsystem() << ",\n";
        std::cout << "    \"sectionAlignment\": " << pe.section_alignment() << ",\n";
        std::cout << "    \"fileAlignment\": " << pe.file_alignment() << ",\n";
        std::cout << "    \"sizeOfImage\": " << pe.size_of_image() << ",\n";
        std::cout << "    \"sizeOfHeaders\": " << pe.size_of_headers() << ",\n";
        std::cout << "    \"dllCharacteristics\": " << pe.dll_characteristics() << "\n";
        std::cout << "  }\n";
        
        std::cout << "}\n";
    } else {
        std::cout << "DOS Header\n";
        std::cout << "==========\n";
        print_kv("e_magic", "MZ (0x5A4D)");
        print_kv("e_lfanew", static_cast<uint32_t>(pe.e_lfanew()), 0, true);
        
        print_section_header("File Header");
        print_kv("Machine", utils::machine_type_name(pe.machine_type()));
        print_kv("NumberOfSections", pe.section_count());
        print_kv("TimeDateStamp", utils::format_timestamp(pe.timestamp()));
        print_kv("Characteristics", pe.characteristics(), 0, true);
        
        if (verbose_) {
            auto chars = pe.characteristics();
            if (chars & IMAGE_FILE_EXECUTABLE_IMAGE) std::cout << "    - EXECUTABLE_IMAGE\n";
            if (chars & IMAGE_FILE_DLL) std::cout << "    - DLL\n";
            if (chars & IMAGE_FILE_LARGE_ADDRESS_AWARE) std::cout << "    - LARGE_ADDRESS_AWARE\n";
            if (chars & IMAGE_FILE_RELOCS_STRIPPED) std::cout << "    - RELOCS_STRIPPED\n";
        }
        
        print_section_header("Optional Header");
        print_kv("Magic", pe.optional_header_magic() == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 
                 "PE32+ (0x20B)" : "PE32 (0x10B)");
        print_kv("ImageBase", pe.image_base(), 0);
        print_kv("AddressOfEntryPoint", pe.entry_point_rva(), 0, true);
        print_kv("Subsystem", utils::subsystem_name(pe.subsystem()));
        print_kv("SectionAlignment", pe.section_alignment(), 0, true);
        print_kv("FileAlignment", pe.file_alignment(), 0, true);
        print_kv("SizeOfImage", pe.size_of_image());
        print_kv("SizeOfHeaders", pe.size_of_headers());
        print_kv("DllCharacteristics", pe.dll_characteristics(), 0, true);
        
        if (verbose_) {
            auto flags = utils::dll_characteristics_flags(pe.dll_characteristics());
            for (const auto& flag : flags) {
                std::cout << "    - " << flag << "\n";
            }
        }
    }
}

void OutputFormatter::print_sections(const SectionTable& sections) {
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"sections\": [\n";
        
        bool first = true;
        for (const auto& section : sections) {
            if (!first) std::cout << ",\n";
            first = false;
            
            std::cout << "    {\n";
            std::cout << "      \"name\": \"" << section.name << "\",\n";
            std::cout << "      \"virtualAddress\": " << section.virtual_address << ",\n";
            std::cout << "      \"virtualSize\": " << section.virtual_size << ",\n";
            std::cout << "      \"rawSize\": " << section.raw_size << ",\n";
            std::cout << "      \"rawOffset\": " << section.raw_offset << ",\n";
            std::cout << "      \"characteristics\": " << section.characteristics << "\n";
            std::cout << "    }";
        }
        
        std::cout << "\n  ]\n";
        std::cout << "}\n";
    } else {
        std::cout << "Section Table (" << sections.count() << " sections)\n";
        std::cout << "==========================================\n\n";
        
        std::cout << std::left 
                  << std::setw(10) << "Name"
                  << std::setw(12) << "VirtAddr"
                  << std::setw(12) << "VirtSize"
                  << std::setw(12) << "RawSize"
                  << std::setw(12) << "RawOffset"
                  << "Flags\n";
        std::cout << std::string(70, '-') << "\n";
        
        for (const auto& section : sections) {
            std::cout << std::left << std::setw(10) << section.name
                      << "0x" << std::hex << std::setfill('0') << std::setw(8) 
                      << section.virtual_address << "  "
                      << std::setw(8) << section.virtual_size << "  "
                      << std::dec << std::setfill(' ')
                      << std::setw(10) << section.raw_size
                      << std::setw(10) << section.raw_offset;
            
            // Print flags
            if (section.is_executable()) std::cout << "E";
            if (section.is_readable()) std::cout << "R";
            if (section.is_writable()) std::cout << "W";
            if (section.is_code()) std::cout << " (code)";
            if (section.is_discardable()) std::cout << " (discard)";
            
            std::cout << "\n";
            
            if (verbose_) {
                auto flags = utils::section_characteristics_flags(section.characteristics);
                for (const auto& flag : flags) {
                    std::cout << "    - " << flag << "\n";
                }
            }
        }
    }
}

void OutputFormatter::print_imports(const ImportTable& imports) {
    // Count filtered results
    size_t filtered_dll_count = 0;
    size_t filtered_func_count = 0;
    
    if (has_filter()) {
        for (const auto& dll : imports) {
            bool dll_matches = matches_filter(dll.name);
            bool has_matching_func = false;
            
            for (const auto& func : dll.functions) {
                if (dll_matches || (!func.name.empty() && matches_filter(func.name))) {
                    has_matching_func = true;
                    filtered_func_count++;
                }
            }
            
            if (dll_matches || has_matching_func) {
                filtered_dll_count++;
            }
        }
    }
    
    if (json_) {
        std::cout << "{\n";
        if (has_filter()) {
            std::cout << "  \"filter\": \"" << filter_ << "\",\n";
            std::cout << "  \"filteredCount\": {\"dlls\": " << filtered_dll_count 
                      << ", \"functions\": " << filtered_func_count << "},\n";
        }
        std::cout << "  \"dlls\": [\n";
        
        bool first_dll = true;
        for (const auto& dll : imports) {
            bool dll_matches = matches_filter(dll.name);
            
            // Collect matching functions
            std::vector<std::reference_wrapper<const ImportedFunction>> matching_funcs;
            if (has_filter()) {
                for (const auto& func : dll.functions) {
                    if (dll_matches || (!func.name.empty() && matches_filter(func.name))) {
                        matching_funcs.push_back(std::cref(func));
                    }
                }
            }
            
            // Skip if filter active and no matches
            if (has_filter() && !dll_matches && matching_funcs.empty()) {
                continue;
            }
            
            if (!first_dll) std::cout << ",\n";
            first_dll = false;
            
            std::cout << "    {\n";
            std::cout << "      \"name\": \"" << dll.name << "\",\n";
            if (dll.is_delay_load) {
                std::cout << "      \"delayLoad\": true,\n";
            }
            std::cout << "      \"functions\": [\n";
            
            bool first_func = true;
            
            for (const auto& func : (has_filter() ? matching_funcs : 
                     std::vector<std::reference_wrapper<const ImportedFunction>>{})) {
                // This branch is for filtered output
                if (!first_func) std::cout << ",\n";
                first_func = false;
                
                std::cout << "        {";
                if (func.get().is_by_ordinal) {
                    std::cout << "\"ordinal\": " << func.get().ordinal;
                } else {
                    std::cout << "\"name\": \"" << func.get().name << "\"";
                }
                std::cout << "}";
            }
            
            // Non-filtered path
            if (!has_filter()) {
                for (const auto& func : dll.functions) {
                    if (!first_func) std::cout << ",\n";
                    first_func = false;
                    
                    std::cout << "        {";
                    if (func.is_by_ordinal) {
                        std::cout << "\"ordinal\": " << func.ordinal;
                    } else {
                        std::cout << "\"name\": \"" << func.name << "\"";
                    }
                    std::cout << "}";
                }
            }
            
            std::cout << "\n      ]\n";
            std::cout << "    }";
        }
        
        std::cout << "\n  ]\n";
        std::cout << "}\n";
    } else {
        if (has_filter()) {
            std::cout << "Import Table (filtered: " << filtered_dll_count << " DLLs, " 
                      << filtered_func_count << " functions match \"" << filter_ << "\")\n";
        } else {
            std::cout << "Import Table (" << imports.dll_count() << " DLLs, " 
                      << imports.function_count() << " functions)\n";
        }
        std::cout << "================================================\n\n";
        
        for (const auto& dll : imports) {
            bool dll_matches = matches_filter(dll.name);
            
            // Collect matching functions if filtering
            std::vector<std::reference_wrapper<const ImportedFunction>> matching_funcs;
            if (has_filter()) {
                for (const auto& func : dll.functions) {
                    if (dll_matches || (!func.name.empty() && matches_filter(func.name))) {
                        matching_funcs.push_back(std::cref(func));
                    }
                }
                
                if (!dll_matches && matching_funcs.empty()) {
                    continue;  // Skip this DLL entirely
                }
            }
            
            std::cout << dll.name;
            if (dll.is_delay_load) std::cout << " (delay-load)";
            std::cout << "\n";
            
            // Print functions
            if (has_filter()) {
                for (const auto& func : matching_funcs) {
                    if (func.get().is_by_ordinal) {
                        std::cout << "    Ordinal: " << func.get().ordinal << "\n";
                    } else {
                        std::cout << "    " << func.get().name;
                        if (verbose_) {
                            std::cout << " (hint: " << func.get().hint << ")";
                        }
                        std::cout << "\n";
                    }
                }
            } else {
                for (const auto& func : dll.functions) {
                    if (func.is_by_ordinal) {
                        std::cout << "    Ordinal: " << func.ordinal << "\n";
                    } else {
                        std::cout << "    " << func.name;
                        if (verbose_) {
                            std::cout << " (hint: " << func.hint << ")";
                        }
                        std::cout << "\n";
                    }
                }
            }
            std::cout << "\n";
        }
    }
}

void OutputFormatter::print_exports(const ExportTable& exports) {
    // Count filtered results
    size_t filtered_count = 0;
    if (has_filter()) {
        for (const auto& func : exports) {
            if (matches_filter(func.name) || matches_filter(func.forward_target)) {
                filtered_count++;
            }
        }
    }
    
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"dllName\": \"" << exports.dll_name() << "\",\n";
        std::cout << "  \"ordinalBase\": " << exports.ordinal_base() << ",\n";
        if (has_filter()) {
            std::cout << "  \"filter\": \"" << filter_ << "\",\n";
            std::cout << "  \"filteredCount\": " << filtered_count << ",\n";
        }
        std::cout << "  \"functions\": [\n";
        
        bool first = true;
        for (const auto& func : exports) {
            // Skip if filter active and no match
            if (has_filter()) {
                if (!matches_filter(func.name) && !matches_filter(func.forward_target)) {
                    continue;
                }
            }
            
            if (!first) std::cout << ",\n";
            first = false;
            
            std::cout << "    {\n";
            std::cout << "      \"ordinal\": " << func.ordinal << ",\n";
            if (!func.name.empty()) {
                std::cout << "      \"name\": \"" << func.name << "\",\n";
            }
            std::cout << "      \"rva\": " << func.rva;
            if (func.is_forwarded) {
                std::cout << ",\n      \"forwarded\": \"" << func.forward_target << "\"";
            }
            std::cout << "\n    }";
        }
        
        std::cout << "\n  ]\n";
        std::cout << "}\n";
    } else {
        if (has_filter()) {
            std::cout << "Export Table (filtered: " << filtered_count 
                      << " functions match \"" << filter_ << "\")\n";
        } else {
            std::cout << "Export Table (" << exports.count() << " functions)\n";
        }
        std::cout << "====================================\n";
        std::cout << "DLL Name: " << exports.dll_name() << "\n";
        std::cout << "Ordinal Base: " << exports.ordinal_base() << "\n\n";
        
        std::cout << std::left 
                  << std::setw(8) << "Ordinal"
                  << std::setw(10) << "RVA"
                  << std::setw(40) << "Name"
                  << "Forward\n";
        std::cout << std::string(80, '-') << "\n";
        
        for (const auto& func : exports) {
            // Skip if filter active and no match
            if (has_filter()) {
                if (!matches_filter(func.name) && !matches_filter(func.forward_target)) {
                    continue;
                }
            }
            
            std::cout << std::left << std::setw(8) << func.ordinal
                      << "0x" << std::hex << std::setfill('0') << std::setw(6) 
                      << func.rva << std::dec << std::setfill(' ') << "  "
                      << std::setw(40) << (func.name.empty() ? "(unnamed)" : func.name);
            
            if (func.is_forwarded) {
                std::cout << " -> " << func.forward_target;
            }
            std::cout << "\n";
        }
    }
}

void OutputFormatter::print_entropy(const PEFile& pe) {
    const auto& sections = pe.sections();
    
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"sections\": [\n";
        
        bool first = true;
        for (const auto& section : sections) {
            if (!first) std::cout << ",\n";
            first = false;
            
            double entropy = section.calculate_entropy(pe);
            std::cout << "    {\n";
            std::cout << "      \"name\": \"" << section.name << "\",\n";
            std::cout << "      \"entropy\": " << std::fixed << std::setprecision(3) << entropy << ",\n";
            std::cout << "      \"classification\": \"" << entropy_classification(entropy) << "\"\n";
            std::cout << "    }";
        }
        
        std::cout << "\n  ]\n";
        std::cout << "}\n";
    } else {
        std::cout << "Section Entropy Analysis\n";
        std::cout << "========================\n\n";
        
        std::cout << std::left 
                  << std::setw(10) << "Name"
                  << std::setw(12) << "Entropy"
                  << std::setw(10) << "Status"
                  << "Classification\n";
        std::cout << std::string(60, '-') << "\n";
        
        for (const auto& section : sections) {
            double entropy = section.calculate_entropy(pe);
            
            std::cout << std::left << std::setw(10) << section.name
                      << std::fixed << std::setprecision(3) << std::setw(12) << entropy;
            
            if (is_high_entropy(entropy)) {
                std::cout << std::setw(10) << "[HIGH]";
            } else {
                std::cout << std::setw(10) << "";
            }
            
            std::cout << entropy_classification(entropy) << "\n";
        }
    }
}

void OutputFormatter::print_security(const SecurityFeatures& features) {
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"aslr\": {\n";
        std::cout << "    \"compatible\": " << (features.aslr_compatible ? "true" : "false") << ",\n";
        std::cout << "    \"relocationsStripped\": " << (features.relocations_stripped ? "true" : "false") << "\n";
        std::cout << "  },\n";
        std::cout << "  \"dep\": {\n";
        std::cout << "    \"compatible\": " << (features.dep_compatible ? "true" : "false") << "\n";
        std::cout << "  },\n";
        std::cout << "  \"cfg\": {\n";
        std::cout << "    \"enabled\": " << (features.cfg_enabled ? "true" : "false") << "\n";
        std::cout << "  },\n";
        std::cout << "  \"safeSeh\": {\n";
        std::cout << "    \"enabled\": " << (features.safeseh_enabled ? "true" : "false") << "\n";
        std::cout << "  },\n";
        std::cout << "  \"signature\": {\n";
        std::cout << "    \"signed\": " << (features.is_signed ? "true" : "false") << "\n";
        std::cout << "  },\n";
        std::cout << "  \"entropy\": {\n";
        std::cout << "    \"hasHighEntropySections\": " << (features.has_high_entropy_sections ? "true" : "false") << "\n";
        std::cout << "  },\n";
        std::cout << "  \"score\": " << features.security_score() << "\n";
        std::cout << "}\n";
    } else {
        std::cout << "Security Features Analysis\n";
        std::cout << "==========================\n\n";
        
        std::cout << features.assessment() << "\n";
    }
}

void OutputFormatter::print_resources(const ResourceTable& resources) {
    if (resources.empty()) {
        if (json_) {
            std::cout << "{\n  \"types\": [],\n  \"count\": 0\n}\n";
        } else {
            std::cout << "No resources found.\n";
        }
        return;
    }
    
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"directoryRva\": " << resources.directory_rva() << ",\n";
        std::cout << "  \"directorySize\": " << resources.directory_size() << ",\n";
        std::cout << "  \"typeCount\": " << resources.type_count() << ",\n";
        std::cout << "  \"totalEntries\": " << resources.entry_count() << ",\n";
        std::cout << "  \"types\": [\n";
        
        bool first_type = true;
        for (const auto& type : resources) {
            if (!first_type) std::cout << ",\n";
            first_type = false;
            
            std::cout << "    {\n";
            if (type.is_named) {
                std::cout << "      \"typeName\": \"" << type.type_name << "\",\n";
            } else {
                std::cout << "      \"typeId\": " << type.type_id << ",\n";
                std::cout << "      \"typeName\": \"" << ResourceTable::type_id_to_string(type.type_id) << "\",\n";
            }
            std::cout << "      \"entryCount\": " << type.entries.size() << ",\n";
            std::cout << "      \"entries\": [\n";
            
            bool first_entry = true;
            for (const auto& entry : type.entries) {
                if (!first_entry) std::cout << ",\n";
                first_entry = false;
                
                std::cout << "        {\n";
                if (entry.is_named) {
                    std::cout << "          \"name\": \"" << entry.name << "\",\n";
                } else {
                    std::cout << "          \"id\": " << entry.id << ",\n";
                }
                std::cout << "          \"rva\": " << entry.rva << ",\n";
                std::cout << "          \"offset\": " << entry.offset << ",\n";
                std::cout << "          \"size\": " << entry.size << ",\n";
                std::cout << "          \"codePage\": " << entry.code_page << ",\n";
                std::cout << "          \"languageId\": " << entry.language_id << ",\n";
                std::cout << "          \"sublanguageId\": " << entry.sublanguage_id << "\n";
                std::cout << "        }";
            }
            
            std::cout << "\n      ]\n";
            std::cout << "    }";
        }
        
        std::cout << "\n  ]\n";
        std::cout << "}\n";
    } else {
        std::cout << "Resource Directory\n";
        std::cout << "==================\n\n";
        std::cout << "Directory RVA: 0x" << std::hex << resources.directory_rva() << std::dec << "\n";
        std::cout << "Directory Size: " << resources.directory_size() << " bytes\n";
        std::cout << "Type Count: " << resources.type_count() << "\n";
        std::cout << "Total Entries: " << resources.entry_count() << "\n\n";
        
        for (const auto& type : resources) {
            std::string type_str;
            if (type.is_named) {
                type_str = type.type_name;
            } else {
                type_str = ResourceTable::type_id_to_string(type.type_id);
                if (type_str == "Unknown") {
                    type_str = "Type " + std::to_string(type.type_id);
                }
            }
            
            print_section_header(type_str.c_str());
            std::cout << "  Entries: " << type.entries.size() << "\n\n";
            
            for (const auto& entry : type.entries) {
                std::cout << "  ";
                if (entry.is_named) {
                    std::cout << entry.name;
                } else {
                    std::cout << "ID: " << entry.id;
                }
                std::cout << "\n";
                
                std::cout << "    RVA: 0x" << std::hex << entry.rva << std::dec << "\n";
                std::cout << "    Offset: 0x" << std::hex << entry.offset << std::dec << "\n";
                std::cout << "    Size: " << entry.size << " bytes\n";
                
                if (verbose_) {
                    std::cout << "    Code Page: " << entry.code_page << "\n";
                    std::cout << "    Language: " << entry.language_id << "\n";
                    std::cout << "    Sublanguage: " << entry.sublanguage_id << "\n";
                }
                std::cout << "\n";
            }
        }
    }
}

void OutputFormatter::print_rich(const RichHeader& rich) {
    if (!rich.is_present()) {
        if (json_) {
            std::cout << "{\"present\": false}\n";
        } else {
            std::cout << "No Rich Header found in this PE file.\n";
        }
        return;
    }
    
    if (json_) {
        std::cout << "{\n";
        std::cout << "  \"present\": true,\n";
        std::cout << "  \"xor_key\": \"0x" << std::hex << rich.xor_key() << std::dec << "\",\n";
        std::cout << "  \"checksum_valid\": " << (rich.validate_checksum() ? "true" : "false") << ",\n";
        std::cout << "  \"entries\": [\n";
        
        const auto& entries = rich.entries();
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            std::cout << "    {\n";
            std::cout << "      \"id\": " << entry.id << ",\n";
            std::cout << "      \"version\": " << entry.version << ",\n";
            std::cout << "      \"count\": " << entry.count << ",\n";
            std::cout << "      \"tool_name\": \"";
            print_json_string(std::cout, rich.tool_name(entry.id));
            std::cout << "\"\n";
            std::cout << "    }";
            if (i < entries.size() - 1) std::cout << ",";
            std::cout << "\n";
        }
        
        std::cout << "  ]\n";
        std::cout << "}\n";
    } else {
        print_section_header("Rich Header");
        
        print_kv("Present", "Yes");
        print_kv("XOR Key", rich.xor_key(), 0, true);
        print_kv("Checksum Valid", rich.validate_checksum() ? "Yes" : "No");
        std::cout << "\n";
        
        print_section_header("Rich Entries");
        
        const auto& entries = rich.entries();
        if (entries.empty()) {
            std::cout << "  No entries found.\n";
        } else {
            for (const auto& entry : entries) {
                std::cout << "  Entry:\n";
                std::cout << "    Tool ID: " << entry.id << " (0x" << std::hex << entry.id << std::dec << ")\n";
                std::cout << "    Version: " << entry.version << " (0x" << std::hex << entry.version << std::dec << ")\n";
                std::cout << "    Count: " << entry.count << "\n";
                std::cout << "    Tool: " << rich.tool_name(entry.id) << "\n";
                std::cout << "\n";
            }
        }
    }
}

} // namespace dlltools::cli
