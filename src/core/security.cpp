#include "core/security.hpp"
#include "core/entropy.hpp"
#include "core/section.hpp"
#include "core/pe_parser.hpp"

// Undefine Windows macros that conflict with std::min/std::max
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

namespace dlltools {

SecurityFeatures analyze_security(const PEFile& pe) {
    SecurityFeatures features;
    
    // Get DLL characteristics
    uint16_t dll_chars = pe.dll_characteristics();
    
    // ASLR check
    features.aslr_compatible = (dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    
    // Check for relocations
    features.relocations_stripped = !has_relocations(pe);
    
    // DEP check
    features.dep_compatible = (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    
    // CFG check
    features.cfg_enabled = (dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    
    // SafeSEH check
    bool no_seh = (dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0;
    if (no_seh) {
        features.safeseh_enabled = true;  // NO_SEH means no SEH handlers, which is safe
    } else {
        // Check for valid SEH table in load config
        // For now, just check if SEH handlers exist
        features.safeseh_enabled = !has_seh_handlers(pe);
    }
    
    // Entropy analysis
    const auto& sections = pe.sections();
    for (const auto& section : sections) {
        double entropy = section.calculate_entropy(pe);
        if (is_high_entropy(entropy)) {
            features.has_high_entropy_sections = true;
            features.high_entropy_sections.push_back(section.name);
        }
    }
    
    // Digital signature check (basic - check for certificate directory)
    if (pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)) {
        const auto* dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY);
        if (dir && dir->Size > 0) {
            features.is_signed = true;
        }
    }
    
    return features;
}

bool has_relocations(const PEFile& pe) {
    // Check if relocation directory exists
    if (!pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
        return false;
    }
    
    // Check file characteristics for stripped relocations
    uint16_t chars = pe.characteristics();
    if (chars & IMAGE_FILE_RELOCS_STRIPPED) {
        return false;
    }
    
    return true;
}

bool has_seh_handlers(const PEFile& pe) {
    // Check for exception directory
    if (!pe.has_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)) {
        return false;
    }
    
    const auto* dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (!dir || dir->Size == 0) {
        return false;
    }
    
    // For x64, check for exception table entries
    // For x86, this would require parsing the load config
    if (pe.is_pe32_plus()) {
        const uint8_t* data = pe.rva_to_ptr(dir->VirtualAddress);
        if (!data) {
            return false;
        }
        
        // Count exception table entries
        size_t count = dir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        return count > 0;
    }
    
    // For x86, we'd need to check the load config for SEH table
    // This is a simplified check
    return false;
}

int SecurityFeatures::security_score() const noexcept {
    int score = 0;
    
    // ASLR (25 points)
    if (aslr_compatible && !relocations_stripped) {
        score += 25;
    } else if (aslr_compatible) {
        score += 10;  // ASLR enabled but relocations stripped
    }
    
    // DEP (25 points)
    if (dep_compatible) {
        score += 25;
    }
    
    // CFG (20 points)
    if (cfg_enabled) {
        score += 20;
    }
    
    // SafeSEH (15 points)
    if (safeseh_enabled) {
        score += 15;
    }
    
    // Signed (10 points)
    if (is_signed) {
        score += 10;
    }
    
    // High entropy penalty (possible packing)
    if (has_high_entropy_sections) {
        score -= 10;
    }
    
    return std::max(0, std::min(100, score));
}

std::string SecurityFeatures::assessment() const {
    std::string result;
    
    if (aslr_compatible) {
        result += "ASLR: Enabled";
        if (relocations_stripped) {
            result += " (but relocations stripped)";
        }
        result += "\n";
    } else {
        result += "ASLR: Disabled\n";
    }
    
    result += std::string("DEP: ") + (dep_compatible ? "Enabled" : "Disabled") + "\n";
    result += std::string("CFG: ") + (cfg_enabled ? "Enabled" : "Disabled") + "\n";
    result += std::string("SafeSEH: ") + (safeseh_enabled ? "Enabled" : "Disabled") + "\n";
    result += std::string("Signed: ") + (is_signed ? "Yes" : "No") + "\n";
    
    if (has_high_entropy_sections) {
        result += "High Entropy Sections: ";
        for (size_t i = 0; i < high_entropy_sections.size(); ++i) {
            if (i > 0) result += ", ";
            result += high_entropy_sections[i];
        }
        result += " (possible packing/encryption)\n";
    }
    
    result += "Security Score: " + std::to_string(security_score()) + "/100";
    
    return result;
}

} // namespace dlltools
