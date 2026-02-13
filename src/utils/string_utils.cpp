#include "utils/string_utils.hpp"
#include <windows.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace dlltools::utils {

// =============================================================================
// UTF-8 / UTF-16 Conversion
// =============================================================================

std::wstring utf8_to_wide(std::string_view str) {
    if (str.empty()) {
        return L"";
    }
    
    int size_needed = ::MultiByteToWideChar(
        CP_UTF8,
        0,
        str.data(),
        static_cast<int>(str.size()),
        nullptr,
        0
    );
    
    if (size_needed == 0) {
        return L"";
    }
    
    std::wstring result(size_needed, 0);
    ::MultiByteToWideChar(
        CP_UTF8,
        0,
        str.data(),
        static_cast<int>(str.size()),
        result.data(),
        size_needed
    );
    
    return result;
}

std::string wide_to_utf8(std::wstring_view wstr) {
    if (wstr.empty()) {
        return "";
    }
    
    int size_needed = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.data(),
        static_cast<int>(wstr.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    
    if (size_needed == 0) {
        return "";
    }
    
    std::string result(size_needed, 0);
    ::WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.data(),
        static_cast<int>(wstr.size()),
        result.data(),
        size_needed,
        nullptr,
        nullptr
    );
    
    return result;
}

// =============================================================================
// String Trimming
// =============================================================================

std::string_view trim_left(std::string_view str) {
    auto it = std::find_if_not(str.begin(), str.end(), [](char c) {
        return std::isspace(static_cast<unsigned char>(c));
    });
    return str.substr(static_cast<size_t>(it - str.begin()));
}

std::string_view trim_right(std::string_view str) {
    auto it = std::find_if_not(str.rbegin(), str.rend(), [](char c) {
        return std::isspace(static_cast<unsigned char>(c));
    });
    return str.substr(0, static_cast<size_t>(str.rend() - it));
}

std::string_view trim(std::string_view str) {
    return trim_right(trim_left(str));
}

// =============================================================================
// PE-Specific String Utilities
// =============================================================================

std::string_view extract_string(const char* data, size_t max_length) {
    if (!data || max_length == 0) {
        return "";
    }
    
    size_t length = 0;
    while (length < max_length && data[length] != '\0') {
        ++length;
    }
    
    return std::string_view(data, length);
}

std::string extract_pe_string(const char* data, size_t length) {
    if (!data || length == 0) {
        return "";
    }
    
    // Find the actual string length (may be null-padded or full length)
    size_t actual_length = 0;
    while (actual_length < length && data[actual_length] != '\0') {
        ++actual_length;
    }
    
    return std::string(data, actual_length);
}

std::string format_timestamp(uint32_t timestamp) {
    if (timestamp == 0) {
        return "N/A";
    }
    
    // Convert Unix timestamp to time_t
    std::time_t time = static_cast<std::time_t>(timestamp);
    std::tm tm_result;
    
    // Use gmtime_s for thread-safe conversion
    if (gmtime_s(&tm_result, &time) != 0) {
        return "Invalid";
    }
    
    std::ostringstream oss;
    oss << std::put_time(&tm_result, "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}

std::string machine_type_name(uint16_t machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:      return "i386";
        case IMAGE_FILE_MACHINE_AMD64:     return "AMD64";
        case IMAGE_FILE_MACHINE_IA64:      return "IA64";
        case IMAGE_FILE_MACHINE_ARM:       return "ARM";
        case IMAGE_FILE_MACHINE_ARMNT:     return "ARM Thumb-2";
        case IMAGE_FILE_MACHINE_ARM64:     return "ARM64";
        case IMAGE_FILE_MACHINE_R4000:     return "MIPS R4000";
        case IMAGE_FILE_MACHINE_POWERPC:   return "PowerPC";
        case IMAGE_FILE_MACHINE_UNKNOWN:   return "Unknown";
        default:                           return "Unknown (0x" + to_hex(machine, 4) + ")";
    }
}

std::string subsystem_name(uint16_t subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_UNKNOWN:                  return "Unknown";
        case IMAGE_SUBSYSTEM_NATIVE:                   return "Native";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:              return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:              return "Windows CUI";
        case IMAGE_SUBSYSTEM_OS2_CUI:                  return "OS/2 CUI";
        case IMAGE_SUBSYSTEM_POSIX_CUI:                return "POSIX CUI";
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:           return "Native Windows";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:           return "Windows CE GUI";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:          return "EFI Application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:  return "EFI Boot Service Driver";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:       return "EFI Runtime Driver";
        case IMAGE_SUBSYSTEM_EFI_ROM:                  return "EFI ROM";
        case IMAGE_SUBSYSTEM_XBOX:                     return "Xbox";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Windows Boot Application";
        default:                                       return "Unknown (" + std::to_string(subsystem) + ")";
    }
}

std::vector<std::string> section_characteristics_flags(uint32_t characteristics) {
    std::vector<std::string> flags;
    
    // Type flags
    if (characteristics & IMAGE_SCN_TYPE_NO_PAD) {
        flags.push_back("NO_PAD");
    }
    if (characteristics & IMAGE_SCN_CNT_CODE) {
        flags.push_back("CODE");
    }
    if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
        flags.push_back("INITIALIZED_DATA");
    }
    if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
        flags.push_back("UNINITIALIZED_DATA");
    }
    
    // Alignment flags
    uint32_t align = characteristics & IMAGE_SCN_ALIGN_MASK;
    if (align != 0) {
        std::string align_str;
        switch (align) {
            case IMAGE_SCN_ALIGN_1BYTES:    align_str = "ALIGN_1"; break;
            case IMAGE_SCN_ALIGN_2BYTES:    align_str = "ALIGN_2"; break;
            case IMAGE_SCN_ALIGN_4BYTES:    align_str = "ALIGN_4"; break;
            case IMAGE_SCN_ALIGN_8BYTES:    align_str = "ALIGN_8"; break;
            case IMAGE_SCN_ALIGN_16BYTES:   align_str = "ALIGN_16"; break;
            case IMAGE_SCN_ALIGN_32BYTES:   align_str = "ALIGN_32"; break;
            case IMAGE_SCN_ALIGN_64BYTES:   align_str = "ALIGN_64"; break;
            case IMAGE_SCN_ALIGN_128BYTES:  align_str = "ALIGN_128"; break;
            case IMAGE_SCN_ALIGN_256BYTES:  align_str = "ALIGN_256"; break;
            case IMAGE_SCN_ALIGN_512BYTES:  align_str = "ALIGN_512"; break;
            case IMAGE_SCN_ALIGN_1024BYTES: align_str = "ALIGN_1024"; break;
            case IMAGE_SCN_ALIGN_2048BYTES: align_str = "ALIGN_2048"; break;
            case IMAGE_SCN_ALIGN_4096BYTES: align_str = "ALIGN_4096"; break;
            case IMAGE_SCN_ALIGN_8192BYTES: align_str = "ALIGN_8192"; break;
            default: align_str = "ALIGN_UNKNOWN"; break;
        }
        flags.push_back(align_str);
    }
    
    // Access flags
    if (characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) {
        flags.push_back("RELOC_OVERFLOW");
    }
    if (characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
        flags.push_back("DISCARDABLE");
    }
    if (characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        flags.push_back("NOT_CACHED");
    }
    if (characteristics & IMAGE_SCN_MEM_NOT_PAGED) {
        flags.push_back("NOT_PAGED");
    }
    if (characteristics & IMAGE_SCN_MEM_SHARED) {
        flags.push_back("SHARED");
    }
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        flags.push_back("EXECUTE");
    }
    if (characteristics & IMAGE_SCN_MEM_READ) {
        flags.push_back("READ");
    }
    if (characteristics & IMAGE_SCN_MEM_WRITE) {
        flags.push_back("WRITE");
    }
    
    return flags;
}

std::vector<std::string> dll_characteristics_flags(uint16_t characteristics) {
    std::vector<std::string> flags;
    
    if (characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
        flags.push_back("HIGH_ENTROPY_VA");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        flags.push_back("DYNAMIC_BASE (ASLR)");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
        flags.push_back("FORCE_INTEGRITY");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
        flags.push_back("NX_COMPAT (DEP)");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) {
        flags.push_back("NO_ISOLATION");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
        flags.push_back("NO_SEH");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) {
        flags.push_back("NO_BIND");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) {
        flags.push_back("APPCONTAINER");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) {
        flags.push_back("WDM_DRIVER");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        flags.push_back("GUARD_CF (CFG)");
    }
    if (characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) {
        flags.push_back("TERMINAL_SERVER_AWARE");
    }
    
    return flags;
}

// =============================================================================
// Size Formatting
// =============================================================================

std::string format_size(uint64_t bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    size_t unit_index = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        ++unit_index;
    }
    
    std::ostringstream oss;
    if (unit_index == 0) {
        oss << bytes << " " << units[unit_index];
    } else {
        oss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
    }
    
    return oss.str();
}

std::string format_entropy(double entropy) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3) << entropy;
    return oss.str();
}

bool string_equals_case_insensitive(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    
    return std::equal(a.begin(), a.end(), b.begin(), 
        [](char ca, char cb) {
            return std::tolower(static_cast<unsigned char>(ca)) == 
                   std::tolower(static_cast<unsigned char>(cb));
        });
}

bool string_contains_case_insensitive(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    
    // Use std::search with case-insensitive comparison
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
        [](char ch1, char ch2) {
            return std::tolower(static_cast<unsigned char>(ch1)) == 
                   std::tolower(static_cast<unsigned char>(ch2));
        });
    
    return it != haystack.end();
}

} // namespace dlltools::utils
