#pragma once

#include "core/pe_parser.hpp"
#include <vector>
#include <string>

namespace dlltools {

/// Security features detected in a PE file
struct SecurityFeatures {
    // ASLR (Address Space Layout Randomization)
    bool aslr_compatible = false;       ///< DYNAMIC_BASE flag set
    bool relocations_stripped = false;  ///< No relocation table
    
    // DEP (Data Execution Prevention)
    bool dep_compatible = false;        ///< NX_COMPAT flag set
    
    // Control Flow Guard
    bool cfg_enabled = false;           ///< Guard CF flag set
    
    // SafeSEH
    bool safeseh_enabled = false;       ///< Valid SEH table or NO_SEH
    
    // Digital signature
    bool is_signed = false;             ///< Has authenticode signature
    
    // Entropy analysis
    bool has_high_entropy_sections = false;  ///< Possible packing
    std::vector<std::string> high_entropy_sections;  ///< Section names with high entropy
    
    /// Get overall security score (0-100)
    [[nodiscard]] int security_score() const noexcept;
    
    /// Get security assessment summary
    [[nodiscard]] std::string assessment() const;
};

/// Analyze security features of a PE file
/// @param pe PE file to analyze
/// @return Security features structure
[[nodiscard]] SecurityFeatures analyze_security(const PEFile& pe);

/// Check if PE has valid relocation table
/// @param pe PE file to check
/// @return true if relocations are present
[[nodiscard]] bool has_relocations(const PEFile& pe);

/// Check if PE has SEH handlers
/// @param pe PE file to check
/// @return true if SEH handlers are present
[[nodiscard]] bool has_seh_handlers(const PEFile& pe);

} // namespace dlltools
