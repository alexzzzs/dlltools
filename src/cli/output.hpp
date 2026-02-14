#pragma once

#include "core/pe_parser.hpp"
#include "core/section.hpp"
#include "core/import.hpp"
#include "core/export.hpp"
#include "core/resource.hpp"
#include "core/security.hpp"
#include "core/rich.hpp"
#include "cli/colours.hpp"
#include <iostream>
#include <string>
#include <optional>

namespace dlltools::cli {

/// Output formatter for different output formats
class OutputFormatter {
public:
    /// Constructor
    /// @param json Use JSON output format
    /// @param verbose Verbose output
    /// @param filter Optional filter string for imports/exports
    /// @param use_colour Enable coloured output
    OutputFormatter(bool json = false, bool verbose = false, const std::string& filter = "", bool use_colour = false);
    
    /// Print PE file overview
    void print_inspect(const PEFile& pe);
    
    /// Print PE headers
    void print_headers(const PEFile& pe);
    
    /// Print section table
    void print_sections(const SectionTable& sections);
    
    /// Print import table
    void print_imports(const ImportTable& imports);
    
    /// Print export table
    void print_exports(const ExportTable& exports);
    
    /// Print entropy analysis
    void print_entropy(const PEFile& pe);
    
    /// Print security features
    void print_security(const SecurityFeatures& features);
    
    /// Print resource table
    void print_resources(const ResourceTable& resources);
    
    /// Print Rich Header
    void print_rich(const RichHeader& rich);
    
private:
    bool json_;
    bool verbose_;
    std::string filter_;
    bool use_colour_;
    
    /// Check if a string matches the filter (case-insensitive substring match)
    [[nodiscard]] bool matches_filter(std::string_view str) const noexcept;
    
    /// Check if filter is active
    [[nodiscard]] bool has_filter() const noexcept { return !filter_.empty(); }
    
    /// Check if colours are enabled
    [[nodiscard]] bool use_colour() const noexcept { return use_colour_; }
    
    /// Print a key-value pair
    void print_kv(const char* key, const char* value, int indent = 0);
    void print_kv(const char* key, const std::string& value, int indent = 0);
    void print_kv(const char* key, uint64_t value, int indent = 0);
    void print_kv(const char* key, uint32_t value, int indent = 0, bool hex = false);
    void print_kv(const char* key, uint16_t value, int indent = 0, bool hex = false);
    
    /// Print a section header
    void print_section_header(const char* title);
    
    /// Print JSON string (escaped)
    void print_json_string(std::ostream& os, std::string_view str);
};

} // namespace dlltools::cli
