#include "core/section.hpp"
#include "core/pe_parser.hpp"
#include "core/entropy.hpp"
#include "utils/string_utils.hpp"
#include <stdexcept>

namespace dlltools {

// =============================================================================
// SectionTable Implementation
// =============================================================================

SectionTable::SectionTable(const PEFile& pe) {
    const auto* raw_sections = pe.section_headers();
    const auto count = pe.section_count();
    
    sections_.reserve(count);
    
    for (uint16_t i = 0; i < count; ++i) {
        const auto& raw = raw_sections[i];
        
        SectionHeader section;
        section.name = utils::extract_pe_string(
            reinterpret_cast<const char*>(raw.Name),
            IMAGE_SIZEOF_SHORT_NAME
        );
        section.virtual_address = raw.VirtualAddress;
        section.virtual_size = raw.Misc.VirtualSize;
        section.raw_size = raw.SizeOfRawData;
        section.raw_offset = raw.PointerToRawData;
        section.characteristics = raw.Characteristics;
        
        sections_.push_back(std::move(section));
    }
}

const SectionHeader& SectionTable::operator[](size_t index) const {
    if (index >= sections_.size()) {
        throw std::out_of_range("SectionTable::operator[] - index out of range");
    }
    return sections_[index];
}

const SectionHeader* SectionTable::at(size_t index) const noexcept {
    if (index >= sections_.size()) {
        return nullptr;
    }
    return &sections_[index];
}

const SectionHeader* SectionTable::find_by_name(std::string_view name) const noexcept {
    for (const auto& section : sections_) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

std::optional<size_t> SectionTable::find_index_by_name(std::string_view name) const noexcept {
    for (size_t i = 0; i < sections_.size(); ++i) {
        if (sections_[i].name == name) {
            return i;
        }
    }
    return std::nullopt;
}

const SectionHeader* SectionTable::find_by_rva(uint32_t rva) const noexcept {
    for (const auto& section : sections_) {
        if (section.contains_rva(rva)) {
            return &section;
        }
    }
    return nullptr;
}

std::optional<size_t> SectionTable::find_index_by_rva(uint32_t rva) const noexcept {
    for (size_t i = 0; i < sections_.size(); ++i) {
        if (sections_[i].contains_rva(rva)) {
            return i;
        }
    }
    return std::nullopt;
}

// =============================================================================
// SectionHeader Implementation
// =============================================================================

double SectionHeader::calculate_entropy(const PEFile& pe) const {
    // Handle uninitialized data sections
    if (raw_size == 0 || raw_offset == 0) {
        return 0.0;
    }
    
    // Get section data
    const uint8_t* data = pe.mapping().ptr_at(raw_offset, raw_size);
    if (!data) {
        return 0.0;
    }
    
    return calculate_shannon_entropy(data, raw_size);
}

} // namespace dlltools
