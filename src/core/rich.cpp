#include "core/rich.hpp"
#include "core/pe_parser.hpp"
#include <stdexcept>
#include <cstring>

namespace dlltools {

// =============================================================================
// RichHeader Implementation
// =============================================================================

RichHeader::RichHeader(
    std::vector<RichEntry>&& entries,
    uint32_t xor_key,
    uint32_t offset,
    uint32_t size,
    bool checksum_valid
) : entries_(std::move(entries))
  , xor_key_(xor_key)
  , offset_(offset)
  , size_(size)
  , present_(true)
  , checksum_valid_(checksum_valid)
{
}

// =============================================================================
// Entry Access
// =============================================================================

const RichEntry& RichHeader::operator[](size_t index) const {
    if (index >= entries_.size()) {
        throw std::out_of_range("RichHeader entry index out of range");
    }
    return entries_[index];
}

const RichEntry* RichHeader::at(size_t index) const noexcept {
    if (index >= entries_.size()) {
        return nullptr;
    }
    return &entries_[index];
}

// =============================================================================
// Parsing
// =============================================================================

Result<RichHeader> RichHeader::parse(const PEFile& pe) {
    // Rich Header is located between DOS header and NT headers
    // It starts at offset 64 (sizeof(IMAGE_DOS_HEADER)) and ends at e_lfanew
    
    const uint8_t* data = pe.data();
    const size_t size = pe.size();
    
    // DOS header is at offset 0
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        return RichHeader{};  // No room for Rich Header
    }
    
    const IMAGE_DOS_HEADER* dos_header = &pe.dos_header();
    int32_t e_lfanew = dos_header->e_lfanew;
    
    // Validate e_lfanew is a reasonable positive value within file bounds
    if (e_lfanew <= 0 || static_cast<size_t>(e_lfanew) > size) {
        return RichHeader{};  // Invalid or out-of-bounds e_lfanew
    }
    
    // Rich Header must be between DOS header and NT headers
    // It starts right after DOS header (offset 64)
    const size_t rich_start = sizeof(IMAGE_DOS_HEADER);
    
    // Check if there's space for a Rich Header
    if (static_cast<size_t>(e_lfanew) <= rich_start + sizeof(uint32_t)) {
        return RichHeader{};  // No space for Rich Header
    }
    
    // Search for "Rich" magic marker (0x68636952)
    // The marker is at the END of the Rich Header, followed by the XOR key
    // Format: ... entries ... "Rich" XOR_KEY
    
    // Search backwards for "Rich" marker
    // The marker should be near the end of the area
    uint32_t rich_offset = 0;
    uint32_t xor_key = 0;
    bool found = false;
    
    // Scan for "Rich" magic - it should be aligned and near the end
    // The structure is: entries (each 8 bytes) + "Rich" (4 bytes) + XOR key (4 bytes)
    for (size_t i = rich_start; i + 8 <= static_cast<size_t>(e_lfanew); i += 4) {
        uint32_t value;
        std::memcpy(&value, data + i, sizeof(uint32_t));
        
        if (value == RICH_MAGIC) {
            // Found "Rich" marker
            rich_offset = static_cast<uint32_t>(i);
            
            // XOR key follows the "Rich" marker
            // Need at least 4 bytes after "Rich" for the key (i + 8 total for both)
            if (i + 8 <= static_cast<size_t>(e_lfanew)) {
                std::memcpy(&xor_key, data + i + 4, sizeof(uint32_t));
            }
            found = true;
            break;
        }
    }
    
    if (!found) {
        return RichHeader{};  // No Rich Header found (not an error - header simply absent)
    }
    
    // Now parse the entries
    // Each entry is 8 bytes: id (2) + version (2) + count (4)
    // All XOR'd with the key
    
    // The entries start at the DOS stub (offset 64) and go until "Rich"
    // But we need to find the START marker "DanS" which is XOR'd with the key
    
    std::vector<RichEntry> entries;
    uint32_t entries_start = 0;
    
    // Search for "DanS" marker (start of entries) - it's XOR'd with the key
    const uint32_t dans_xor = DAN_MAGIC ^ xor_key;
    
    for (size_t i = rich_start; i + 4 <= rich_offset; i += 4) {
        uint32_t value;
        std::memcpy(&value, data + i, sizeof(uint32_t));
        
        if (value == dans_xor) {
            entries_start = static_cast<uint32_t>(i + 4);  // Entries start after "DanS"
            break;
        }
    }
    
    // If no "DanS" found, entries might start right after DOS header
    // Some implementations don't have the start marker
    if (entries_start == 0) {
        entries_start = static_cast<uint32_t>(rich_start);
    }
    
    // Parse entries until we reach "Rich"
    // Each entry is 8 bytes, XOR'd with the key
    for (size_t i = entries_start; i + 8 <= rich_offset; i += 8) {
        uint32_t entry_data[2];
        std::memcpy(entry_data, data + i, sizeof(uint32_t) * 2);
        
        // Decode with XOR key
        uint32_t decoded0 = entry_data[0] ^ xor_key;
        uint32_t decoded1 = entry_data[1] ^ xor_key;
        
        // Extract fields
        // Rich header format: upper 16 bits = product/comp ID, lower 16 bits = build number
        RichEntry entry;
        entry.id = static_cast<uint16_t>((decoded0 >> 16) & 0xFFFF);  // Product/comp ID
        entry.version = static_cast<uint16_t>(decoded0 & 0xFFFF);       // Build number
        entry.count = decoded1;
        
        // Skip zero entries (padding)
        if (entry.id != 0 || entry.count != 0) {
            entries.push_back(entry);
        }
    }
    
    // Validate checksum using standard Rich algorithm
    // 1. Compute rol_sum over first 64 DOS-header bytes (skip e_lfanew at 0x3C-0x3F)
    // 2. XOR that rol_sum with encoded DanS block bytes
    // 3. Result should equal xor_key
    
    bool checksum_valid = false;
    
    // Compute rol_sum over DOS header bytes 0-63, skipping e_lfanew (0x3C-0x3F)
    uint32_t rol_sum = 0;
    for (size_t i = 0; i < 64; ++i) {
        // Skip the e_lfanew field at offset 0x3C-0x3F
        if (i >= 0x3C && i < 0x40) {
            continue;
        }
        uint8_t byte = data[i];
        // Rotate left by 1 bit
        rol_sum = ((rol_sum << 1) | (rol_sum >> 31)) & 0xFFFFFFFF;
        // Add byte
        rol_sum = (rol_sum + byte) & 0xFFFFFFFF;
    }
    
    // XOR the encoded DanS block bytes (between entries_start and rich_offset)
    for (size_t i = entries_start; i < rich_offset; ++i) {
        rol_sum ^= static_cast<uint32_t>(data[i]);
    }
    
    // The result should equal the xor_key
    checksum_valid = (rol_sum == xor_key);
    
    // Calculate size
    uint32_t header_size = rich_offset - rich_start + 8;  // Include "Rich" and XOR key
    
    return RichHeader(
        std::move(entries),
        xor_key,
        static_cast<uint32_t>(rich_start),
        header_size,
        checksum_valid
    );
}

// =============================================================================
// Tool Name Lookup
// =============================================================================

std::string RichHeader::tool_name(uint16_t id) {
    // Known tool IDs based on research
    // These are the product/build numbers used by Microsoft build tools
    // Reference: https://github.com/ladislav-zezula/StormLib/blob/master/src/stormlib/rich.c
    
    switch (id) {
        // Common tool IDs (basic set)
        case 0x0000: return "Unknown/VS2003";
        case 0x0001: return "Unknown/VS2005";
        case 0x0002: return "Unknown/VS2008";
        case 0x0003: return "Unknown/VS2010";
        case 0x0004: return "Unknown/VS2012";
        case 0x0005: return "Unknown/VS2013";
        case 0x0006: return "Unknown/VS2015";
        case 0x0007: return "Unknown/VS2017";
        case 0x0008: return "Unknown/VS2019";
        case 0x0009: return "Unknown/VS2022";
        
        // Standard tool IDs
        case 0x0014: return "lib.exe";
        case 0x0015: return "link.exe";
        case 0x0016: return "cvtres.exe";
        case 0x0017: return "rc.exe";
        case 0x0018: return "cl.exe (C)";
        case 0x0019: return "cl.exe (C++)";
        case 0x001A: return "ml.exe (MASM)";
        case 0x001B: return "lib.exe (import library)";
        case 0x001C: return "editbin.exe";
        case 0x001D: return "bscmake.exe";
        case 0x001E: return "hlp.exe";
        case 0x001F: return "MsJava.exe";
        
        // VS2008 specific build IDs
        case 0x7864: return "link.exe";
        case 0x7865: return "cvtres.exe";
        case 0x7866: return "rc.exe";
        case 0x7867: return "cl.exe";
        
        // VS2010 specific build IDs
        case 0x7D1C: return "link.exe";
        case 0x7D1D: return "cvtres.exe";
        case 0x7D1E: return "rc.exe";
        case 0x7D1F: return "cl.exe";
        
        // VS2012 specific build IDs
        case 0x82AC: return "link.exe";
        case 0x82AD: return "cvtres.exe";
        case 0x82AE: return "rc.exe";
        case 0x82AF: return "cl.exe";
        
        // VS2013 specific build IDs
        case 0x8754: return "link.exe";
        case 0x8755: return "cvtres.exe";
        case 0x8756: return "rc.exe";
        case 0x8757: return "cl.exe";
        
        // VS2015 specific build IDs
        case 0x8C50: return "link.exe";
        case 0x8C51: return "cvtres.exe";
        case 0x8C52: return "rc.exe";
        case 0x8C53: return "cl.exe";
        
        // VS2017 specific build IDs (VS 15.x)
        case 0x9198: return "link.exe";
        case 0x9199: return "cvtres.exe";
        case 0x919A: return "rc.exe";
        case 0x919B: return "cl.exe";
        
        // VS2019 specific build IDs (VS 16.x)
        case 0x9648: return "link.exe";
        case 0x9649: return "cvtres.exe";
        case 0x964A: return "rc.exe";
        case 0x964B: return "cl.exe";
        
        // VS2022 specific build IDs (VS 17.x)
        case 0x9B58: return "link.exe";
        case 0x9B59: return "cvtres.exe";
        case 0x9B5A: return "rc.exe";
        case 0x9B5B: return "cl.exe";
        
        default:
            // Try to identify tool by build ID ranges
            if (id >= 0x7864 && id <= 0x786F) return "VS2008 Tool";
            if (id >= 0x7D1C && id <= 0x7D2F) return "VS2010 Tool";
            if (id >= 0x82AC && id <= 0x82BF) return "VS2012 Tool";
            if (id >= 0x8754 && id <= 0x876F) return "VS2013 Tool";
            if (id >= 0x8C50 && id <= 0x8C6F) return "VS2015 Tool";
            if (id >= 0x9198 && id <= 0x91FF) return "VS2017 Tool";
            if (id >= 0x9648 && id <= 0x96FF) return "VS2019 Tool";
            if (id >= 0x9B58 && id <= 0x9BFF) return "VS2022 Tool";
            if (id >= 0x0014 && id <= 0x001F) return "Build Tool";
            return "Unknown Tool";
    }
}

} // namespace dlltools
