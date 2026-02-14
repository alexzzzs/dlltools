# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Rich Header parsing for PE files (Microsoft compilation metadata)
  - Located after DOS header, contains tool IDs and checksums
  - Used for anti-tamper detection and build environment identification
  - Supports Visual Studio tool ID lookup (VS2003-VS2022)
  - CLI command: `dlltools rich <file>`

### Changed
- Refactored PEFile accessor methods to reduce code duplication
- Optimized RVA-to-offset conversion logic
- Fixed union initialization for MSVC compatibility

## [0.1.0] - 2026-02-13

### Added
- Initial release of dlltools
- PE file parsing with support for PE32 and PE32+ formats
- DOS and NT header inspection
- Section table parsing with characteristics decoding
- Import table parsing (by-name and by-ordinal imports)
- Export table parsing with forwarded export detection
- Shannon entropy calculation for sections
- Security feature detection (ASLR, DEP, CFG, SafeSEH)
- Resource directory enumeration
- CLI with multiple output formats (text, JSON, raw)
- Coloured terminal output support
- Filter option for imports/exports commands
- Memory-mapped file I/O for efficient large file handling
- Error handling with `std::expected`
- Unit test suite using Catch2

### Commands
- `inspect` - Overview of PE file
- `headers` - Display PE headers
- `sections` - Display section table
- `imports` - Display import table
- `exports` - Display export table
- `entropy` - Calculate section entropy
- `security` - Analyze security features
- `resources` - Enumerate resources

### Technical Details
- Built with C++23 (requires MSVC 2022 v19.34+)
- Uses `std::expected` for error handling
- Bounds-checked RVA conversions for safety

