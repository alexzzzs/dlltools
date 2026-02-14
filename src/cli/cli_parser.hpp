#pragma once

#include "core/error.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace dlltools::cli {

/// Command types
enum class CommandType {
    Inspect,    ///< Overview of PE file
    Headers,    ///< Full header dump
    Sections,   ///< Section table display
    Imports,    ///< Import table display
    Exports,    ///< Export table display
    Entropy,    ///< Entropy analysis
    Security,   ///< Security features display
    Resources,  ///< Resource enumeration
    Rich,       ///< Rich Header display
    Help,       ///< Show help
    Version     ///< Show version
};

/// Global CLI options
struct GlobalOptions {
    bool verbose = false;       ///< Verbose output
    bool json_output = false;   ///< JSON output format
    bool raw_output = false;    ///< Raw output format
    bool colour_output = false; ///< Colour output (auto-detect if not specified)
    std::filesystem::path input_file;  ///< Input file path
};

/// Parsed command
struct Command {
    CommandType type = CommandType::Help;
    GlobalOptions global;
    
    // Command-specific arguments
    uint32_t pid = 0;           ///< Process ID for live/modules commands
    std::string filter;         ///< Optional filter string
};

/// Parse command-line arguments
/// @param argc Argument count
/// @param argv Argument values
/// @return Result containing Command or Error
[[nodiscard]] Result<Command> parse_arguments(int argc, char* argv[]);

/// Get command name as string
/// @param type Command type
/// @return Command name string
[[nodiscard]] const char* command_name(CommandType type) noexcept;

/// Get usage string for a command
/// @param type Command type
/// @return Usage string
[[nodiscard]] const char* command_usage(CommandType type) noexcept;

/// Print help message
void print_help();

/// Print version information
void print_version();

} // namespace dlltools::cli
