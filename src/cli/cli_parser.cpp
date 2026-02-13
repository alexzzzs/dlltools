#include "cli/cli_parser.hpp"
#include <iostream>
#include <cstring>

namespace dlltools::cli {

namespace {

/// Check if string starts with prefix
bool starts_with(std::string_view str, std::string_view prefix) {
    return str.size() >= prefix.size() && 
           str.compare(0, prefix.size(), prefix) == 0;
}

/// Parse a number from string
std::optional<uint32_t> parse_number(std::string_view str) {
    if (str.empty()) {
        return std::nullopt;
    }
    
    try {
        size_t pos = 0;
        uint32_t value = 0;
        
        // Check for hex prefix
        if (starts_with(str, "0x") || starts_with(str, "0X")) {
            value = static_cast<uint32_t>(std::stoul(std::string(str), &pos, 16));
        } else {
            value = static_cast<uint32_t>(std::stoul(std::string(str), &pos, 10));
        }
        
        if (pos != str.size()) {
            return std::nullopt;
        }
        
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

} // anonymous namespace

Result<Command> parse_arguments(int argc, char* argv[]) {
    Command cmd;
    cmd.type = CommandType::Help;
    
    if (argc < 2) {
        return cmd;  // Show help
    }
    
    std::string_view arg1 = argv[1];
    
    // Parse command
    if (arg1 == "inspect") {
        cmd.type = CommandType::Inspect;
    } else if (arg1 == "headers") {
        cmd.type = CommandType::Headers;
    } else if (arg1 == "sections") {
        cmd.type = CommandType::Sections;
    } else if (arg1 == "imports") {
        cmd.type = CommandType::Imports;
    } else if (arg1 == "exports") {
        cmd.type = CommandType::Exports;
    } else if (arg1 == "entropy") {
        cmd.type = CommandType::Entropy;
    } else if (arg1 == "security") {
        cmd.type = CommandType::Security;
    } else if (arg1 == "resources") {
        cmd.type = CommandType::Resources;
    } else if (arg1 == "help" || arg1 == "--help" || arg1 == "-h") {
        cmd.type = CommandType::Help;
        return cmd;
    } else if (arg1 == "version" || arg1 == "--version" || arg1 == "-v") {
        cmd.type = CommandType::Version;
        return cmd;
    } else {
        return std::unexpected(Error::unknown_command(std::string(arg1)));
    }
    
    // Parse remaining arguments
    for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        
        if (arg == "--verbose" || arg == "-V") {
            cmd.global.verbose = true;
        } else if (arg == "--json") {
            cmd.global.json_output = true;
        } else if (arg == "--raw") {
            cmd.global.raw_output = true;
        } else if (arg == "--colour" || arg == "--color") {
            cmd.global.colour_output = true;
        } else if (arg == "--no-colour" || arg == "--no-color") {
            cmd.global.colour_output = false;
        } else if (starts_with(arg, "--pid=")) {
            auto pid_str = arg.substr(6);
            auto pid = parse_number(pid_str);
            if (!pid) {
                return std::unexpected(Error::invalid_argument(
                    std::string(arg),
                    "Invalid PID format"
                ));
            }
            cmd.pid = *pid;
        } else if (arg == "--pid" && i + 1 < argc) {
            auto pid = parse_number(argv[++i]);
            if (!pid) {
                return std::unexpected(Error::invalid_argument(
                    argv[i],
                    "Invalid PID format"
                ));
            }
            cmd.pid = *pid;
        } else if (starts_with(arg, "--filter=")) {
            cmd.filter = std::string(arg.substr(9));
        } else if (!starts_with(arg, "-")) {
            // Positional argument - input file
            if (cmd.global.input_file.empty()) {
                cmd.global.input_file = arg;
            }
        } else {
            return std::unexpected(Error::invalid_argument(
                std::string(arg),
                "Unknown option"
            ));
        }
    }
    
    // Validate required arguments
    switch (cmd.type) {
        case CommandType::Inspect:
        case CommandType::Headers:
        case CommandType::Sections:
        case CommandType::Imports:
        case CommandType::Exports:
        case CommandType::Entropy:
        case CommandType::Security:
        case CommandType::Resources:
            if (cmd.global.input_file.empty()) {
                return std::unexpected(Error::missing_argument("file"));
            }
            break;
            
        default:
            break;
    }
    
    return cmd;
}

const char* command_name(CommandType type) noexcept {
    switch (type) {
        case CommandType::Inspect:   return "inspect";
        case CommandType::Headers:   return "headers";
        case CommandType::Sections:  return "sections";
        case CommandType::Imports:   return "imports";
        case CommandType::Exports:   return "exports";
        case CommandType::Entropy:   return "entropy";
        case CommandType::Security:  return "security";
        case CommandType::Resources: return "resources";
        case CommandType::Help:      return "help";
        case CommandType::Version:   return "version";
        default:                     return "unknown";
    }
}

const char* command_usage(CommandType type) noexcept {
    switch (type) {
        case CommandType::Inspect:   return "dlltools inspect <file> [--json] [--verbose]";
        case CommandType::Headers:   return "dlltools headers <file> [--json] [--raw]";
        case CommandType::Sections:  return "dlltools sections <file> [--json] [--verbose]";
        case CommandType::Imports:   return "dlltools imports <file> [--json] [--filter=<name>]";
        case CommandType::Exports:   return "dlltools exports <file> [--json] [--filter=<name>]";
        case CommandType::Entropy:   return "dlltools entropy <file> [--json]";
        case CommandType::Security:  return "dlltools security <file> [--json]";
        case CommandType::Resources: return "dlltools resources <file> [--json]";
        case CommandType::Help:      return "dlltools help [command]";
        case CommandType::Version:   return "dlltools version";
        default:                     return "dlltools <command> [options]";
    }
}

void print_help() {
    std::cout << R"(dlltools - Windows DLL Inspection & Analysis Toolkit v0.1

USAGE:
    dlltools <command> [options]

COMMANDS:
    inspect    Overview of PE file
    headers    Display PE headers
    sections   Display section table
    imports    Display import table
    exports    Display export table
    entropy    Calculate section entropy
    security   Analyze security features
    resources  Enumerate resources

GLOBAL OPTIONS:
    --json         Output in JSON format
    --raw          Output raw values
    --verbose      Verbose output
    --colour       Enable coloured output
    --no-colour    Disable coloured output
    --help, -h     Show this help message
    --version      Show version

FILTERING:
    --filter=<pattern>   Filter imports/exports by name (substring match)

EXAMPLES:
    dlltools inspect kernel32.dll
    dlltools imports --json myapp.exe
    dlltools imports myapp.exe --filter=CreateFile
    dlltools exports mylib.dll --filter=init

For more information about a command:
    dlltools help <command>
)";
}

void print_version() {
    std::cout << "dlltools v0.1.0\n";
    std::cout << "Windows DLL Inspection & Analysis Toolkit\n";
    std::cout << "Built with " << _MSC_VER << " (MSVC)\n";
}

} // namespace dlltools::cli
