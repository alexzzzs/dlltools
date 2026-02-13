#pragma once

#include "cli/cli_parser.hpp"
#include "core/pe_parser.hpp"

namespace dlltools::cli {

/// Command executor - runs parsed commands
class CommandExecutor {
public:
    /// Execute a parsed command
    /// @param cmd Command to execute
    /// @return Exit code (0 for success, non-zero for error)
    int execute(const Command& cmd);
    
private:
    /// Execute inspect command
    int cmd_inspect(const Command& cmd);
    
    /// Execute headers command
    int cmd_headers(const Command& cmd);
    
    /// Execute sections command
    int cmd_sections(const Command& cmd);
    
    /// Execute imports command
    int cmd_imports(const Command& cmd);
    
    /// Execute exports command
    int cmd_exports(const Command& cmd);
    
    /// Execute entropy command
    int cmd_entropy(const Command& cmd);
    
    /// Execute security command
    int cmd_security(const Command& cmd);
    
    /// Execute resources command
    int cmd_resources(const Command& cmd);
    
    /// Print error message
    void print_error(const Error& error);
};

} // namespace dlltools::cli
