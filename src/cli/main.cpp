#include "cli/cli_parser.hpp"
#include "cli/commands.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    // Parse command line arguments
    auto cmd_result = dlltools::cli::parse_arguments(argc, argv);
    
    if (!cmd_result) {
        const auto& error = cmd_result.error();
        std::cerr << "Error: " << error.message << "\n";
        return static_cast<int>(error.category);
    }
    
    const auto& cmd = *cmd_result;
    
    // Execute command
    dlltools::cli::CommandExecutor executor;
    return executor.execute(cmd);
}
