#include "cli/commands.hpp"
#include "cli/output.hpp"
#include "core/section.hpp"
#include "core/import.hpp"
#include "core/export.hpp"
#include "core/resource.hpp"
#include "core/security.hpp"
#include "core/entropy.hpp"
#include "utils/string_utils.hpp"
#include <iostream>

namespace dlltools::cli {

int CommandExecutor::execute(const Command& cmd) {
    switch (cmd.type) {
        case CommandType::Inspect:
            return cmd_inspect(cmd);
            
        case CommandType::Headers:
            return cmd_headers(cmd);
            
        case CommandType::Sections:
            return cmd_sections(cmd);
            
        case CommandType::Imports:
            return cmd_imports(cmd);
            
        case CommandType::Exports:
            return cmd_exports(cmd);
            
        case CommandType::Entropy:
            return cmd_entropy(cmd);
            
        case CommandType::Security:
            return cmd_security(cmd);
            
        case CommandType::Resources:
            return cmd_resources(cmd);
            
        case CommandType::Help:
            print_help();
            return 0;
            
        case CommandType::Version:
            print_version();
            return 0;
            
        default:
            std::cerr << "Unknown command type\n";
            return 1;
    }
}

void CommandExecutor::print_error(const Error& error) {
    std::cerr << "Error: " << error.message << "\n";
    if (error.location.file_name()) {
        std::cerr << "  at " << error.location.file_name() 
                  << ":" << error.location.line() << "\n";
    }
}

int CommandExecutor::cmd_inspect(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, "", cmd.global.colour_output);
    formatter.print_inspect(pe);
    
    return 0;
}

int CommandExecutor::cmd_headers(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, "", cmd.global.colour_output);
    formatter.print_headers(pe);
    
    return 0;
}

int CommandExecutor::cmd_sections(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, "", cmd.global.colour_output);
    formatter.print_sections(pe.sections());
    
    return 0;
}

int CommandExecutor::cmd_imports(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    auto imports_result = pe.imports();
    if (!imports_result) {
        print_error(imports_result.error());
        return 1;
    }
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, cmd.filter, cmd.global.colour_output);
    formatter.print_imports(imports_result->get());
    
    return 0;
}

int CommandExecutor::cmd_exports(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    auto exports_result = pe.exports();
    if (!exports_result) {
        print_error(exports_result.error());
        return 1;
    }
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, cmd.filter, cmd.global.colour_output);
    formatter.print_exports(exports_result->get());
    
    return 0;
}

int CommandExecutor::cmd_entropy(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, "", cmd.global.colour_output);
    formatter.print_entropy(pe);
    
    return 0;
}

int CommandExecutor::cmd_security(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    auto features = pe.security_features();
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, "", cmd.global.colour_output);
    formatter.print_security(features);
    
    return 0;
}

int CommandExecutor::cmd_resources(const Command& cmd) {
    auto pe_result = PEParser::parse(cmd.global.input_file);
    if (!pe_result) {
        print_error(pe_result.error());
        return 1;
    }
    
    const auto& pe = *pe_result;
    
    auto resources_result = pe.resources();
    if (!resources_result) {
        print_error(resources_result.error());
        return 1;
    }
    
    const auto& resources = resources_result->get();
    
    OutputFormatter formatter(cmd.global.json_output, cmd.global.verbose, "", cmd.global.colour_output);
    formatter.print_resources(resources);
    
    return 0;
}

} // namespace dlltools::cli
