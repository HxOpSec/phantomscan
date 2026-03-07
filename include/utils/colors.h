#pragma once
#include <string>

namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string BOLD    = "\033[1m";
    const std::string WHITE   = "\033[37m";

    const std::string OK   = "\033[32m[+]\033[0m ";
    const std::string FAIL = "\033[31m[-]\033[0m ";
    const std::string INFO = "\033[36m[*]\033[0m ";
    const std::string WARN = "\033[33m[!]\033[0m ";
    const std::string SCAN = "\033[35m[~]\033[0m ";
}