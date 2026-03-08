#include "utils/banner.h"
#include "utils/colors.h"
#include <iostream>

void print_banner() {
    std::cout << Color::CYAN << Color::BOLD;
    std::cout << R"(
██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
)" << Color::RESET;

    std::cout << Color::YELLOW << Color::BOLD;
    std::cout << "              Network Scanner v1.0  |  by UMEDJON\n";
    std::cout << Color::RESET;
    std::cout << Color::WHITE;
    std::cout << "──────────────────────────────────────────────────────────\n";
    std::cout << Color::RESET << std::endl;
}

void print_usage(const char* program) {
    std::cout << Color::INFO << "Использование:\n";
    std::cout << Color::CYAN << "  " << program << " <IP или домен>\n";
    std::cout << Color::CYAN << "  " << program << " google.com\n";
    std::cout << Color::CYAN << "  " << program << " 192.168.1.1\n";
    std::cout << Color::RESET << std::endl;
}