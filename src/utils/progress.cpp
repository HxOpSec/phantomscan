#include "utils/progress.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>

void print_table(const std::vector<PortResult>& results) {
    if (results.empty()) {
        std::cout << Color::WARN << "Открытых портов не найдено" 
                  << Color::RESET << std::endl;
        return;
    }

    // Шапка таблицы
    std::cout << Color::BOLD << Color::CYAN;
    std::cout << "┌──────────┬─────────────────────────────┐\n";
    std::cout << "│   ПОРТ   │         СЛУЖБА              │\n";
    std::cout << "├──────────┼─────────────────────────────┤\n";
    std::cout << Color::RESET;

    // Строки таблицы
    for (const auto& r : results) {
        std::cout << Color::CYAN << "│" << Color::RESET;
        std::cout << Color::GREEN << "  " << std::setw(6) << r.port << "  " << Color::RESET;
        std::cout << Color::CYAN << "│" << Color::RESET;
        std::cout << Color::YELLOW << "  " << std::setw(27) << std::left 
                  << r.service << Color::RESET;
        std::cout << Color::CYAN << "│\n" << Color::RESET;
    }

    // Подвал таблицы
    std::cout << Color::CYAN << Color::BOLD;
    std::cout << "└──────────┴─────────────────────────────┘\n";
    std::cout << Color::RESET;
}

void print_summary(const std::string& target, const std::string& os,
                   int open_ports, int total_sec) {
    std::cout << std::endl;
    std::cout << Color::BOLD << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────┐\n";
    std::cout << "│              ИТОГ СКАНИРОВАНИЯ          │\n";
    std::cout << "├─────────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    std::cout << Color::CYAN << "│ " << Color::RESET;
    std::cout << Color::WHITE << "Цель     : " << Color::YELLOW 
              << std::setw(29) << std::left << target << Color::CYAN << "│\n" << Color::RESET;

    std::cout << Color::CYAN << "│ " << Color::RESET;
    std::cout << Color::WHITE << "ОС       : " << Color::YELLOW 
              << std::setw(29) << std::left << os << Color::CYAN << "│\n" << Color::RESET;

    std::cout << Color::CYAN << "│ " << Color::RESET;
    std::cout << Color::WHITE << "Портов   : " << Color::GREEN 
              << std::setw(29) << std::left << open_ports << Color::CYAN << "│\n" << Color::RESET;

    std::cout << Color::CYAN << "│ " << Color::RESET;
    std::cout << Color::WHITE << "Время    : " << Color::GREEN 
              << std::setw(26) << std::left << (std::to_string(total_sec) + " сек") 
              << Color::CYAN << "│\n" << Color::RESET;

    std::cout << Color::BOLD << Color::CYAN;
    std::cout << "└─────────────────────────────────────────┘\n";
    std::cout << Color::RESET << std::endl;
}