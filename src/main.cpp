#include "modules/menu.h"
#include "utils/banner.h"
#include "utils/colors.h"
#include <iostream>
#include <string>
#include <cstring>

void print_usage() {
    std::cout << Color::CYAN;
    std::cout << "Использование:\n";
    std::cout << "  phantomscan                        — интерактивное меню\n";
    std::cout << "  phantomscan -t <цель>              — сканировать цель\n";
    std::cout << "  phantomscan -t <цель> -p 1-1024    — указать диапазон портов\n";
    std::cout << "  phantomscan -t <цель> -o txt       — сохранить отчёт (txt/json/html)\n";
    std::cout << "  phantomscan -t <цель> -p 1-500 -o html\n";
    std::cout << Color::RESET;
}

int main(int argc, char* argv[]) {
    // Без аргументов — интерактивное меню
    if (argc == 1) {
        Menu menu;
        menu.run();
        return 0;
    }

    // Парсим аргументы
    std::string target = "";
    int port_start = 1;
    int port_end = 1024;
    std::string output = "all"; // all = txt+json+html

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            // Парсим "1-1024"
            std::string range = argv[++i];
            size_t dash = range.find('-');
            if (dash != std::string::npos) {
                port_start = std::stoi(range.substr(0, dash));
                port_end   = std::stoi(range.substr(dash + 1));
            } else {
                port_start = port_end = std::stoi(range);
            }
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || 
                   strcmp(argv[i], "--help") == 0) {
            print_banner();
            print_usage();
            return 0;
        } else {
            std::cout << Color::FAIL << "Неизвестный аргумент: " 
                      << argv[i] << Color::RESET << std::endl;
            print_usage();
            return 1;
        }
    }

    if (target.empty()) {
        std::cout << Color::FAIL << "Укажите цель: -t <IP или домен>" 
                  << Color::RESET << std::endl;
        print_usage();
        return 1;
    }

    // Запускаем сканирование с аргументами
    Menu menu;
    menu.run_cli(target, port_start, port_end, output);
    return 0;
}