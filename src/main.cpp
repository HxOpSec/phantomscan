#include "modules/menu.h"
#include "utils/banner.h"
#include "utils/colors.h"
#include <iostream>
#include <string>
#include <cstring>
#include <climits>    // FIX: для INT_MAX
#include <stdexcept>  // FIX: для stoi исключений

// ── Константы ────────────────────────────────────────────
static const int PORT_MIN = 1;
static const int PORT_MAX = 65535;

void print_usage() {
    std::cout << Color::CYAN;
    std::cout << "Использование:\n";
    std::cout << "  phantomscan                           — интерактивное меню\n";
    std::cout << "  phantomscan -t <цель>                 — сканировать цель (порты 1-1024)\n";
    std::cout << "  phantomscan -t <цель> -p 1-1024       — указать диапазон портов\n";
    std::cout << "  phantomscan -t <цель> -o txt          — сохранить отчёт\n";
    std::cout << "  phantomscan -t <цель> -p 1-500 -o all — порты + все форматы\n\n";
    std::cout << "Форматы отчёта: txt | json | html | all\n";
    std::cout << Color::RESET;
}

// FIX: Безопасный парсер диапазона портов с валидацией
// Старый код: stoi без try/catch — падал при "-p abc" или "-p 99999-100000"
static bool parse_port_range(const std::string& range,
                              int& port_start, int& port_end) {
    try {
        size_t dash = range.find('-');
        if (dash != std::string::npos) {
            // Формат: "1-1024"
            port_start = std::stoi(range.substr(0, dash));
            port_end   = std::stoi(range.substr(dash + 1));
        } else {
            // Один порт: "80"
            port_start = port_end = std::stoi(range);
        }
    } catch (const std::exception&) {
        // stoi кидает invalid_argument или out_of_range
        std::cout << Color::FAIL
                  << "[-] Неверный формат портов: \"" << range << "\"\n"
                  << "    Пример правильного формата: -p 1-1024\n"
                  << Color::RESET;
        return false;
    }

    // Проверяем диапазон
    if (port_start < PORT_MIN || port_end > PORT_MAX) {
        std::cout << Color::FAIL
                  << "[-] Порты должны быть от " << PORT_MIN
                  << " до " << PORT_MAX << "\n"
                  << "    Вы указали: " << port_start << "-" << port_end << "\n"
                  << Color::RESET;
        return false;
    }

    if (port_start > port_end) {
        std::cout << Color::FAIL
                  << "[-] Начальный порт больше конечного: "
                  << port_start << " > " << port_end << "\n"
                  << Color::RESET;
        return false;
    }

    return true;
}

// FIX: Валидация формата отчёта
static bool valid_output(const std::string& output) {
    return output == "txt" || output == "json" ||
           output == "html" || output == "all";
}

int main(int argc, char* argv[]) {
    // Без аргументов — интерактивное меню
    if (argc == 1) {
        Menu menu;
        menu.run();
        return 0;
    }

    std::string target     = "";
    int         port_start = 1;
    int         port_end   = 1024;
    std::string output     = "all";

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target") == 0)
             && i + 1 < argc) {
            target = argv[++i];

        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--ports") == 0)
                    && i + 1 < argc) {
            if (!parse_port_range(argv[++i], port_start, port_end))
                return 1;

        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)
                    && i + 1 < argc) {
            output = argv[++i];
            // FIX: раньше неверный формат просто игнорировался
            if (!valid_output(output)) {
                std::cout << Color::FAIL
                          << "[-] Неверный формат отчёта: \"" << output << "\"\n"
                          << "    Доступно: txt | json | html | all\n"
                          << Color::RESET;
                return 1;
            }

        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_banner();
            print_usage();
            return 0;

        } else if (argv[i][0] == '-') {
            // FIX: теперь проверяем что это именно флаг (начинается с -)
            std::cout << Color::FAIL << "[-] Неизвестный флаг: " << argv[i]
                      << "\nИспользуй -h для справки\n" << Color::RESET;
            return 1;

        } else {
            // FIX: если аргумент без флага — подсказываем
            std::cout << Color::FAIL
                      << "[-] Неожиданный аргумент: \"" << argv[i] << "\"\n"
                      << "    Чтобы указать цель используй: -t " << argv[i] << "\n"
                      << Color::RESET;
            return 1;
        }
    }

    if (target.empty()) {
        std::cout << Color::FAIL
                  << "[-] Укажите цель: -t <IP или домен>\n"
                  << Color::RESET;
        print_usage();
        return 1;
    }

    Menu menu;
    menu.run_cli(target, port_start, port_end, output);
    return 0;
}







