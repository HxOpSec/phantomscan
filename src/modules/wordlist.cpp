#include "modules/wordlist.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <netdb.h>
#include <arpa/inet.h>

std::vector<std::string> WordlistGenerator::generate(
        const std::string& domain) {

    std::vector<std::string> found;

    std::cout << Color::INFO << "Генерируем wordlist для: "
              << Color::CYAN << domain << Color::RESET << std::endl;
    std::cout << Color::INFO << "Проверяем "
              << base_words.size() << " вариантов..."
              << Color::RESET << std::endl;

    // Добавляем вариации на основе домена
    // Например для "google.com" → "google-dev", "google-api" и т.д.
    std::string base = domain;
    size_t dot = domain.find('.');
    if (dot != std::string::npos)
        base = domain.substr(0, dot);

    std::vector<std::string> extra = {
        base + "-dev",    base + "-test",
        base + "-api",    base + "-admin",
        base + "-portal", base + "-staging",
        base + "-old",    base + "-new",
        base + "-backup", base + "-secure",
        "dev-"  + base,   "test-" + base,
        "api-"  + base,   "old-"  + base,
    };

    // Объединяем base_words + extra
    std::vector<std::string> all_words = base_words;
    for (auto& e : extra) all_words.push_back(e);

    // Проверяем каждый через DNS
    for (const auto& word : all_words) {
        std::string full = word + "." + domain;

        struct hostent* h = gethostbyname(full.c_str());
        if (h) {
            std::string ip = inet_ntoa(
                *(struct in_addr*)h->h_addr_list[0]);

            found.push_back(full);
            std::cout << Color::OK << "Найден: " << Color::CYAN
                      << full << Color::RESET
                      << " → " << Color::GREEN << ip
                      << Color::RESET << std::endl;
        }
    }

    return found;
}

void WordlistGenerator::save_to_file(
        const std::vector<std::string>& words,
        const std::string& filename) {

    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cout << Color::FAIL << "Не удалось сохранить файл!"
                  << Color::RESET << std::endl;
        return;
    }

    for (const auto& w : words) f << w << "\n";
    f.close();

    std::cout << Color::OK << "Wordlist сохранён: "
              << Color::CYAN << filename
              << Color::RESET << std::endl;
}

void WordlistGenerator::print_results(
        const std::vector<std::string>& found) {

    if (found.empty()) {
        std::cout << Color::WARN << "Поддомены не найдены"
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────────┐\n";
    std::cout << "│           НАЙДЕННЫЕ ПОДДОМЕНЫ               │\n";
    std::cout << "├─────────────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& w : found) {
        std::string s = w;
        if (s.size() > 43) s = s.substr(0, 40) + "...";
        while (s.size() < 43) s += " ";

        std::cout << Color::OK;
        std::cout << "│ " << s << " │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└─────────────────────────────────────────────┘\n";
    std::cout << Color::RESET;
    std::cout << Color::INFO << "Найдено поддоменов: "
              << Color::GREEN << found.size()
              << Color::RESET << std::endl;
}