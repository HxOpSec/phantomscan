#include "modules/wordlist.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>

// FIX: getaddrinfo вместо gethostbyname
static std::string resolve_ip(const std::string& host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return "";

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,
              &((struct sockaddr_in*)res->ai_addr)->sin_addr,
              buf, sizeof(buf));
    freeaddrinfo(res);
    return std::string(buf);
}

std::vector<std::string> WordlistGenerator::generate(
        const std::string& domain) {

    std::vector<std::string> found;

    // Вытаскиваем базовое имя домена
    // scanme.nmap.org → "scanme", google.com → "google"
    std::string base = domain;
    size_t dot = domain.find('.');
    if (dot != std::string::npos)
        base = domain.substr(0, dot);

    // Генерируем вариации на основе имени домена
    std::vector<std::string> extra = {
        base + "-dev",     base + "-test",
        base + "-api",     base + "-admin",
        base + "-portal",  base + "-staging",
        base + "-old",     base + "-new",
        base + "-backup",  base + "-secure",
        base + "-prod",    base + "-beta",
        base + "-app",     base + "-web",
        base + "-vpn",     base + "-mail",
        base + "-db",      base + "-cdn",
        base + "-static",  base + "-media",
        "dev-"  + base,    "test-" + base,
        "api-"  + base,    "old-"  + base,
        "app-"  + base,    "web-"  + base,
    };

    // Объединяем base_words + extra
    std::vector<std::string> all_words = base_words;
    for (auto& e : extra) all_words.push_back(e);

    std::cout << Color::INFO << "Генерируем wordlist для: "
              << Color::CYAN << domain << Color::RESET << "\n";
    std::cout << Color::INFO << "Проверяем "
              << all_words.size() << " вариантов...\n"
              << Color::RESET;

    // Проверяем каждый через DNS
    for (const auto& word : all_words) {
        std::string full = word + "." + domain;
        std::string ip   = resolve_ip(full);

        if (!ip.empty()) {
            found.push_back(full + " → " + ip);
            std::cout << Color::OK << "Найден: " << Color::CYAN
                      << full << Color::RESET
                      << " → " << Color::YELLOW << ip
                      << Color::RESET << "\n";
        }
    }

    return found;
}

void WordlistGenerator::save_to_file(
        const std::vector<std::string>& words,
        const std::string& filename) {

    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cout << Color::FAIL << "Не удалось сохранить файл!\n"
                  << Color::RESET;
        return;
    }

    for (const auto& w : words) f << w << "\n";
    f.close();

    std::cout << Color::OK << "Wordlist сохранён: "
              << Color::CYAN << filename << Color::RESET << "\n";
}

void WordlistGenerator::print_results(
        const std::vector<std::string>& found) {

    if (found.empty()) {
        std::cout << Color::WARN
                  << "[!] Поддомены не найдены\n"
                  << Color::RESET;
        return;
    }

    std::cout << "\n" << Color::CYAN
              << "╔══════════════════════════════════════════════════╗\n"
              << "║           НАЙДЕННЫЕ ПОДДОМЕНЫ                    ║\n"
              << "╠══════════════════════════════════════════════════╣\n"
              << Color::RESET;

    for (const auto& w : found) {
        std::string s = w;
        if ((int)s.size() > 48) s = s.substr(0, 45) + "...";
        while ((int)s.size() < 48) s += " ";

        std::cout << Color::GREEN << "║ " << s << " ║\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN
              << "╚══════════════════════════════════════════════════╝\n"
              << Color::RESET;
    std::cout << Color::INFO << "Найдено: " << Color::GREEN
              << found.size() << Color::RESET << "\n";
}
