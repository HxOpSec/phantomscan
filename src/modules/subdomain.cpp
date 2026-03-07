#include "modules/subdomain.h"
#include <iostream>
#include <netdb.h>        // Для gethostbyname()
#include <arpa/inet.h>    // Для inet_ntoa()
#include <cstring>

// Встроенный список популярных поддоменов
std::vector<std::string> SubdomainEnum::get_wordlist() {
    return {
        "www", "mail", "ftp", "admin", "dev",
        "test", "api", "blog", "shop", "secure",
        "vpn", "remote", "portal", "mx", "smtp",
        "pop", "imap", "ns1", "ns2", "cdn",
        "staging", "beta", "app", "mobile", "m"
    };
}

// Проверяем один поддомен через DNS
bool SubdomainEnum::check_subdomain(const std::string& subdomain, std::string& ip) {
    struct hostent* host = gethostbyname(subdomain.c_str());

    if (host == nullptr) return false;

    // Получаем IP адрес
    struct in_addr* addr = (struct in_addr*)host->h_addr_list[0];
    ip = inet_ntoa(*addr);
    return true;
}

// Главная функция — перебираем поддомены
std::vector<SubdomainResult> SubdomainEnum::enumerate(const std::string& domain) {
    std::vector<SubdomainResult> results;
    std::vector<std::string> wordlist = get_wordlist();

    std::cout << "[*] Ищем поддомены для: " << domain << std::endl;
    std::cout << "[*] Проверяем " << wordlist.size() << " вариантов..." << std::endl;

    for (const std::string& word : wordlist) {
        std::string full = word + "." + domain;
        std::string ip;

        if (check_subdomain(full, ip)) {
            SubdomainResult result;
            result.subdomain = full;
            result.ip = ip;
            results.push_back(result);

            std::cout << "[+] Найден: " << full
                      << " → " << ip << std::endl;
        }
    }

    return results;
}