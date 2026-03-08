#include "modules/shodan.h"
#include "utils/colors.h"
#include <iostream>
#include <sstream>
#include <cstdio>

std::string ShodanAPI::fetch(const std::string& url) {
    std::string cmd = "curl -s -m 10 \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";

    std::string result = "";
    char line[1024];
    while (fgets(line, sizeof(line), pipe))
        result += std::string(line);
    pclose(pipe);
    return result;
}

void ShodanAPI::set_api_key(const std::string& key) {
    api_key = key;
}

ShodanResult ShodanAPI::lookup(const std::string& ip) {
    ShodanResult result;
    result.ip = ip;

    if (api_key.empty()) {
        std::cout << Color::FAIL << "API ключ не установлен!"
                  << Color::RESET << std::endl;
        return result;
    }

    std::cout << Color::INFO << "Shodan поиск: "
              << Color::CYAN << ip
              << Color::RESET << std::endl;

    // Запрос к Shodan API
    std::string url = "https://api.shodan.io/shodan/host/"
                    + ip + "?key=" + api_key;

    std::string response = fetch(url);

    if (response.empty() || 
        response.find("error") != std::string::npos) {
        std::cout << Color::FAIL
                  << "Ошибка Shodan API! Проверь ключ."
                  << Color::RESET << std::endl;
        return result;
    }

    // Простой JSON парсинг без библиотек
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = response.find(search);
        if (pos == std::string::npos) return "Неизвестно";
        pos += search.size();
        size_t end = response.find("\"", pos);
        if (end == std::string::npos) return "Неизвестно";
        return response.substr(pos, end - pos);
    };

    auto extract_num = [&](const std::string& key) 
                           -> std::string {
        std::string search = "\"" + key + "\":";
        size_t pos = response.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        size_t end = response.find_first_of(",}", pos);
        if (end == std::string::npos) return "";
        return response.substr(pos, end - pos);
    };

    result.org     = extract("org");
    result.country = extract("country_name");
    result.os      = extract("os");

    // Парсим порты из массива
    size_t ports_pos = response.find("\"ports\":[");
    if (ports_pos != std::string::npos) {
        ports_pos += 9;
        size_t ports_end = response.find("]", ports_pos);
        std::string ports_str = response.substr(
            ports_pos, ports_end - ports_pos);

        std::istringstream iss(ports_str);
        std::string token;
        while (std::getline(iss, token, ',')) {
            try {
                result.ports.push_back(std::stoi(token));
            } catch (...) {}
        }
    }

    // Парсим уязвимости
    size_t vuln_pos = response.find("\"vulns\":{");
    if (vuln_pos != std::string::npos) {
        vuln_pos += 9;
        size_t vuln_end = response.find("}", vuln_pos);
        std::string vuln_str = response.substr(
            vuln_pos, vuln_end - vuln_pos);

        // Ищем CVE-XXXX-XXXX паттерны
        size_t p = 0;
        while ((p = vuln_str.find("CVE-", p)) 
               != std::string::npos) {
            size_t end = vuln_str.find("\"", p);
            if (end != std::string::npos)
                result.vulns.push_back(
                    vuln_str.substr(p, end - p));
            p += 4;
        }
    }

    return result;
}

void ShodanAPI::print_results(const ShodanResult& result) {
    if (result.org.empty()) return;

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────────┐\n";
    std::cout << "│              SHODAN РЕЗУЛЬТАТ               │\n";
    std::cout << "├─────────────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    auto pad = [](std::string s, int n) {
        if ((int)s.size() > n) s = s.substr(0, n-3) + "...";
        while ((int)s.size() < n) s += " ";
        return s;
    };

    std::cout << Color::INFO;
    std::cout << "│ IP      : " << pad(result.ip,      35) << " │\n";
    std::cout << "│ Орг     : " << pad(result.org,     35) << " │\n";
    std::cout << "│ Страна  : " << pad(result.country, 35) << " │\n";
    std::cout << "│ ОС      : " << pad(result.os,      35) << " │\n";
    std::cout << Color::RESET;

    // Порты
    if (!result.ports.empty()) {
        std::string ports_str = "";
        for (int p : result.ports)
            ports_str += std::to_string(p) + " ";
        std::cout << Color::WARN;
        std::cout << "│ Порты   : " << pad(ports_str, 35) << " │\n";
        std::cout << Color::RESET;
    }

    // CVE
    if (!result.vulns.empty()) {
        std::cout << Color::FAIL;
        std::cout << "├─────────────────────────────────────────────┤\n";
        std::cout << "│ УЯЗВИМОСТИ:                                 │\n";
        for (const auto& v : result.vulns) {
            std::cout << "│  ⚠  " << pad(v, 39) << " │\n";
        }
        std::cout << Color::RESET;
    } else {
        std::cout << Color::OK;
        std::cout << "│ CVE     : Не найдено                        │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└─────────────────────────────────────────────┘\n";
    std::cout << Color::RESET;
}