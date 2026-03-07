#include <vector>
#include "modules/whois.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <memory>
#include <string>
#include <array>

// Выполняем команду и читаем вывод
static std::string exec_cmd(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Получаем WHOIS через curl
WhoisResult Whois::lookup(const std::string& target) {
    WhoisResult result;
    result.ip = target;

    std::cout << Color::INFO << "Получаем WHOIS информацию..." << Color::RESET << std::endl;

    // Используем curl для запроса к ip-api.com
    std::string cmd = "curl -s 'http://ip-api.com/line/" + target + 
                      "?fields=country,city,org,isp' 2>/dev/null";
    std::string output = exec_cmd(cmd);

    if (output.empty()) {
        result.country = "Недоступно";
        result.city    = "Недоступно";
        result.org     = "Недоступно";
        result.isp     = "Недоступно";
        return result;
    }

    // Парсим строки ответа
    std::vector<std::string> lines;
    std::string line;
    for (char c : output) {
        if (c == '\n') {
            if (!line.empty()) lines.push_back(line);
            line.clear();
        } else {
            line += c;
        }
    }

    if (lines.size() >= 4) {
        result.country = lines[0];
        result.city    = lines[1];
        result.org     = lines[2];
        result.isp     = lines[3];
    }

    return result;
}