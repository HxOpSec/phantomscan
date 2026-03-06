#include "modules/os_detect.h"
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

// Выполняет команду и возвращает вывод
static std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Получаем TTL через ping
int OSDetector::get_ttl(const std::string& ip) {
    // Отправляем 1 пинг и читаем TTL
    std::string cmd = "ping -c 1 -W 2 " + ip + " 2>/dev/null";
    std::string output = exec(cmd.c_str());

    // Ищем "ttl=" в выводе
    size_t pos = output.find("ttl=");
    if (pos == std::string::npos) {
        pos = output.find("TTL=");
    }

    if (pos == std::string::npos) return -1; // Не нашли

    // Читаем число после "ttl="
    pos += 4;
    std::string ttl_str;
    while (pos < output.size() && isdigit(output[pos])) {
        ttl_str += output[pos++];
    }

    if (ttl_str.empty()) return -1;
    return std::stoi(ttl_str);
}

// Определяем ОС по TTL
std::string OSDetector::ttl_to_os(int ttl) {
    if (ttl <= 0)   return "Недоступен";
    if (ttl <= 64)  return "Linux / macOS";
    if (ttl <= 128) return "Windows";
    if (ttl <= 255) return "Cisco / Network Device";
    return "Unknown";
}

// Главная функция
std::string OSDetector::detect(const std::string& ip) {
    int ttl = get_ttl(ip);

    if (ttl < 0) {
        return "Недоступен (нет ответа)";
    }

    std::string os = ttl_to_os(ttl);
    return os + " (TTL=" + std::to_string(ttl) + ")";
}