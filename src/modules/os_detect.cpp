#include "modules/os_detect.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <memory>
#include <string>
#include <array>

// FIX: lambda вместо &pclose — убирает warning ignored-attributes
static std::string exec(const char* cmd) {
    std::array<char, 256> buffer;
    std::string result;
    // Используем lambda как deleter — компилятор не ругается
    auto closer = [](FILE* f) { if (f) pclose(f); };
    std::unique_ptr<FILE, decltype(closer)> pipe(popen(cmd, "r"), closer);
    if (!pipe) return "";
    while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        result += buffer.data();
    return result;
}

// ── Получаем TTL через ping ───────────────────────────
int OSDetector::get_ttl(const std::string& ip) {
    std::string cmd    = "ping -c 1 -W 2 " + ip + " 2>/dev/null";
    std::string output = exec(cmd.c_str());

    // Ищем ttl= или TTL=
    size_t pos = output.find("ttl=");
    if (pos == std::string::npos)
        pos = output.find("TTL=");
    if (pos == std::string::npos) return -1;

    pos += 4;
    std::string ttl_str;
    while (pos < output.size() && isdigit(output[pos]))
        ttl_str += output[pos++];

    if (ttl_str.empty()) return -1;
    try { return std::stoi(ttl_str); } catch (...) { return -1; }
}

// ── Определяем ОС по TTL ─────────────────────────────
std::string OSDetector::ttl_to_os(int ttl) {
    if (ttl <= 0)   return "Недоступен";
    if (ttl <= 64)  return "Linux / macOS";
    if (ttl <= 128) return "Windows";
    if (ttl <= 255) return "Cisco / Network Device";
    return "Unknown";
}

// ── Улучшенное определение по баннеру ────────────────
static std::string banner_detect(const std::string& ip) {
    // Пробуем прочитать SSH баннер (порт 22)
    std::string cmd = "timeout 2 bash -c 'echo | nc -w1 "
                    + ip + " 22 2>/dev/null' | head -1";
    std::string out = exec(cmd.c_str());

    if (out.find("Ubuntu")  != std::string::npos) return "Ubuntu Linux";
    if (out.find("Debian")  != std::string::npos) return "Debian Linux";
    if (out.find("CentOS")  != std::string::npos) return "CentOS Linux";
    if (out.find("FreeBSD") != std::string::npos) return "FreeBSD";
    if (out.find("OpenSSH") != std::string::npos) return "Linux (OpenSSH)";
    if (out.find("Windows") != std::string::npos) return "Windows";
    return "";
}

// ── Главная функция ───────────────────────────────────
std::string OSDetector::detect(const std::string& ip) {
    // Сначала пробуем по баннеру — точнее
    std::string banner = banner_detect(ip);
    if (!banner.empty()) return banner;

    // Иначе по TTL
    int ttl = get_ttl(ip);
    if (ttl < 0) return "Недоступен (нет ответа)";

    return ttl_to_os(ttl) + " (TTL=" + std::to_string(ttl) + ")";
}