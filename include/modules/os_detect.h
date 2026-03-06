#pragma once
#include <string>

class OSDetector {
public:
    // Главная функция — определяет ОС по IP
    std::string detect(const std::string& ip);

private:
    // Получает TTL от цели
    int get_ttl(const std::string& ip);

    // Определяет ОС по значению TTL
    std::string ttl_to_os(int ttl);
};