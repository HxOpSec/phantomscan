#pragma once
#include <string>
#include <vector>

// Результат одного поддомена
struct SubdomainResult {
    std::string subdomain;  // Полное имя (www.example.com)
    std::string ip;         // IP адрес
};

class SubdomainEnum {
public:
    // Главная функция — ищем поддомены
    std::vector<SubdomainResult> enumerate(const std::string& domain);

private:
    // Проверяет один поддомен — существует ли он
    bool check_subdomain(const std::string& subdomain, std::string& ip);

    // Встроенный список популярных поддоменов
    std::vector<std::string> get_wordlist();
};