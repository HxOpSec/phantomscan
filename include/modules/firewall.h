#pragma once
#include <string>

// Результат проверки фаервола
struct FirewallResult {
    bool detected;        // Обнаружен ли фаервол
    std::string status;   // Описание статуса
    int tested_port;      // Какой порт тестировали
};

class FirewallDetector {
public:
    // Главная функция — проверяем цель
    FirewallResult detect(const std::string& ip);

private:
    // Проверяет один порт и возвращает статус
    // 0 = открыт, 1 = закрыт (RST), 2 = фильтруется (нет ответа)
    int probe_port(const std::string& ip, int port, int timeout_sec);
};