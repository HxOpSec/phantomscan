#pragma once                  // Защита от двойного подключения
#include <string>             // Для работы со строками
#include <vector>             // Для работы со списками

// Структура — результат сканирования одного порта
struct PortResult {
    int port;          // Номер порта (например 80)
    bool is_open;      // Открыт или закрыт
    std::string service; // Название службы (HTTP, SSH...)
    std::string version; // Версия/баннер службы
};

// Класс Scanner — наш сканер портов
class Scanner {
public:
    // Конструктор — принимает IP адрес цели
    Scanner(const std::string& target_ip);

    // Главная функция — сканирует диапазон портов
    std::vector<PortResult> scan(int start_port, int end_port);

private:
    std::string target_ip;  // IP адрес цели

    // Проверяет один порт — открыт или нет
    bool check_port(int port);
};
