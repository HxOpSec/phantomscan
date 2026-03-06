#pragma once
#include <string>
#include <map>

class ServiceDetector {
public:
    // Конструктор — загружает таблицу портов
    ServiceDetector();

    // Определяет службу по номеру порта
    std::string detect(const std::string& ip, int port);

private:
    // Таблица: номер порта → название службы
    std::map<int, std::string> port_table;

    // Пробует получить баннер от сервера
    std::string grab_banner(const std::string& ip, int port);

    // Загружает таблицу известных портов
    void load_port_table();
};