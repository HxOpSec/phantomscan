#include "modules/service_detect.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sys/select.h>

// Конструктор — сразу загружаем таблицу
ServiceDetector::ServiceDetector() {
    load_port_table();
}

// Таблица известных портов
void ServiceDetector::load_port_table() {
    port_table[21]   = "FTP";
    port_table[22]   = "SSH";
    port_table[23]   = "Telnet";
    port_table[25]   = "SMTP";
    port_table[53]   = "DNS";
    port_table[80]   = "HTTP";
    port_table[110]  = "POP3";
    port_table[143]  = "IMAP";
    port_table[443]  = "HTTPS";
    port_table[3306] = "MySQL";
    port_table[5432] = "PostgreSQL";
    port_table[6379] = "Redis";
    port_table[8080] = "HTTP-Alt";
    port_table[8443] = "HTTPS-Alt";
    port_table[27017]= "MongoDB";
}

// Пробуем получить баннер от сервера
std::string ServiceDetector::grab_banner(const std::string& ip, int port) {
    // Создаём сокет
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    // Таймаут 2 секунды
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Подключаемся
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    // Читаем баннер (первые 256 байт)
    char buffer[256] = {0};
    recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);

    // Убираем переносы строк
    std::string banner(buffer);
    if (!banner.empty() && banner.back() == '\n')
        banner.pop_back();

    return banner;
}

// Главная функция — определяем службу
std::string ServiceDetector::detect(const std::string& ip, int port) {
    // Сначала пробуем получить баннер
    std::string banner = grab_banner(ip, port);

    if (!banner.empty()) {
        // Баннер есть — возвращаем его
        return banner.substr(0, 50); // Первые 50 символов
    }

    // Баннера нет — смотрим в таблице
    if (port_table.count(port)) {
        return port_table[port];
    }

    // Не знаем — неизвестная служба
    return "unknown";
}