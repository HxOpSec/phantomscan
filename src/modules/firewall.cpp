#include "modules/firewall.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <cerrno>

// Проверяем порт с таймаутом
// Возвращает: 0 = открыт, 1 = закрыт, 2 = фильтруется
int FirewallDetector::probe_port(const std::string& ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 2;

    // Неблокирующий режим
    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    // Ждём ответа
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int result = select(sock + 1, NULL, &fdset, NULL, &tv);

    if (result == 0) {
        // Таймаут — нет ответа = фаервол фильтрует
        close(sock);
        return 2;
    }

    if (result > 0) {
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);

        close(sock);

        if (error == 0) return 0;        // Открыт
        if (error == ECONNREFUSED) return 1; // Закрыт (RST)
        return 2;                        // Фильтруется
    }

    close(sock);
    return 2;
}

// Главная функция — анализируем цель
FirewallResult FirewallDetector::detect(const std::string& ip) {
    FirewallResult result;

    // Тестируем несколько портов
    int ports[] = {80, 443, 22, 8080, 3389};
    int open_count     = 0;
    int closed_count   = 0;
    int filtered_count = 0;

    std::cout << "[*] Тестируем порты для обнаружения фаервола..." << std::endl;

    for (int port : ports) {
        int status = probe_port(ip, port, 2);

        if (status == 0) {
            open_count++;
            std::cout << "    [+] Порт " << port << " → ОТКРЫТ" << std::endl;
        } else if (status == 1) {
            closed_count++;
            std::cout << "    [-] Порт " << port << " → ЗАКРЫТ (RST)" << std::endl;
        } else {
            filtered_count++;
            std::cout << "    [?] Порт " << port << " → ФИЛЬТРУЕТСЯ" << std::endl;
        }
    }

    result.tested_port = 5;

    // Анализируем результаты
    if (filtered_count >= 3) {
        result.detected = true;
        result.status = "Фаервол ОБНАРУЖЕН (много фильтрованных портов)";
    } else if (filtered_count >= 1 && closed_count == 0) {
        result.detected = true;
        result.status = "Вероятно есть фаервол (есть фильтрация)";
    } else {
        result.detected = false;
        result.status = "Фаервол не обнаружен";
    }

    return result;
}