#include "core/scanner.h"
#include "modules/service_detect.h"
#include <iostream>
#include <sys/socket.h>    // Для работы с сокетами
#include <netinet/in.h>    // Для структуры sockaddr_in
#include <arpa/inet.h>     // Для inet_addr()
#include <unistd.h>        // Для close()
#include <fcntl.h>         // Для неблокирующего режима
#include <sys/select.h>    // Для select() — таймаут

// Конструктор — сохраняем IP адрес цели
Scanner::Scanner(const std::string& target_ip) 
    : target_ip(target_ip) {}

// Проверяем один порт
bool Scanner::check_port(int port) {
    // 1. Создаём сокет (TCP)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // 2. Говорим сокету не ждать вечно (неблокирующий режим)
    fcntl(sock, F_SETFL, O_NONBLOCK);

    // 3. Заполняем адрес цели
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;           // IPv4
    addr.sin_port = htons(port);         // Порт (htons = правильный порядок байт)
    addr.sin_addr.s_addr = inet_addr(target_ip.c_str()); // IP адрес

    // 4. Пробуем подключиться
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    // 5. Ждём ответа максимум 1 секунду
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;     
    tv.tv_sec = 1;   // 1 секунда
    tv.tv_usec = 0;

    bool is_open = false;

    // 6. Если сокет готов — порт открыт!
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int error;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        is_open = (error == 0);
    }

    // 7. Закрываем сокет
    close(sock);
    return is_open;
}

// Сканируем диапазон портов
std::vector<PortResult> Scanner::scan(int start_port, int end_port) {
    std::vector<PortResult> results;

    for (int port = start_port; port <= end_port; port++) {
        bool open = check_port(port);

        if (open) {
            PortResult result;
            result.port = port;
            result.is_open = true;
            ServiceDetector detector;
result.service = detector.detect(target_ip, port);
            results.push_back(result);

            std::cout << "[+] Port " << result.port 
          << " is OPEN | Service: " << result.service 
          << std::endl;
        }
    }

    return results;
}
