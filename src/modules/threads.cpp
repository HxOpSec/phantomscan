#include <algorithm>
#include <chrono>
#include "modules/threads.h"
#include "modules/service_detect.h"
#include "utils/colors.h"
#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <cerrno>

ThreadScanner::ThreadScanner(const std::string& target_ip, int num_threads)
    : target_ip(target_ip), num_threads(num_threads) {}

// Проверяем один порт
static bool check_port(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 300000;

    bool is_open = false;
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int error;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        is_open = (error == 0);
    }

    close(sock);
    return is_open;
}

// Один поток сканирует свой диапазон
void ThreadScanner::scan_range(int start, int end, std::vector<PortResult>& results) {
    for (int port = start; port <= end; port++) {
        if (check_port(target_ip, port)) {
            PortResult result;
            result.port = port;
            result.is_open = true;

            ServiceDetector detector;
            result.service = detector.detect(target_ip, port);

            // Защищаем запись в общий список
            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back(result);

            std::cout << "\r" << Color::OK
                      << "Порт " << Color::BOLD << result.port << Color::RESET
                      << Color::GREEN << " ОТКРЫТ" << Color::RESET
                      << " | " << Color::YELLOW << result.service << Color::RESET
                      << std::string(20, ' ') << std::endl;
        }
    }
}

// Главная функция — делим порты между потоками
std::vector<PortResult> ThreadScanner::scan(int start_port, int end_port) {
    std::vector<PortResult> results;
    std::vector<std::thread> threads;

    int total = end_port - start_port + 1;
    int chunk = total / num_threads; // Сколько портов на каждый поток

    std::cout << Color::INFO << "Потоков: " << Color::CYAN << num_threads
              << Color::RESET << std::endl;

    auto start_time = std::chrono::steady_clock::now();

    // Запускаем потоки
    for (int i = 0; i < num_threads; i++) {
        int start = start_port + (i * chunk);
        int end   = (i == num_threads - 1) ? end_port : start + chunk - 1;

        threads.emplace_back(&ThreadScanner::scan_range, this, start, end, std::ref(results));
    }

    // Ждём завершения всех потоков
    for (auto& t : threads) {
        t.join();
    }

    // Сортируем по номеру порта
    std::sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b) {
        return a.port < b.port;
    });

    auto end_time = std::chrono::steady_clock::now();
    int total_sec = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
    std::cout << Color::INFO << "Сканирование завершено за "
              << Color::YELLOW << total_sec << " секунд"
              << Color::RESET << std::endl;

    return results;
}