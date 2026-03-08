#include <iomanip>
#include "modules/traceroute.h"
#include "utils/colors.h"
#include <iostream>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

std::vector<TraceHop> Traceroute::trace(const std::string& target,
                                         int max_hops) {
    std::vector<TraceHop> hops;

    std::cout << Color::INFO << "Трассировка к: " << Color::CYAN 
              << target << Color::RESET << std::endl;
    std::cout << Color::INFO << "Макс хопов: " << max_hops 
              << Color::RESET << std::endl;

    // Резолвим цель
    struct hostent* host_info = gethostbyname(target.c_str());
    if (!host_info) {
        std::cout << Color::FAIL << "Не удалось разрезолвить цель!" 
                  << Color::RESET << std::endl;
        return hops;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    memcpy(&dest.sin_addr, host_info->h_addr_list[0], 
           host_info->h_length);

    std::string dest_ip = inet_ntoa(dest.sin_addr);

    // Создаём ICMP сокет
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (send_sock < 0 || recv_sock < 0) {
        std::cout << Color::FAIL << "Нужен sudo!" 
                  << Color::RESET << std::endl;
        return hops;
    }

    // Таймаут получения
    struct timeval tv = {2, 0}; // 2 секунды
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int ttl = 1; ttl <= max_hops; ttl++) {
        // Устанавливаем TTL
        setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        // Создаём ICMP Echo Request
        char send_buf[64];
        memset(send_buf, 0, sizeof(send_buf));
        struct icmphdr* icmp = (struct icmphdr*)send_buf;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = getpid();
        icmp->un.echo.sequence = ttl;
        icmp->checksum = 0;

        // Считаем checksum
        uint32_t sum = 0;
        uint16_t* ptr = (uint16_t*)send_buf;
        for (size_t i = 0; i < sizeof(struct icmphdr)/2; i++)
            sum += ptr[i];
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        icmp->checksum = ~sum;

        // Запоминаем время отправки
        auto t_start = std::chrono::steady_clock::now();

        // Отправляем
        sendto(send_sock, send_buf, sizeof(struct icmphdr), 0,
               (struct sockaddr*)&dest, sizeof(dest));

        // Ждём ответ
        char recv_buf[512];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        int bytes = recvfrom(recv_sock, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr*)&from, &from_len);

        auto t_end = std::chrono::steady_clock::now();
        double rtt = std::chrono::duration<double, std::milli>
                     (t_end - t_start).count();

        TraceHop hop;
        hop.hop = ttl;
        hop.rtt_ms = rtt;
        hop.timeout = false;

        if (bytes < 0) {
            // Таймаут
            hop.ip = "*";
            hop.hostname = "*";
            hop.timeout = true;
        } else {
            hop.ip = inet_ntoa(from.sin_addr);
            hop.hostname = hop.ip;

            // Пробуем получить hostname
            struct hostent* h = gethostbyaddr(
                &from.sin_addr, sizeof(from.sin_addr), AF_INET);
            if (h) hop.hostname = h->h_name;
        }

        hops.push_back(hop);

        // Выводим в реальном времени
        if (hop.timeout) {
            std::cout << Color::WARN 
                      << std::setw(3) << ttl << "  * * *  (timeout)" 
                      << Color::RESET << std::endl;
        } else {
            std::cout << Color::OK 
                      << std::setw(3) << ttl << "  " 
                      << hop.ip;
            if (hop.hostname != hop.ip)
                std::cout << " (" << hop.hostname << ")";
            std::cout << "  " << Color::YELLOW 
                      << std::fixed << std::setprecision(2) 
                      << rtt << " ms" << Color::RESET << std::endl;
        }

        // Достигли цели?
        if (!hop.timeout && hop.ip == dest_ip) {
            std::cout << Color::OK << "Цель достигнута!" 
                      << Color::RESET << std::endl;
            break;
        }
    }

    close(send_sock);
    close(recv_sock);
    return hops;
}

void Traceroute::print_results(const std::vector<TraceHop>& hops) {
    int reached = 0;
    int timeouts = 0;
    for (auto& h : hops) {
        if (h.timeout) timeouts++;
        else reached++;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────┐\n";
    std::cout << "│          ИТОГ ТРАССИРОВКИ               │\n";
    std::cout << "├─────────────────────────────────────────┤\n";
    std::cout << "│ Всего хопов  : " << std::setw(3) << hops.size() 
              << "                        │\n";
    std::cout << "│ Отвечали     : " << std::setw(3) << reached 
              << "                        │\n";
    std::cout << "│ Таймаут      : " << std::setw(3) << timeouts 
              << "                        │\n";
    std::cout << "└─────────────────────────────────────────┘\n";
    std::cout << Color::RESET;
}