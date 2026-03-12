#include "modules/udp_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>

// Известные UDP службы
static std::string udp_service(int port) {
    switch (port) {
        case 53:   return "DNS";
        case 67:   return "DHCP Server";
        case 68:   return "DHCP Client";
        case 69:   return "TFTP";
        case 123:  return "NTP";
        case 137:  return "NetBIOS";
        case 138:  return "NetBIOS";
        case 161:  return "SNMP";
        case 162:  return "SNMP Trap";
        case 500:  return "IKE/VPN";
        case 514:  return "Syslog";
        case 1194: return "OpenVPN";
        case 1900: return "UPnP";
        case 4500: return "IPSec";
        case 5353: return "mDNS";
        default:   return "unknown";
    }
}

std::vector<UDPResult> UDPScanner::scan(const std::string& target,
                                         int port_start, int port_end) {
    std::vector<UDPResult> results;

    std::cout << Color::INFO << "UDP скан: " << Color::CYAN
              << target << Color::RESET << std::endl;
    std::cout << Color::WARN
              << "[!] UDP сложнее TCP — нет handshake!"
              << Color::RESET << std::endl;

    // FIX: getaddrinfo() вместо gethostbyname()
    // gethostbyname() — устарела, не thread-safe, не поддерживает IPv6
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_DGRAM;    // UDP

    int err = getaddrinfo(target.c_str(), nullptr, &hints, &res);
    if (err != 0) {
        std::cout << Color::FAIL << "Не удалось резолвить цель: "
                  << gai_strerror(err)  // точное сообщение об ошибке
                  << Color::RESET << std::endl;
        return results;
    }

    struct sockaddr_in* addr_in = (struct sockaddr_in*)res->ai_addr;
    struct in_addr dest_addr    = addr_in->sin_addr;
    freeaddrinfo(res);             // FIX: освобождаем память

    for (int port = port_start; port <= port_end; port++) {

        // Создаём UDP сокет
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) continue;

        // Таймаут 1 сек
        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Адрес назначения
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(port);
        dest.sin_addr   = dest_addr;

        // Отправляем пустой UDP пакет
        const char* payload = "\x00";
        sendto(sock, payload, 1, 0,
               (struct sockaddr*)&dest, sizeof(dest));

        // Ждём ответ
        char recv_buf[1024];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr*)&from, &from_len);

        UDPResult res;
        res.port    = port;
        res.service = udp_service(port);

        if (bytes > 0) {
            // Получили ответ — порт точно открыт!
            res.state = "OPEN";
            results.push_back(res);
            std::cout << Color::OK << "[+] Порт " << port
                      << "/UDP ОТКРЫТ (" << res.service << ")"
                      << Color::RESET << std::endl;
        } else {
            // Нет ответа — OPEN|FILTERED (UDP не говорит закрыт)
            // Показываем только известные службы
            if (res.service != "unknown") {
                res.state = "OPEN|FILTERED";
                results.push_back(res);
                std::cout << Color::WARN << "[?] Порт " << port
                          << "/UDP OPEN|FILTERED (" << res.service << ")"
                          << Color::RESET << std::endl;
            }
        }

        close(sock);
    }

    return results;
}

void UDPScanner::print_results(const std::vector<UDPResult>& results) {
    if (results.empty()) {
        std::cout << Color::WARN << "UDP портов не найдено"
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌──────────┬──────────────────┬─────────────────┐\n";
    std::cout << "│   ПОРТ   │     СЛУЖБА       │     СТАТУС      │\n";
    std::cout << "├──────────┼──────────────────┼─────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& r : results) {
        std::string port_s = std::to_string(r.port) + "/UDP";
        std::string svc    = r.service;
        std::string state  = r.state;

        while (port_s.size() < 8)  port_s += " ";
        while (svc.size()    < 16) svc    += " ";
        while (state.size()  < 15) state  += " ";

        if (r.state == "OPEN")
            std::cout << Color::OK;
        else
            std::cout << Color::WARN;

        std::cout << "│ " << port_s << " │ " << svc
                  << " │ " << state << " │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└──────────┴──────────────────┴─────────────────┘\n";
    std::cout << Color::RESET;
    std::cout << Color::INFO << "Найдено UDP портов: "
              << Color::GREEN << results.size()
              << Color::RESET << std::endl;
}