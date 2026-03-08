#include "modules/syn_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>

// Структура для подсчёта checksum
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

// Считаем checksum
unsigned short checksum(void* b, int len) {
    unsigned short* buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

std::vector<SYNResult> SYNScanner::scan(const std::string& target,
                                         int port_start, int port_end) {
    std::vector<SYNResult> results;

    std::cout << Color::INFO << "SYN Stealth скан: " << Color::CYAN
              << target << Color::RESET << std::endl;
    std::cout << Color::INFO << "Порты: " << port_start
              << "-" << port_end << Color::RESET << std::endl;
    std::cout << Color::WARN
              << "Режим: невидимый (SYN без ACK)"
              << Color::RESET << std::endl;

    // Резолвим цель
    struct hostent* he = gethostbyname(target.c_str());
    if (!he) {
        std::cout << Color::FAIL << "Не удалось разрезолвить!"
                  << Color::RESET << std::endl;
        return results;
    }

    struct in_addr dest_addr;
    memcpy(&dest_addr, he->h_addr_list[0], sizeof(dest_addr));
    std::string dest_ip = inet_ntoa(dest_addr);

    // Raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cout << Color::FAIL << "Нужен sudo!"
                  << Color::RESET << std::endl;
        return results;
    }

    // Говорим ядру что мы сами строим IP заголовок
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // Таймаут
    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int port = port_start; port <= port_end; port++) {

        // Буфер пакета
        char packet[4096];
        memset(packet, 0, sizeof(packet));

        // IP заголовок
        struct iphdr* iph = (struct iphdr*)packet;
        iph->ihl      = 5;
        iph->version  = 4;
        iph->tos      = 0;
        iph->tot_len  = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id       = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check    = 0;
        iph->saddr    = inet_addr("0.0.0.0"); // ядро подставит
        iph->daddr    = dest_addr.s_addr;

        // TCP заголовок
        struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
        tcph->source  = htons(rand() % 60000 + 1024);
        tcph->dest    = htons(port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = 0;
        tcph->doff    = 5;
        tcph->syn     = 1; // SYN флаг — главное отличие!
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;

        // Pseudo header для checksum
        char psh[4096];
        struct pseudo_header* pshdr = (struct pseudo_header*)psh;
        pshdr->src_addr  = iph->saddr;
        pshdr->dst_addr  = iph->daddr;
        pshdr->placeholder = 0;
        pshdr->protocol  = IPPROTO_TCP;
        pshdr->tcp_length = htons(sizeof(struct tcphdr));
        memcpy(psh + sizeof(struct pseudo_header), tcph,
               sizeof(struct tcphdr));
        tcph->check = checksum(psh,
            sizeof(struct pseudo_header) + sizeof(struct tcphdr));

        // Адрес назначения
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr   = dest_addr;

        // Отправляем SYN
        sendto(sock, packet, iph->tot_len, 0,
               (struct sockaddr*)&dest, sizeof(dest));

        // Ждём ответ
        char recv_buf[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr*)&from, &from_len);

        if (bytes > 0) {
            struct iphdr*  r_ip  = (struct iphdr*)recv_buf;
            struct tcphdr* r_tcp = (struct tcphdr*)
                                   (recv_buf + r_ip->ihl * 4);

            if (ntohs(r_tcp->source) == port) {
                SYNResult res;
                res.port = port;

                if (r_tcp->syn && r_tcp->ack) {
                    // SYN-ACK = порт ОТКРЫТ
                    res.state   = "OPEN";
                    res.service = "unknown";
                    results.push_back(res);

                    std::cout << Color::OK << "Порт " << port
                              << " → ОТКРЫТ (SYN-ACK)"
                              << Color::RESET << std::endl;

                    // Сразу RST чтобы не завершать соединение
                    // (это и есть stealth!)
                    struct tcphdr* rst = r_tcp;
                    rst->syn = 0;
                    rst->ack = 0;
                    rst->rst = 1;
                    sendto(sock, recv_buf, bytes, 0,
                           (struct sockaddr*)&from, from_len);

                } else if (r_tcp->rst) {
                    // RST = порт закрыт (не выводим)
                }
            }
        }
    }

    close(sock);
    return results;
}

void SYNScanner::print_results(const std::vector<SYNResult>& results) {
    if (results.empty()) {
        std::cout << Color::WARN << "Открытых портов не найдено"
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌──────────┬─────────┬──────────────────────┐\n";
    std::cout << "│   ПОРТ   │  СТАТУС │       СЛУЖБА         │\n";
    std::cout << "├──────────┼─────────┼──────────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& r : results) {
        std::string port_s = std::to_string(r.port);
        while (port_s.size() < 8) port_s += " ";
        std::string state = r.state;
        while (state.size() < 7) state += " ";
        std::string svc = r.service;
        while (svc.size() < 20) svc += " ";

        std::cout << Color::OK;
        std::cout << "│ " << port_s << " │ " << state
                  << " │ " << svc << " │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└──────────┴─────────┴──────────────────────┘\n";
    std::cout << Color::RESET;
    std::cout << Color::INFO << "Найдено открытых: " << Color::GREEN
              << results.size() << Color::RESET << std::endl;
}