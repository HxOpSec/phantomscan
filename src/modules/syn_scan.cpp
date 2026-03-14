#include "modules/syn_scan.h"
#include "modules/service_detect.h"
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
#include <net/if.h>
#include <ifaddrs.h>

// ── Pseudo header ─────────────────────────────────────
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

// ── Checksum ──────────────────────────────────────────
static unsigned short checksum(void* b, int len) {
    unsigned short* buf = (unsigned short*)b;
    unsigned int    sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// ── Получаем свой реальный IP ─────────────────────────
static uint32_t get_local_ip() {
    struct ifaddrs *ifap, *ifa;
    uint32_t local_ip = inet_addr("127.0.0.1");

    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (ifa->ifa_addr->sa_family != AF_INET) continue;
            // Пропускаем loopback
            if (std::string(ifa->ifa_name) == "lo") continue;

            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            local_ip = sa->sin_addr.s_addr;
            break;
        }
        freeifaddrs(ifap);
    }
    return local_ip;
}

std::vector<SYNResult> SYNScanner::scan(const std::string& target,
                                         int port_start, int port_end) {
    std::vector<SYNResult> results;

    std::cout << Color::INFO << "SYN Stealth скан: " << Color::CYAN
              << target << Color::RESET << "\n";
    std::cout << Color::INFO << "Порты: "
              << port_start << "-" << port_end << Color::RESET << "\n";
    std::cout << Color::WARN << "Режим: невидимый (SYN без ACK)\n"
              << Color::RESET;

    // Резолвинг
    struct addrinfo hints, *addr_res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(target.c_str(), nullptr, &hints, &addr_res);
    if (err != 0) {
        std::cout << Color::FAIL << "Не удалось разрезолвить: "
                  << gai_strerror(err) << Color::RESET << "\n";
        return results;
    }

    struct sockaddr_in* addr_in = (struct sockaddr_in*)addr_res->ai_addr;
    struct in_addr dest_addr    = addr_in->sin_addr;
    freeaddrinfo(addr_res);

    // Получаем свой реальный IP (важно для checksum)
    uint32_t src_ip = get_local_ip();

    char src_ip_str[INET_ADDRSTRLEN];
    struct in_addr src_in;
    src_in.s_addr = src_ip;
    inet_ntop(AF_INET, &src_in, src_ip_str, sizeof(src_ip_str));
    std::cout << Color::INFO << "Источник: " << Color::CYAN
              << src_ip_str << Color::RESET << "\n";

    // Raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cout << Color::FAIL << "Нужен sudo!\n" << Color::RESET;
        return results;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Фиксированный source port для этого скана
    uint16_t src_port = 54321;

    for (int port = port_start; port <= port_end; port++) {

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
        iph->saddr    = src_ip;          // реальный IP источника
        iph->daddr    = dest_addr.s_addr;

        // TCP заголовок
        struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
        tcph->source  = htons(src_port); // фиксированный src port
        tcph->dest    = htons(port);
        tcph->seq     = htonl(0xDEADBEEF);
        tcph->ack_seq = 0;
        tcph->doff    = 5;
        tcph->syn     = 1;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;

        // Pseudo header для checksum
        char psh[4096];
        struct pseudo_header* pshdr = (struct pseudo_header*)psh;
        pshdr->src_addr    = iph->saddr;
        pshdr->dst_addr    = iph->daddr;
        pshdr->placeholder = 0;
        pshdr->protocol    = IPPROTO_TCP;
        pshdr->tcp_length  = htons(sizeof(struct tcphdr));
        memcpy(psh + sizeof(struct pseudo_header), tcph,
               sizeof(struct tcphdr));
        tcph->check = checksum(psh,
            sizeof(struct pseudo_header) + sizeof(struct tcphdr));

        // IP checksum
        iph->check = checksum(iph, sizeof(struct iphdr));

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr   = dest_addr;

        sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr),
               0, (struct sockaddr*)&dest, sizeof(dest));

        // Ждём ответ — цикл пока не получим наш пакет
        char recv_buf[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        bool found = false;

        for (int attempt = 0; attempt < 10 && !found; attempt++) {
            int bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                                 (struct sockaddr*)&from, &from_len);
            if (bytes <= 0) break;

            struct iphdr*  r_ip  = (struct iphdr*)recv_buf;
            struct tcphdr* r_tcp = (struct tcphdr*)
                                   (recv_buf + r_ip->ihl * 4);

            // Проверяем IP источника и порт назначения
            if (r_ip->saddr  != dest_addr.s_addr) continue;
            if (ntohs(r_tcp->source) != port)      continue;
            if (ntohs(r_tcp->dest)   != src_port)  continue;

            found = true;

            if (r_tcp->syn && r_tcp->ack) {
                SYNResult syn_res;
                syn_res.port  = port;
                syn_res.state = "OPEN";

                ServiceDetector detector;
                syn_res.service = detector.detect(target, port);
                results.push_back(syn_res);

                std::cout << Color::OK << "Порт " << Color::BOLD
                          << port << Color::RESET
                          << Color::GREEN << " ОТКРЫТ (SYN-ACK)"
                          << Color::RESET << " | "
                          << Color::YELLOW << syn_res.service
                          << Color::RESET << "\n";

                // RST — stealth режим, не завершаем соединение
                r_tcp->syn = 0;
                r_tcp->ack = 0;
                r_tcp->rst = 1;
                r_tcp->check = 0;
                // Пересчитываем checksum для RST
                memset(psh, 0, sizeof(psh));
                pshdr = (struct pseudo_header*)psh;
                pshdr->src_addr   = r_ip->daddr;
                pshdr->dst_addr   = r_ip->saddr;
                pshdr->protocol   = IPPROTO_TCP;
                pshdr->tcp_length = htons(sizeof(struct tcphdr));
                memcpy(psh + sizeof(struct pseudo_header), r_tcp,
                       sizeof(struct tcphdr));
                r_tcp->check = checksum(psh,
                    sizeof(struct pseudo_header) + sizeof(struct tcphdr));

                sendto(sock, recv_buf, bytes, 0,
                       (struct sockaddr*)&from, from_len);
            }
            // RST = закрыт, просто игнорируем
        }
    }

    close(sock);
    return results;
}

void SYNScanner::print_results(const std::vector<SYNResult>& results) {
    if (results.empty()) {
        std::cout << Color::WARN << "Открытых портов не найдено\n"
                  << Color::RESET;
        return;
    }

    std::cout << "\n" << Color::CYAN;
    std::cout << "┌──────────┬─────────┬──────────────────────┐\n";
    std::cout << "│   ПОРТ   │  СТАТУС │       СЛУЖБА         │\n";
    std::cout << "├──────────┼─────────┼──────────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& r : results) {
        std::string port_s = std::to_string(r.port);
        std::string state  = r.state;
        std::string svc    = r.service;
        while (port_s.size() < 8)  port_s += " ";
        while (state.size()  < 7)  state  += " ";
        while (svc.size()    < 20) svc    += " ";

        std::cout << Color::OK
                  << "│ " << port_s
                  << " │ " << state
                  << " │ " << svc << " │\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└──────────┴─────────┴──────────────────────┘\n";
    std::cout << Color::RESET;
    std::cout << Color::INFO << "Найдено открытых: " << Color::GREEN
              << results.size() << Color::RESET << "\n";
}