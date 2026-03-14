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

// ── Известные UDP службы ──────────────────────────────
static std::string udp_service(int port) {
    switch (port) {
        case 53:    return "DNS";
        case 67:    return "DHCP Server";
        case 68:    return "DHCP Client";
        case 69:    return "TFTP";
        case 111:   return "RPCbind";
        case 123:   return "NTP";
        case 137:   return "NetBIOS-NS";
        case 138:   return "NetBIOS-DGM";
        case 161:   return "SNMP";
        case 162:   return "SNMP Trap";
        case 177:   return "XDMCP";
        case 443:   return "QUIC/HTTPS";
        case 500:   return "IKE/IPSec";
        case 514:   return "Syslog";
        case 520:   return "RIP";
        case 623:   return "IPMI";
        case 631:   return "IPP";
        case 1194:  return "OpenVPN";
        case 1434:  return "MSSQL Monitor";
        case 1604:  return "Citrix";
        case 1701:  return "L2TP";
        case 1900:  return "UPnP/SSDP";
        case 2049:  return "NFS";
        case 3478:  return "STUN/TURN";
        case 3702:  return "WS-Discovery";
        case 4500:  return "IPSec NAT-T";
        case 5060:  return "SIP";
        case 5353:  return "mDNS";
        case 5355:  return "LLMNR";
        case 5683:  return "CoAP";
        case 6881:  return "BitTorrent";
        case 9200:  return "Elasticsearch";
        case 10000: return "Webmin";
        case 11211: return "Memcached";
        case 17185: return "VxWorks WDBRPC";
        case 27015: return "Steam/Game";
        case 47808: return "BACnet";
        default:    return "unknown";
    }
}

// ── Специфичные payload для протоколов ───────────────
static std::pair<const unsigned char*, int> udp_payload(int port) {
    // DNS query для "version.bind"
    static const unsigned char dns_probe[] = {
        0x00,0x00, 0x01,0x00, 0x00,0x01, 0x00,0x00,
        0x00,0x00, 0x00,0x00, 0x07,'v','e','r','s',
        'i','o','n', 0x04,'b','i','n','d', 0x00,
        0x00,0x10, 0x00,0x03
    };
    // NTP version request
    static const unsigned char ntp_probe[] = {
        0x1b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    // SNMP v1 GetRequest public
    static const unsigned char snmp_probe[] = {
        0x30,0x26,0x02,0x01,0x00,0x04,0x06,'p','u',
        'b','l','i','c',0xa0,0x19,0x02,0x04,0x71,
        0xb4,0x24,0xd9,0x02,0x01,0x00,0x02,0x01,
        0x00,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,
        0x06,0x01,0x02,0x01,0x05,0x00
    };
    // SSDP M-SEARCH
    static const unsigned char ssdp_probe[] =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "ST: ssdp:all\r\n"
        "MX: 1\r\n\r\n";
    // NetBIOS Name Service
    static const unsigned char netbios_probe[] = {
        0x82,0x28,0x00,0x00,0x00,0x01,0x00,0x00,
        0x00,0x00,0x00,0x00,0x20,0x43,0x4b,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x21,
        0x00,0x01
    };

    switch (port) {
        case 53:  return {dns_probe,    sizeof(dns_probe)};
        case 123: return {ntp_probe,    sizeof(ntp_probe)};
        case 161: return {snmp_probe,   sizeof(snmp_probe)};
        case 1900: return {ssdp_probe,  (int)strlen((const char*)ssdp_probe)};
        case 137: return {netbios_probe,sizeof(netbios_probe)};
        default:  { static const unsigned char z[] = {0}; return {z, 1}; }
    }
}

std::vector<UDPResult> UDPScanner::scan(const std::string& target,
                                         int port_start, int port_end) {
    std::vector<UDPResult> results;

    std::cout << Color::INFO << "UDP скан: " << Color::CYAN
              << target << Color::RESET << "\n";
    std::cout << Color::WARN
              << "[!] UDP — нет handshake, используем протокольные probe\n"
              << Color::RESET;

    struct addrinfo hints, *addr_res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(target.c_str(), nullptr, &hints, &addr_res);
    if (err != 0) {
        std::cout << Color::FAIL << "Не удалось резолвить цель: "
                  << gai_strerror(err) << Color::RESET << "\n";
        return results;
    }

    struct sockaddr_in* addr_in = (struct sockaddr_in*)addr_res->ai_addr;
    struct in_addr dest_addr    = addr_in->sin_addr;
    freeaddrinfo(addr_res);

    for (int port = port_start; port <= port_end; port++) {

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) continue;

        // Таймаут 1.5 сек
        struct timeval tv = {1, 500000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(port);
        dest.sin_addr   = dest_addr;

        // Отправляем протокольный payload
        auto [payload, plen] = udp_payload(port);
        sendto(sock, (const char*)payload, plen, 0,
               (struct sockaddr*)&dest, sizeof(dest));

        char recv_buf[2048];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr*)&from, &from_len);

        UDPResult udp_res;
        udp_res.port    = port;
        udp_res.service = udp_service(port);

        if (bytes > 0) {
            // Получили ответ — порт точно OPEN
            udp_res.state = "OPEN";
            results.push_back(udp_res);
            std::cout << Color::GREEN << "[+] " << std::setw(5) << port
                      << "/UDP  OPEN        | " << udp_res.service
                      << Color::RESET << "\n";
        } else {
            // Нет ответа = OPEN|FILTERED (показываем только известные)
            if (udp_res.service != "unknown") {
                udp_res.state = "OPEN|FILTERED";
                results.push_back(udp_res);
                std::cout << Color::YELLOW << "[?] " << std::setw(5) << port
                          << "/UDP  OPEN|FILTERED | " << udp_res.service
                          << Color::RESET << "\n";
            }
        }

        close(sock);
    }

    return results;
}

void UDPScanner::print_results(const std::vector<UDPResult>& results) {
    if (results.empty()) {
        std::cout << Color::WARN << "[!] UDP портов не найдено\n"
                  << Color::RESET;
        return;
    }

    // Считаем open и open|filtered отдельно
    int open_count = 0, filtered_count = 0;
    for (const auto& r : results) {
        if (r.state == "OPEN") open_count++;
        else filtered_count++;
    }

    std::cout << "\n" << Color::CYAN
              << "╔══════════════╦══════════════════════╦═══════════════════╗\n"
              << "║     PORT     ║       SERVICE        ║      STATUS       ║\n"
              << "╠══════════════╬══════════════════════╬═══════════════════╣\n"
              << Color::RESET;

    for (const auto& r : results) {
        std::string port_s = std::to_string(r.port) + "/UDP";
        std::string svc    = r.service;
        std::string state  = r.state;

        while ((int)port_s.size() < 12) port_s += " ";
        while ((int)svc.size()    < 20) svc    += " ";
        while ((int)state.size()  < 17) state  += " ";

        std::string col = (r.state == "OPEN") ? Color::GREEN : Color::YELLOW;
        std::cout << col
                  << "║ " << port_s
                  << " ║ " << svc
                  << " ║ " << state << " ║\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN
              << "╚══════════════╩══════════════════════╩═══════════════════╝\n"
              << Color::RESET;
    std::cout << Color::GREEN  << "  OPEN:          " << open_count << "\n"
              << Color::YELLOW << "  OPEN|FILTERED: " << filtered_count << "\n"
              << Color::INFO   << "  Total:         " << results.size()
              << Color::RESET  << "\n";
}