#include "modules/arp_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <sstream>
#include <cstdio>
#include <iomanip>

std::vector<ARPHost> ARPScanner::scan(const std::string& subnet) {
    std::vector<ARPHost> hosts;

    std::cout << Color::INFO << "ARP скан сети: " << Color::CYAN 
              << subnet << Color::RESET << std::endl;
    std::cout << Color::INFO << "Отправляем ARP запросы..." 
              << Color::RESET << std::endl;

    // Сначала делаем быстрый ping sweep чтобы заполнить ARP таблицу
    std::string ping_cmd = "nmap -sn " + subnet +
                           " > /dev/null 2>&1";
    int ping_status = system(ping_cmd.c_str());
    (void)ping_status;

    // Читаем ARP таблицу ядра
    std::string arp_cmd = "arp -n 2>/dev/null";
    FILE* pipe = popen(arp_cmd.c_str(), "r");
    if (!pipe) return hosts;

    char line[256];
    bool first = true;
    while (fgets(line, sizeof(line), pipe)) {
        if (first) { first = false; continue; } // пропускаем заголовок

        std::string s(line);
        std::istringstream iss(s);
        std::string ip, hw_type, mac, flags, iface;
        iss >> ip >> hw_type >> mac >> flags >> iface;

        // Пропускаем неполные записи
        if (mac == "(incomplete)" || mac.empty() || ip.empty()) continue;
        if (mac.find(':') == std::string::npos) continue;

        // Пробуем получить hostname
        std::string hostname = ip;
        std::string host_cmd = "host " + ip + 
                               " 2>/dev/null | head -1";
        FILE* hp = popen(host_cmd.c_str(), "r");
        if (hp) {
            char hbuf[256];
            if (fgets(hbuf, sizeof(hbuf), hp)) {
                std::string hs(hbuf);
                // "1.1.168.192.in-addr.arpa domain name pointer myhost."
                size_t pos = hs.find("pointer ");
                if (pos != std::string::npos) {
                    hostname = hs.substr(pos + 8);
                    if (!hostname.empty() && 
                        hostname.back() == '\n')
                        hostname.pop_back();
                    if (!hostname.empty() && 
                        hostname.back() == '.')
                        hostname.pop_back();
                }
            }
            pclose(hp);
        }

        hosts.push_back({ip, mac, hostname});
    }
    pclose(pipe);
    return hosts;
}

void ARPScanner::print_results(const std::vector<ARPHost>& hosts) {
    if (hosts.empty()) {
        std::cout << Color::WARN << "Устройства не найдены" 
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────┬───────────────────┬─────────────────────────┐\n";
    std::cout << "│      IP         │       MAC         │       HOSTNAME          │\n";
    std::cout << "├─────────────────┼───────────────────┼─────────────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& h : hosts) {
        std::string ip = h.ip;
        std::string mac = h.mac;
        std::string host = h.hostname;

        // Обрезаем если слишком длинные
        if (ip.size() > 15)   ip   = ip.substr(0, 15);
        if (mac.size() > 17)  mac  = mac.substr(0, 17);
        if (host.size() > 23) host = host.substr(0, 23);

        // Дополняем пробелами
        while (ip.size() < 15)   ip   += " ";
        while (mac.size() < 17)  mac  += " ";
        while (host.size() < 23) host += " ";

        std::cout << Color::OK;
        std::cout << "│ " << ip << " │ " << mac 
                  << " │ " << host << " │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└─────────────────┴───────────────────┴─────────────────────────┘\n";
    std::cout << Color::RESET;
    std::cout << Color::INFO << "Найдено устройств: " << Color::GREEN 
              << hosts.size() << Color::RESET << std::endl;
}
