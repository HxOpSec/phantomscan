#include "modules/packet_capture.h"
#include <iostream>
#include <netinet/ip.h>       // Для IP заголовка
#include <netinet/tcp.h>      // Для TCP заголовка
#include <netinet/udp.h>      // Для UDP заголовка
#include <netinet/ip_icmp.h>  // Для ICMP заголовка
#include <arpa/inet.h>        // Для inet_ntoa()
#include <net/ethernet.h>     // Для Ethernet заголовка

// Конструктор
PacketCapture::PacketCapture(const std::string& interface)
    : interface(interface) {}

// Обработчик каждого пакета
void PacketCapture::packet_handler(u_char* user,
                                   const struct pcap_pkthdr* header,
                                   const u_char* packet) {
    (void)user;

    // 1. Пропускаем Ethernet заголовок (14 байт)
    const struct ip* ip_header = (struct ip*)(packet + 14);

    // 2. Читаем IP адреса
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    int size = header->len;

    // 3. Определяем протокол
    std::string protocol;
    int src_port = 0, dst_port = 0;

    int ip_header_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        const struct tcphdr* tcp = (struct tcphdr*)
            ((u_char*)ip_header + ip_header_len);
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        const struct udphdr* udp = (struct udphdr*)
            ((u_char*)ip_header + ip_header_len);
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);

    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        protocol = "ICMP";
    } else {
        protocol = "OTHER";
    }

    // 4. Выводим информацию
    std::cout << "[PKT] " << protocol
              << " | " << src_ip << ":" << src_port
              << " → " << dst_ip << ":" << dst_port
              << " | " << size << " bytes"
              << std::endl;
}

// Запускаем захват
void PacketCapture::start(int count) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. Открываем интерфейс
    pcap_t* handle = pcap_open_live(
        interface.c_str(),  // Интерфейс (eth0, wlan0...)
        65536,              // Макс размер пакета
        1,                  // Promiscuous mode (ловим всё)
        1000,               // Таймаут (мс)
        errbuf              // Буфер ошибок
    );

    if (!handle) {
        std::cerr << "[-] Ошибка pcap: " << errbuf << std::endl;
        return;
    }

    std::cout << "[*] Захват пакетов на " << interface
              << " (" << count << " пакетов)..." << std::endl;

    // 2. Начинаем захват
    pcap_loop(handle, count, packet_handler, nullptr);

    // 3. Закрываем
    pcap_close(handle);
    std::cout << "[*] Захват завершён!" << std::endl;
}