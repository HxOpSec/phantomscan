#include "modules/packet_capture.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

// FIX: параметр iface_ вместо interface (shadow warning)
PacketCapture::PacketCapture(const std::string& iface_)
    : interface(iface_) {}

// ── Обработчик каждого пакета ─────────────────────────
void PacketCapture::packet_handler(u_char* user,
                                   const struct pcap_pkthdr* header,
                                   const u_char* packet) {
    (void)user;

    // Проверка минимального размера пакета
    if (header->len < 14 + sizeof(struct ip)) return;

    // Пропускаем Ethernet заголовок (14 байт)
    const struct ip* ip_hdr = (struct ip*)(packet + 14);
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    // Защита от кривых пакетов
    if (ip_hdr_len < 20) return;

    std::string src_ip = inet_ntoa(ip_hdr->ip_src);
    std::string dst_ip = inet_ntoa(ip_hdr->ip_dst);
    int         size   = (int)header->len;

    std::string protocol;
    int src_port = 0, dst_port = 0;
    std::string flags;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        // Проверяем что TCP заголовок влезает в пакет
        if (header->len >= (u_int)(14 + ip_hdr_len + (int)sizeof(struct tcphdr))) {
            const struct tcphdr* tcp = (struct tcphdr*)
                ((u_char*)ip_hdr + ip_hdr_len);
            src_port = ntohs(tcp->source);
            dst_port = ntohs(tcp->dest);

            // Читаем TCP флаги
            if (tcp->syn) flags += "SYN ";
            if (tcp->ack) flags += "ACK ";
            if (tcp->fin) flags += "FIN ";
            if (tcp->rst) flags += "RST ";
            if (tcp->psh) flags += "PSH ";
            if (!flags.empty() && flags.back() == ' ')
                flags.pop_back();
        }

    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        if (header->len >= (u_int)(14 + ip_hdr_len + (int)sizeof(struct udphdr))) {
            const struct udphdr* udp = (struct udphdr*)
                ((u_char*)ip_hdr + ip_hdr_len);
            src_port = ntohs(udp->source);
            dst_port = ntohs(udp->dest);
        }

    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        protocol = "ICMP";
    } else {
        protocol = "OTHER";
    }

    // Цвет по протоколу
    std::string col = Color::WHITE;
    if      (protocol == "TCP")  col = Color::CYAN;
    else if (protocol == "UDP")  col = Color::YELLOW;
    else if (protocol == "ICMP") col = Color::GREEN;

    // Вывод
    std::cout << col << "[PKT] "
              << std::left << std::setw(5) << protocol
              << Color::RESET
              << " | " << Color::YELLOW
              << std::left << std::setw(15) << src_ip
              << Color::RESET << ":" << std::setw(5) << src_port
              << " → "
              << Color::CYAN
              << std::left << std::setw(15) << dst_ip
              << Color::RESET << ":" << std::setw(5) << dst_port
              << " | " << std::setw(6) << size << " bytes";

    if (!flags.empty())
        std::cout << " | " << Color::RED << flags << Color::RESET;

    std::cout << "\n";
}

// ── Запуск захвата ────────────────────────────────────
void PacketCapture::start(int count) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        interface.c_str(),
        65536,
        1,       // promiscuous mode
        1000,    // таймаут мс
        errbuf
    );

    if (!handle) {
        std::cout << Color::FAIL << "[-] Ошибка pcap: "
                  << errbuf << Color::RESET << "\n";
        return;
    }

    // Фильтр — только IP пакеты
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    std::cout << Color::INFO << "Захват пакетов на "
              << Color::CYAN << interface << Color::RESET
              << " | Ожидаем " << count << " пакетов...\n";
    std::cout << Color::INFO
              << "Протокол | Источник              | Назначение            | Размер\n"
              << "──────────────────────────────────────────────────────────────────\n"
              << Color::RESET;

    pcap_loop(handle, count, packet_handler, nullptr);

    pcap_close(handle);
    std::cout << Color::OK << "Захват завершён!\n" << Color::RESET;
}