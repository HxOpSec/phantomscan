#pragma once
#include <string>
#include <pcap.h>

// Информация об одном пакете
struct PacketInfo {
    std::string src_ip;   // Откуда пришёл
    std::string dst_ip;   // Куда идёт
    int src_port;         // Порт источника
    int dst_port;         // Порт назначения
    std::string protocol; // TCP / UDP / ICMP
    int size;             // Размер пакета
};

class PacketCapture {
public:
    // Конструктор — выбираем сетевой интерфейс (eth0, wlan0...)
    PacketCapture(const std::string& interface);

    // Начать захват (count = сколько пакетов поймать)
    void start(int count);

private:
    std::string interface;

    // Обработчик каждого пакета (вызывается автоматически)
    static void packet_handler(u_char* user,
                               const struct pcap_pkthdr* header,
                               const u_char* packet);
};