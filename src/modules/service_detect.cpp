#include "modules/service_detect.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sys/select.h>

ServiceDetector::ServiceDetector() {
    load_port_table();
}

void ServiceDetector::load_port_table() {
    port_table[21]   = "FTP";
    port_table[22]   = "SSH";
    port_table[23]   = "Telnet";
    port_table[25]   = "SMTP";
    port_table[53]   = "DNS";
    port_table[80]   = "HTTP";
    port_table[110]  = "POP3";
    port_table[143]  = "IMAP";
    port_table[443]  = "HTTPS";
    port_table[3306] = "MySQL";
    port_table[5432] = "PostgreSQL";
    port_table[6379] = "Redis";
    port_table[8080] = "HTTP-Alt";
    port_table[8443] = "HTTPS-Alt";
    port_table[27017]= "MongoDB";
}

std::string ServiceDetector::grab_banner(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    // Для HTTP отправляем запрос
    if (port == 80 || port == 8080) {
        std::string req = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n";
        send(sock, req.c_str(), req.size(), 0);
    }

    char buffer[512] = {0};
    recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);

    std::string banner(buffer);
    // Убираем лишние символы
    while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r'))
        banner.pop_back();

    return banner;
}

// Парсим версию из баннера
std::string ServiceDetector::parse_version(const std::string& banner, const std::string& service) {
    if (banner.empty()) return service;

    // SSH: "SSH-2.0-OpenSSH_8.4p1"
    if (service == "SSH") {
        size_t pos = banner.find("SSH-");
        if (pos != std::string::npos) {
            std::string ver = banner.substr(pos, 30);
            // Убираем лишнее после пробела
            size_t space = ver.find(' ');
            if (space != std::string::npos) ver = ver.substr(0, space);
            return "SSH " + ver;
        }
    }

    // FTP: "220 FileZilla Server 1.2"
    if (service == "FTP") {
        if (banner.size() > 4) {
            return "FTP " + banner.substr(4, 30);
        }
    }

    // HTTP: ищем Server: Apache/2.4
    if (service == "HTTP" || service == "HTTP-Alt") {
        size_t pos = banner.find("Server:");
        if (pos != std::string::npos) {
            std::string ver = banner.substr(pos + 8, 30);
            size_t nl = ver.find('\n');
            if (nl != std::string::npos) ver = ver.substr(0, nl);
            return "HTTP " + ver;
        }
        return "HTTP";
    }

    // SMTP: "220 mail.example.com ESMTP"
    if (service == "SMTP") {
        if (banner.size() > 4) {
            return "SMTP " + banner.substr(4, 25);
        }
    }

    // Если не распознали — возвращаем первые 40 символов баннера
    if (banner.size() > 0) {
        return service + " [" + banner.substr(0, 40) + "]";
    }

    return service;
}

std::string ServiceDetector::get_version(const std::string& ip, int port) {
    std::string service = "unknown";
    if (port_table.count(port)) {
        service = port_table[port];
    }

    std::string banner = grab_banner(ip, port);
    return parse_version(banner, service);
}

std::string ServiceDetector::detect(const std::string& ip, int port) {
    std::string service = "unknown";
    if (port_table.count(port)) {
        service = port_table[port];
    }

    std::string banner = grab_banner(ip, port);
    return parse_version(banner, service);
}