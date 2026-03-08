#include <algorithm>
#include "modules/vuln_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

// Захватываем баннер с версией
std::string VulnScanner::grab_version(const std::string& target,
                                       int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct hostent* he = gethostbyname(target.c_str());
    if (!he) { close(sock); return ""; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock); return "";
    }

    // Для HTTP отправляем запрос
    if (port == 80 || port == 8080 || port == 8000) {
        std::string req = "HEAD / HTTP/1.0\r\nHost: "
                        + target + "\r\n\r\n";
        send(sock, req.c_str(), req.size(), 0);
    }

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);

    return std::string(buf);
}

// Определяем уязвимые версии
std::string VulnScanner::detect_severity(const std::string& version,
                                          const std::string& service) {
    // Уязвимые версии OpenSSH
    if (service == "SSH") {
        if (version.find("OpenSSH_7.") != std::string::npos)
            return "HIGH";
        if (version.find("OpenSSH_6.") != std::string::npos)
            return "CRITICAL";
        if (version.find("OpenSSH_5.") != std::string::npos)
            return "CRITICAL";
    }
    // Уязвимые версии Apache
    if (service == "HTTP" || service == "HTTPS") {
        if (version.find("Apache/2.4.49") != std::string::npos)
            return "CRITICAL"; // Path Traversal CVE-2021-41773
        if (version.find("Apache/2.4.50") != std::string::npos)
            return "CRITICAL"; // CVE-2021-42013
        if (version.find("Apache/2.2.") != std::string::npos)
            return "HIGH";
    }
    // Уязвимые версии nginx
    if (version.find("nginx/1.16.") != std::string::npos)
        return "MEDIUM";
    if (version.find("nginx/1.14.") != std::string::npos)
        return "HIGH";

    // Уязвимые версии vsftpd
    if (service == "FTP") {
        if (version.find("vsftpd 2.3.4") != std::string::npos)
            return "CRITICAL"; // Backdoor CVE-2011-2523
        if (version.find("ProFTPD 1.3.3") != std::string::npos)
            return "CRITICAL";
    }

    return "";
}

std::vector<VulnResult> VulnScanner::scan(const std::string& target,
                                            int port_start,
                                            int port_end) {
    std::vector<VulnResult> results;

    std::cout << Color::INFO << "Сканер уязвимых версий: "
              << Color::CYAN << target << Color::RESET << std::endl;

    // Таблица портов и служб
    struct PortService { int port; std::string service; };
    std::vector<PortService> known = {
        {21,   "FTP"},   {22,  "SSH"},  {23,  "Telnet"},
        {25,   "SMTP"},  {80,  "HTTP"}, {443, "HTTPS"},
        {3306, "MySQL"}, {5432,"PostgreSQL"},
        {6379, "Redis"}, {8080,"HTTP"}, {8443,"HTTPS"},
        {27017,"MongoDB"},{9200,"Elasticsearch"}
    };

    for (auto& ps : known) {
        if (ps.port < port_start || ps.port > port_end) continue;

        std::cout << Color::INFO << "Проверяем порт "
                  << ps.port << " (" << ps.service << ")..."
                  << Color::RESET << std::endl;

        std::string banner = grab_version(target, ps.port);
        if (banner.empty()) continue;

        // Ищем версию в баннере
        std::string version = "";
        std::string severity = detect_severity(banner, ps.service);

        if (severity.empty()) continue; // версия не уязвимая

        // Вытаскиваем строку версии
        std::istringstream iss(banner);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.find("Server:") != std::string::npos ||
                line.find("SSH-")   != std::string::npos ||
                line.find("FTP")    != std::string::npos) {
                version = line;
                break;
            }
        }
        if (version.empty()) version = banner.substr(0, 50);

        // Убираем \r\n
        version.erase(std::remove(version.begin(),
                                   version.end(), '\r'),
                       version.end());
        version.erase(std::remove(version.begin(),
                                   version.end(), '\n'),
                       version.end());

        VulnResult r;
        r.service     = ps.service;
        r.version     = version;
        r.severity    = severity;

        if (severity == "CRITICAL") {
            r.cve_id      = "CVE-KNOWN-CRITICAL";
            r.description = "Уязвимая версия ПО!";
        } else if (severity == "HIGH") {
            r.cve_id      = "CVE-KNOWN-HIGH";
            r.description = "Устаревшая версия с уязвимостями";
        } else {
            r.cve_id      = "CVE-KNOWN-MEDIUM";
            r.description = "Рекомендуется обновление";
        }

        results.push_back(r);
        std::cout << Color::FAIL << "[!] Уязвимость найдена: "
                  << ps.service << " → " << severity
                  << Color::RESET << std::endl;
    }

    return results;
}

void VulnScanner::print_results(
        const std::vector<VulnResult>& results) {
    if (results.empty()) {
        std::cout << Color::OK
                  << "Уязвимых версий не обнаружено"
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌──────────┬──────────┬────────────────────────────────────┐\n";
    std::cout << "│  СЛУЖБА  │ SEVERITY │          ВЕРСИЯ                    │\n";
    std::cout << "├──────────┼──────────┼────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& r : results) {
        std::string svc = r.service;
        while (svc.size() < 8) svc += " ";
        std::string sev = r.severity;
        while (sev.size() < 8) sev += " ";
        std::string ver = r.version;
        if (ver.size() > 34) ver = ver.substr(0, 31) + "...";
        while (ver.size() < 34) ver += " ";

        if (r.severity == "CRITICAL")
            std::cout << Color::FAIL;
        else if (r.severity == "HIGH")
            std::cout << Color::WARN;
        else
            std::cout << Color::INFO;

        std::cout << "│ " << svc << " │ " << sev
                  << " │ " << ver << " │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└──────────┴──────────┴────────────────────────────────────┘\n";
    std::cout << Color::RESET;
    std::cout << Color::FAIL << "Уязвимостей найдено: "
              << results.size() << Color::RESET << std::endl;
}