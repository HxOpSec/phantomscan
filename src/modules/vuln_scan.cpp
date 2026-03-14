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

// ── Banner grabber ────────────────────────────────────
std::string VulnScanner::grab_version(const std::string& target, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(target.c_str(), nullptr, &hints, &res) != 0) {
        close(sock); return "";
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr   = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock); return "";
    }

    // Отправляем запрос в зависимости от порта
    std::string req;
    if (port == 80 || port == 8080 || port == 8000 || port == 8008)
        req = "HEAD / HTTP/1.0\r\nHost: " + target + "\r\n\r\n";
    else if (port == 443 || port == 8443)
        req = "HEAD / HTTP/1.0\r\nHost: " + target + "\r\n\r\n";
    else if (port == 3306)  // MySQL greeting
        req = "";
    else if (port == 5432)  // PostgreSQL startup
        req = "";
    else if (port == 6379)  // Redis
        req = "INFO server\r\n";
    else if (port == 9200)  // Elasticsearch
        req = "GET / HTTP/1.0\r\nHost: " + target + "\r\n\r\n";
    else if (port == 11211) // Memcached
        req = "version\r\n";
    else if (port == 5672 || port == 15672) // RabbitMQ
        req = "";
    else if (port == 9042)  // Cassandra
        req = "";
    else if (port == 1521)  // Oracle
        req = "";
    else if (port == 2375 || port == 2376) // Docker API
        req = "GET /version HTTP/1.0\r\nHost: " + target + "\r\n\r\n";
    else if (port == 8500)  // Consul
        req = "GET /v1/agent/self HTTP/1.0\r\nHost: " + target + "\r\n\r\n";
    else if (port == 4848)  // GlassFish admin
        req = "GET / HTTP/1.0\r\nHost: " + target + "\r\n\r\n";
    else if (port == 8161)  // ActiveMQ
        req = "GET / HTTP/1.0\r\nHost: " + target + "\r\n\r\n";

    if (!req.empty())
        send(sock, req.c_str(), req.size(), 0);

    char buf[2048];
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);
    return std::string(buf);
}

// ── Определяем severity по баннеру ───────────────────
std::string VulnScanner::detect_severity(const std::string& banner,
                                          const std::string& service) {
    if (service == "SSH") {
        if (banner.find("OpenSSH_3.")  != std::string::npos) return "CRITICAL";
        if (banner.find("OpenSSH_4.")  != std::string::npos) return "CRITICAL";
        if (banner.find("OpenSSH_5.")  != std::string::npos) return "CRITICAL";
        if (banner.find("OpenSSH_6.")  != std::string::npos) return "CRITICAL"; // CVE-2016-6210, username enum
        if (banner.find("OpenSSH_7.1") != std::string::npos) return "CRITICAL"; // CVE-2016-0777
        if (banner.find("OpenSSH_7.2") != std::string::npos) return "HIGH";     // CVE-2016-6515
        if (banner.find("OpenSSH_7.3") != std::string::npos) return "HIGH";
        if (banner.find("OpenSSH_7.4") != std::string::npos) return "HIGH";
        if (banner.find("OpenSSH_7.5") != std::string::npos) return "HIGH";
        if (banner.find("OpenSSH_7.6") != std::string::npos) return "HIGH";
        if (banner.find("OpenSSH_7.7") != std::string::npos) return "HIGH";     // CVE-2018-15473
        if (banner.find("OpenSSH_7.")  != std::string::npos) return "HIGH";
        if (banner.find("OpenSSH_8.0") != std::string::npos) return "MEDIUM";
        if (banner.find("OpenSSH_8.1") != std::string::npos) return "MEDIUM";
        if (banner.find("OpenSSH_8.2") != std::string::npos) return "MEDIUM";
        if (banner.find("OpenSSH_8.")  != std::string::npos) return "LOW";
        if (banner.find("OpenSSH_9.")  != std::string::npos) return "LOW";
        if (!banner.empty()) return "LOW";
    }
    if (service == "FTP") {
        if (banner.find("vsftpd 2.3.4")  != std::string::npos) return "CRITICAL";
        if (banner.find("ProFTPD 1.3.3") != std::string::npos) return "CRITICAL";
        if (banner.find("ProFTPD 1.3.5") != std::string::npos) return "HIGH";
        if (banner.find("wu-ftpd")        != std::string::npos) return "CRITICAL";
        if (!banner.empty()) return "MEDIUM";
    }
    if (service == "HTTP" || service == "HTTPS") {
        // Apache — уязвимые версии
        if (banner.find("Apache/2.4.49") != std::string::npos) return "CRITICAL"; // CVE-2021-41773
        if (banner.find("Apache/2.4.50") != std::string::npos) return "CRITICAL"; // CVE-2021-42013
        if (banner.find("Apache/2.0.")   != std::string::npos) return "CRITICAL"; // очень старая
        if (banner.find("Apache/2.2.")   != std::string::npos) return "HIGH";     // EOL
        if (banner.find("Apache/2.3.")   != std::string::npos) return "HIGH";     // beta/old
        if (banner.find("Apache/2.4.1")  != std::string::npos) return "HIGH";     // 2.4.1-2.4.19
        if (banner.find("Apache/2.4.2")  != std::string::npos) return "HIGH";
        if (banner.find("Apache/2.4.3")  != std::string::npos) return "HIGH";
        if (banner.find("Apache/2.4.4")  != std::string::npos) return "HIGH";
        if (banner.find("Apache/2.4.5")  != std::string::npos) return "HIGH";
        if (banner.find("Apache/2.4.6")  != std::string::npos) return "HIGH";
        if (banner.find("Apache/2.4.7")  != std::string::npos) return "HIGH";     // Ubuntu 14.04
        if (banner.find("Apache/2.4.8")  != std::string::npos) return "HIGH";
        if (banner.find("Apache/2.4.9")  != std::string::npos) return "HIGH";
        // nginx — уязвимые версии
        if (banner.find("nginx/1.0.")    != std::string::npos) return "CRITICAL";
        if (banner.find("nginx/1.2.")    != std::string::npos) return "HIGH";
        if (banner.find("nginx/1.4.")    != std::string::npos) return "HIGH";
        if (banner.find("nginx/1.6.")    != std::string::npos) return "HIGH";
        if (banner.find("nginx/1.8.")    != std::string::npos) return "MEDIUM";
        if (banner.find("nginx/1.10.")   != std::string::npos) return "MEDIUM";
        if (banner.find("nginx/1.12.")   != std::string::npos) return "MEDIUM";
        if (banner.find("nginx/1.14.")   != std::string::npos) return "HIGH";
        if (banner.find("nginx/1.16.")   != std::string::npos) return "MEDIUM";
        if (banner.find("nginx/1.18.")   != std::string::npos) return "LOW";
        // IIS
        if (banner.find("IIS/5.0")       != std::string::npos) return "CRITICAL";
        if (banner.find("IIS/6.0")       != std::string::npos) return "CRITICAL"; // EOL 2015
        if (banner.find("IIS/7.0")       != std::string::npos) return "HIGH";
        if (banner.find("IIS/7.5")       != std::string::npos) return "HIGH";
        if (banner.find("IIS/8.0")       != std::string::npos) return "MEDIUM";
        if (banner.find("IIS/8.5")       != std::string::npos) return "MEDIUM";
        // Другие
        if (banner.find("Jetty/")        != std::string::npos) return "MEDIUM";
        if (banner.find("Tomcat/")       != std::string::npos) return "MEDIUM";
        if (banner.find("lighttpd/1.4.") != std::string::npos) return "MEDIUM";
        if (banner.find("WebSphere")     != std::string::npos) return "HIGH";
        if (banner.find("JBoss")         != std::string::npos) return "HIGH";
        if (banner.find("Werkzeug")      != std::string::npos) return "MEDIUM"; // debug mode?
        if (!banner.empty()) return "LOW"; // любой сервер = показываем версию
    }
    if (service == "SMTP") {
        if (banner.find("Sendmail")   != std::string::npos) return "MEDIUM";
        if (banner.find("Exim 4.8")   != std::string::npos) return "HIGH";
        if (banner.find("Exim 4.9")   != std::string::npos) return "HIGH";
        if (banner.find("Postfix")    != std::string::npos) return "LOW";
        if (!banner.empty()) return "MEDIUM";
    }
    if (service == "Telnet") {
        if (!banner.empty()) return "HIGH"; // Telnet = plaintext всегда опасно
    }
    if (service == "Redis") {
        if (!banner.empty()) return "CRITICAL"; // без auth = RCE
    }
    if (service == "MongoDB") {
        if (!banner.empty()) return "HIGH";
    }
    if (service == "Elasticsearch") {
        if (banner.find("cluster_name") != std::string::npos) return "CRITICAL";
        if (!banner.empty()) return "HIGH";
    }
    if (service == "Memcached") {
        if (!banner.empty()) return "HIGH"; // без auth, reflection DDoS
    }
    if (service == "Docker API") {
        if (banner.find("ApiVersion") != std::string::npos) return "CRITICAL"; // открытый Docker = RCE
        if (!banner.empty()) return "CRITICAL";
    }
    if (service == "Consul") {
        if (!banner.empty()) return "HIGH"; // без ACL = полный доступ
    }
    if (service == "RabbitMQ") {
        if (!banner.empty()) return "MEDIUM";
    }
    if (service == "ActiveMQ") {
        if (banner.find("ActiveMQ") != std::string::npos) return "CRITICAL"; // CVE-2023-46604
        if (!banner.empty()) return "HIGH";
    }
    if (service == "GlassFish") {
        if (!banner.empty()) return "HIGH";
    }
    if (service == "VNC") {
        if (!banner.empty()) return "HIGH"; // открытый VNC без пароля
    }
    if (service == "MSSQL") {
        if (!banner.empty()) return "HIGH";
    }
    if (service == "Oracle DB") {
        if (!banner.empty()) return "HIGH";
    }
    if (service == "Cassandra") {
        if (!banner.empty()) return "MEDIUM";
    }
    if (service == "LDAP") {
        if (!banner.empty()) return "MEDIUM";
    }
    if (service == "SNMP") {
        if (!banner.empty()) return "HIGH"; // community string = info leak
    }
    return "";
}

std::vector<VulnResult> VulnScanner::scan(const std::string& target,
                                            int port_start, int port_end) {
    std::vector<VulnResult> results;

    std::cout << Color::INFO << "Сканер уязвимых версий: "
              << Color::CYAN << target << Color::RESET << "\n";

    struct PS { int port; const char* service; const char* cve; const char* desc; };
    std::vector<PS> known = {
        // Стандартные сервисы
        {21,    "FTP",           "CVE-2011-2523",  "vsftpd backdoor / ProFTPD RCE"},
        {22,    "SSH",           "CVE-2023-38408", "OpenSSH RCE / username enum"},
        {23,    "Telnet",        "CVE-1999-0619",  "Plaintext credentials"},
        {25,    "SMTP",          "CVE-2019-10149", "Exim RCE / open relay"},
        {53,    "DNS",           "CVE-2020-1350",  "DNS zone transfer / SIGRed"},
        {80,    "HTTP",          "CVE-2021-41773", "Apache Path Traversal / IIS"},
        {110,   "POP3",          "CVE-2003-0143",  "POP3 plaintext / buffer overflow"},
        {111,   "RPCbind",       "CVE-2017-8779",  "RPCbind amplification DDoS"},
        {135,   "MSRPC",         "CVE-2003-0352",  "MS RPC DCOM buffer overflow"},
        {139,   "NetBIOS",       "CVE-2017-0144",  "EternalBlue / SMB vuln"},
        {143,   "IMAP",          "CVE-2021-38371", "IMAP plaintext credentials"},
        {389,   "LDAP",          "CVE-2021-44228", "LDAP injection / Log4Shell"},
        {443,   "HTTPS",         "CVE-2021-41773", "Apache Path Traversal"},
        {445,   "SMB",           "CVE-2017-0144",  "EternalBlue MS17-010"},
        {512,   "RSH",           "CVE-1999-0651",  "rsh no auth remote exec"},
        {513,   "Rlogin",        "CVE-1999-0653",  "rlogin no auth"},
        {514,   "RSH/Syslog",    "CVE-1999-0651",  "rsh trust bypass"},
        {873,   "Rsync",         "CVE-2014-9512",  "Rsync no-auth file access"},
        {1099,  "Java RMI",      "CVE-2011-3556",  "Java RMI deserialization RCE"},
        {1433,  "MSSQL",         "CVE-2020-0618",  "MSSQL RCE / SA brute"},
        {1521,  "Oracle DB",     "CVE-2012-1675",  "Oracle TNS poison"},
        {2049,  "NFS",           "CVE-2019-3010",  "NFS no-auth file access"},
        {2375,  "Docker API",    "CVE-2019-5736",  "Docker daemon no-auth = RCE"},
        {2376,  "Docker API",    "CVE-2019-5736",  "Docker TLS bypass"},
        {3000,  "Grafana",       "CVE-2021-43798", "Grafana path traversal"},
        {3306,  "MySQL",         "CVE-2012-2122",  "MySQL auth bypass"},
        {3389,  "RDP",           "CVE-2019-0708",  "BlueKeep RDP RCE"},
        {4848,  "GlassFish",     "CVE-2011-0807",  "GlassFish admin no-auth"},
        {5432,  "PostgreSQL",    "CVE-2019-9193",  "PostgreSQL superuser RCE"},
        {5672,  "RabbitMQ",      "CVE-2023-46120", "RabbitMQ default creds"},
        {5900,  "VNC",           "CVE-2019-15694", "VNC no-auth / weak password"},
        {5984,  "CouchDB",       "CVE-2017-12636", "CouchDB RCE no-auth"},
        {6379,  "Redis",         "CVE-2022-0543",  "Redis no-auth RCE"},
        {7001,  "WebLogic",      "CVE-2020-14882", "Oracle WebLogic RCE"},
        {8009,  "AJP",           "CVE-2020-1938",  "Ghostcat AJP file read"},
        {8080,  "HTTP",          "CVE-2021-41773", "HTTP alternate port"},
        {8161,  "ActiveMQ",      "CVE-2023-46604", "ActiveMQ RCE"},
        {8443,  "HTTPS",         "CVE-2021-41773", "HTTPS alternate port"},
        {8500,  "Consul",        "CVE-2018-19653", "Consul no-ACL RCE"},
        {9000,  "PHP-FPM",       "CVE-2019-11043", "PHP-FPM RCE"},
        {9042,  "Cassandra",     "CVE-2015-0225",  "Cassandra no-auth"},
        {9200,  "Elasticsearch", "CVE-2021-44228", "Elasticsearch no-auth / Log4j"},
        {11211, "Memcached",     "CVE-2018-1000115","Memcached no-auth DDoS"},
        {15672, "RabbitMQ",      "CVE-2023-46120", "RabbitMQ web admin"},
        {27017, "MongoDB",       "CVE-2013-4650",  "MongoDB no-auth exposure"},
        {50000, "SAP",           "CVE-2020-6287",  "SAP RECON RCE"},
    };

    for (auto& ps : known) {
        if (ps.port < port_start || ps.port > port_end) continue;

        std::cout << Color::INFO << "  Checking "
                  << std::setw(5) << ps.port
                  << " (" << std::left << std::setw(14) << ps.service << ")..."
                  << Color::RESET << "\r" << std::flush;

        std::string banner = grab_version(target, ps.port);
        if (banner.empty()) continue;

        std::string severity = detect_severity(banner, ps.service);
        if (severity.empty()) continue;

        // Извлекаем первую значимую строку
        std::string version;
        std::istringstream iss(banner);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.find("Server:")      != std::string::npos ||
                line.find("SSH-")         != std::string::npos ||
                line.find("220 ")         != std::string::npos ||
                line.find("redis_version")!= std::string::npos ||
                line.find("VERSION")      != std::string::npos ||
                line.find("cluster_name") != std::string::npos ||
                line.find("FTP")          != std::string::npos) {
                version = line;
                break;
            }
        }
        if (version.empty()) version = banner.substr(0, 60);

        version.erase(std::remove(version.begin(), version.end(), '\r'), version.end());
        version.erase(std::remove(version.begin(), version.end(), '\n'), version.end());

        VulnResult r;
        r.service     = ps.service;
        r.version     = version;
        r.severity    = severity;
        r.cve_id      = ps.cve;
        r.description = ps.desc;
        results.push_back(r);

        std::string col = (severity == "CRITICAL") ? Color::RED :
                          (severity == "HIGH")     ? Color::YELLOW : Color::INFO;
        std::cout << col << "[!] " << std::left << std::setw(14) << ps.service
                  << " PORT:" << ps.port << " → " << severity
                  << Color::RESET << std::string(10, ' ') << "\n";
    }

    return results;
}

void VulnScanner::print_results(const std::vector<VulnResult>& results) {
    if (results.empty()) {
        std::cout << Color::GREEN
                  << "[+] Vulnerable versions not found\n"
                  << Color::RESET;
        return;
    }

    std::cout << "\n" << Color::CYAN
              << "╔════════════════╦══════════╦════════════════════════════════╗\n"
              << "║  SERVICE       ║ SEVERITY ║  VERSION / BANNER              ║\n"
              << "╠════════════════╬══════════╬════════════════════════════════╣\n"
              << Color::RESET;

    for (const auto& r : results) {
        std::string svc = r.service;
        std::string sev = r.severity;
        std::string ver = r.version;

        while ((int)svc.size() < 14) svc += " ";
        while ((int)sev.size() < 8)  sev += " ";
        if ((int)ver.size() > 30) ver = ver.substr(0, 27) + "...";
        while ((int)ver.size() < 30) ver += " ";

        std::string col = (r.severity == "CRITICAL") ? Color::RED    :
                          (r.severity == "HIGH")     ? Color::YELLOW :
                          (r.severity == "MEDIUM")   ? Color::CYAN   : Color::WHITE;

        std::cout << col
                  << "║ " << svc << " ║ " << sev << " ║ " << ver << " ║\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN
              << "╚════════════════╩══════════╩════════════════════════════════╝\n"
              << Color::RESET;
    std::cout << Color::RED << "[!] Vulnerabilities found: "
              << results.size() << Color::RESET << "\n";
}