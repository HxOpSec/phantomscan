#include "modules/http_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

struct PathEntry { const char* path; const char* risk; const char* desc; };

static const PathEntry PATHS[] = {
    // ── CRITICAL — утечка ключей/паролей/БД ──────────
    {"/.env",                   "CRITICAL", "Environment file (passwords/API keys)"},
    {"/.env.local",             "CRITICAL", "Local .env (passwords)"},
    {"/.env.production",        "CRITICAL", "Production .env"},
    {"/.env.backup",            "CRITICAL", "Backup .env file"},
    {"/.env.dev",               "CRITICAL", "Dev .env file"},
    {"/.env.staging",           "CRITICAL", "Staging .env file"},
    {"/.git/config",            "CRITICAL", "Git config (repo leak)"},
    {"/.git/HEAD",              "CRITICAL", "Git HEAD (source code)"},
    {"/.git/index",             "CRITICAL", "Git index"},
    {"/.gitignore",             "CRITICAL", "Gitignore (structure leak)"},
    {"/backup.sql",             "CRITICAL", "Database dump"},
    {"/database.sql",           "CRITICAL", "Database dump"},
    {"/db.sql",                 "CRITICAL", "Database dump"},
    {"/dump.sql",               "CRITICAL", "Database dump"},
    {"/data.sql",               "CRITICAL", "Database dump"},
    {"/mysql.sql",              "CRITICAL", "MySQL dump"},
    {"/config.php.bak",         "CRITICAL", "PHP config backup"},
    {"/wp-config.php.bak",      "CRITICAL", "WordPress config backup"},
    {"/wp-config.php~",         "CRITICAL", "WordPress config backup"},
    {"/sftp-config.json",       "CRITICAL", "SFTP credentials"},
    {"/.ssh/id_rsa",            "CRITICAL", "Private SSH key"},
    {"/.ssh/authorized_keys",   "CRITICAL", "SSH authorized keys"},
    {"/.htpasswd",              "CRITICAL", "HTTP passwords"},
    {"/credentials.json",       "CRITICAL", "Credentials file"},
    {"/secrets.yml",            "CRITICAL", "Secrets YAML"},
    {"/secrets.json",           "CRITICAL", "Secrets JSON"},
    {"/private.key",            "CRITICAL", "Private key file"},
    {"/server.key",             "CRITICAL", "Server private key"},
    {"/.aws/credentials",       "CRITICAL", "AWS credentials"},
    {"/cloud.json",             "CRITICAL", "Cloud credentials"},

    // ── HIGH — admin panels ───────────────────────────
    {"/admin",                  "HIGH", "Admin panel"},
    {"/admin/",                 "HIGH", "Admin panel"},
    {"/admin/login",            "HIGH", "Admin login"},
    {"/admin/dashboard",        "HIGH", "Admin dashboard"},
    {"/administrator",          "HIGH", "Joomla/generic admin"},
    {"/administrator/",         "HIGH", "Joomla admin"},
    {"/wp-admin",               "HIGH", "WordPress admin"},
    {"/wp-admin/",              "HIGH", "WordPress admin"},
    {"/phpmyadmin",             "HIGH", "phpMyAdmin"},
    {"/phpmyadmin/",            "HIGH", "phpMyAdmin"},
    {"/pma",                    "HIGH", "phpMyAdmin short"},
    {"/pma/",                   "HIGH", "phpMyAdmin short"},
    {"/mysql",                  "HIGH", "MySQL admin"},
    {"/manager",                "HIGH", "Tomcat Manager"},
    {"/manager/html",           "HIGH", "Tomcat Manager HTML"},
    {"/console",                "HIGH", "Management console"},
    {"/dashboard",              "HIGH", "Dashboard"},
    {"/login",                  "HIGH", "Login page"},
    {"/signin",                 "HIGH", "Sign in page"},
    {"/cp",                     "HIGH", "Control panel"},
    {"/controlpanel",           "HIGH", "Control panel"},
    {"/cpanel",                 "HIGH", "cPanel"},
    {"/webadmin",               "HIGH", "Web admin"},
    {"/jenkins",                "HIGH", "Jenkins CI/CD"},
    {"/jenkins/",               "HIGH", "Jenkins CI/CD"},
    {"/gitlab",                 "HIGH", "GitLab"},
    {"/grafana",                "HIGH", "Grafana dashboard"},
    {"/grafana/",               "HIGH", "Grafana dashboard"},
    {"/kibana",                 "HIGH", "Kibana UI"},
    {"/portainer",              "HIGH", "Portainer (Docker UI)"},
    {"/adminer.php",            "HIGH", "Adminer DB manager"},
    {"/shell.php",              "HIGH", "PHP webshell!"},
    {"/cmd.php",                "HIGH", "PHP webshell!"},
    {"/c99.php",                "HIGH", "c99 webshell!"},
    {"/r57.php",                "HIGH", "r57 webshell!"},
    {"/webshell.php",           "HIGH", "PHP webshell!"},

    // ── HIGH — backups & archives ─────────────────────
    {"/backup",                 "HIGH", "Backup directory"},
    {"/backup/",                "HIGH", "Backup directory"},
    {"/backups/",               "HIGH", "Backup directory"},
    {"/backup.zip",             "HIGH", "Backup archive"},
    {"/backup.tar.gz",          "HIGH", "Backup archive"},
    {"/backup.tar",             "HIGH", "Backup archive"},
    {"/site.zip",               "HIGH", "Site archive"},
    {"/www.zip",                "HIGH", "Site archive"},
    {"/web.zip",                "HIGH", "Web archive"},
    {"/old/",                   "HIGH", "Old version directory"},
    {"/old.zip",                "HIGH", "Old version archive"},
    {"/.DS_Store",              "HIGH", "macOS metadata (dir structure)"},
    {"/Thumbs.db",              "HIGH", "Windows thumbnail DB"},
    {"/core",                   "HIGH", "Core dump file"},

    // ── MEDIUM — configs & info ───────────────────────
    {"/phpinfo.php",            "MEDIUM", "phpinfo() — server info"},
    {"/info.php",               "MEDIUM", "phpinfo()"},
    {"/php.php",                "MEDIUM", "phpinfo()"},
    {"/test.php",               "MEDIUM", "Test PHP file"},
    {"/test/",                  "MEDIUM", "Test directory"},
    {"/config.php",             "MEDIUM", "PHP config"},
    {"/config.yml",             "MEDIUM", "YAML config"},
    {"/config.yaml",            "MEDIUM", "YAML config"},
    {"/config.json",            "MEDIUM", "JSON config"},
    {"/configuration.php",      "MEDIUM", "Joomla config"},
    {"/settings.php",           "MEDIUM", "Settings file"},
    {"/settings.py",            "MEDIUM", "Django settings"},
    {"/web.config",             "MEDIUM", "IIS web.config"},
    {"/server-status",          "MEDIUM", "Apache server-status"},
    {"/server-info",            "MEDIUM", "Apache server-info"},
    {"/.well-known/",           "MEDIUM", "Well-known directory"},
    {"/api",                    "MEDIUM", "API endpoint"},
    {"/api/v1",                 "MEDIUM", "API v1"},
    {"/api/v2",                 "MEDIUM", "API v2"},
    {"/api/v3",                 "MEDIUM", "API v3"},
    {"/swagger",                "MEDIUM", "Swagger API docs"},
    {"/swagger-ui.html",        "MEDIUM", "Swagger UI"},
    {"/swagger.json",           "MEDIUM", "Swagger JSON spec"},
    {"/openapi.json",           "MEDIUM", "OpenAPI spec"},
    {"/api-docs",               "MEDIUM", "API documentation"},
    {"/actuator",               "MEDIUM", "Spring Boot Actuator"},
    {"/actuator/health",        "MEDIUM", "Spring Boot health"},
    {"/actuator/env",           "MEDIUM", "Spring Boot env (dangerous!)"},
    {"/actuator/beans",         "MEDIUM", "Spring Boot beans"},
    {"/actuator/mappings",      "MEDIUM", "Spring Boot mappings"},
    {"/metrics",                "MEDIUM", "App metrics"},
    {"/health",                 "MEDIUM", "Health check"},
    {"/status",                 "MEDIUM", "Status endpoint"},
    {"/debug",                  "MEDIUM", "Debug endpoint"},
    {"/trace",                  "MEDIUM", "Trace endpoint"},
    {"/graphql",                "MEDIUM", "GraphQL endpoint"},
    {"/graphiql",               "MEDIUM", "GraphiQL IDE"},
    {"/__debug__/",             "MEDIUM", "Django debug toolbar"},
    {"/django-admin",           "MEDIUM", "Django admin"},
    {"/rails/info",             "MEDIUM", "Rails info page"},
    {"/telescope",              "MEDIUM", "Laravel Telescope"},
    {"/horizon",                "MEDIUM", "Laravel Horizon"},
    {"/nova",                   "MEDIUM", "Laravel Nova"},

    // ── INFO — standard paths ─────────────────────────
    {"/robots.txt",             "INFO", "robots.txt (site map)"},
    {"/sitemap.xml",            "INFO", "Sitemap"},
    {"/sitemap_index.xml",      "INFO", "Sitemap index"},
    {"/crossdomain.xml",        "INFO", "Flash crossdomain policy"},
    {"/favicon.ico",            "INFO", "Favicon"},
    {"/.htaccess",              "INFO", "Apache .htaccess"},
    {"/readme.html",            "INFO", "README (CMS version)"},
    {"/readme.txt",             "INFO", "README"},
    {"/README.md",              "INFO", "README markdown"},
    {"/changelog.txt",          "INFO", "Changelog (software version)"},
    {"/license.txt",            "INFO", "License file"},
    {"/wp-login.php",           "INFO", "WordPress login"},
    {"/xmlrpc.php",             "INFO", "WordPress XML-RPC"},
    {"/wp-json/",               "INFO", "WordPress REST API"},
    {"/wp-content/",            "INFO", "WordPress content dir"},
    {"/wp-includes/",           "INFO", "WordPress includes"},
    {"/upload",                 "INFO", "Upload directory"},
    {"/uploads/",               "INFO", "Upload directory"},
    {"/files/",                 "INFO", "Files directory"},
    {"/images/",                "INFO", "Images directory"},
    {"/img/",                   "INFO", "Images directory"},
    {"/static/",                "INFO", "Static files"},
    {"/assets/",                "INFO", "Assets directory"},
    {"/js/",                    "INFO", "JavaScript files"},
    {"/css/",                   "INFO", "CSS files"},
    {"/logs/",                  "INFO", "Logs directory"},
    {"/log/",                   "INFO", "Log directory"},
    {"/temp/",                  "INFO", "Temp directory"},
    {"/tmp/",                   "INFO", "Temp directory"},
    {"/cache/",                 "INFO", "Cache directory"},
    {"/cgi-bin/",               "INFO", "CGI directory"},
    {"/include/",               "INFO", "Include directory"},
    {"/includes/",              "INFO", "Includes directory"},
    {"/vendor/",                "INFO", "Vendor directory"},
    {"/node_modules/",          "INFO", "Node modules"},
    {"/dist/",                  "INFO", "Distribution files"},
    {"/src/",                   "INFO", "Source directory"},
};

static const int PATHS_COUNT = sizeof(PATHS) / sizeof(PATHS[0]);

// ── HTTP запрос ───────────────────────────────────────
int HTTPScanner::check_path(const std::string& host, int port,
                             const std::string& path) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    std::string request =
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,*/*\r\n"
        "Connection: close\r\n\r\n";

    send(sock, request.c_str(), request.size(), 0);

    char buf[512];
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);

    std::string resp(buf);
    size_t sp1 = resp.find(' ');
    if (sp1 == std::string::npos) return -1;
    size_t sp2 = resp.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return -1;

    try {
        return std::stoi(resp.substr(sp1 + 1, sp2 - sp1 - 1));
    } catch (...) { return -1; }
}

// ── Сканирование ──────────────────────────────────────
std::vector<HTTPPath> HTTPScanner::scan(const std::string& target, int port) {
    std::vector<HTTPPath> results;

    std::cout << Color::INFO << "HTTP directory scan: " << Color::CYAN
              << target << ":" << port << Color::RESET << "\n";
    std::cout << Color::INFO << "Checking " << PATHS_COUNT
              << " paths...\n" << Color::RESET;
    std::cout << std::string(50, '-') << "\n";

    for (int i = 0; i < PATHS_COUNT; i++) {
        // Прогресс каждые 25 путей
        if ((i + 1) % 25 == 0)
            std::cout << Color::INFO << "  [" << i+1 << "/"
                      << PATHS_COUNT << "] checked...\r"
                      << Color::RESET << std::flush;

        std::string path = PATHS[i].path;
        int code = check_path(target, port, path);

        if (code == 200 || code == 301 || code == 302 || code == 403) {
            HTTPPath hp;
            hp.path        = path;
            hp.status_code = code;
            hp.risk        = PATHS[i].risk;
            hp.desc        = PATHS[i].desc;
            results.push_back(hp);

            std::string col = Color::WHITE;
            if      (hp.risk == "CRITICAL") col = Color::RED;
            else if (hp.risk == "HIGH")     col = Color::YELLOW;
            else if (hp.risk == "MEDIUM")   col = Color::CYAN;

            std::string status = (code == 200) ? "OPEN  " :
                                 (code == 403) ? "FORBID" : "REDIR ";

            std::cout << col << "[" << code << "] "
                      << std::left << std::setw(38) << path
                      << std::setw(9) << hp.risk
                      << Color::RESET << hp.desc << "\n";
        }
    }

    std::cout << "\n";
    return results;
}

// ── Вывод итогов ──────────────────────────────────────
void HTTPScanner::print_results(const std::vector<HTTPPath>& results) {
    if (results.empty()) {
        std::cout << Color::GREEN << "[+] No hidden paths found\n"
                  << Color::RESET;
        return;
    }

    int crit = 0, high = 0, med = 0, info = 0;
    for (const auto& r : results) {
        if      (r.risk == "CRITICAL") crit++;
        else if (r.risk == "HIGH")     high++;
        else if (r.risk == "MEDIUM")   med++;
        else                           info++;
    }

    // Ширина: ║ CODE(5) ║ PATH(36) ║ RISK(8) ║ STATUS(8) ║
    std::cout << "\n" << Color::CYAN
              << "╔═══════╦══════════════════════════════════════╦══════════╦══════════╗\n"
              << "║ CODE  ║  PATH                                ║  RISK    ║  STATUS  ║\n"
              << "╠═══════╬══════════════════════════════════════╬══════════╬══════════╣\n"
              << Color::RESET;

    for (const auto& r : results) {
        std::string path = r.path;
        std::string risk = r.risk;
        std::string stat = (r.status_code == 200) ? "OPEN    " :
                           (r.status_code == 403) ? "FORBID  " : "REDIRECT";

        if ((int)path.size() > 36) path = path.substr(0, 33) + "...";
        while ((int)path.size() < 36) path += " ";
        while ((int)risk.size() < 8)  risk += " ";

        std::string col = Color::WHITE;
        if      (r.risk == "CRITICAL") col = Color::RED;
        else if (r.risk == "HIGH")     col = Color::YELLOW;
        else if (r.risk == "MEDIUM")   col = Color::CYAN;

        std::string code_s = std::to_string(r.status_code);
        while ((int)code_s.size() < 5) code_s += " ";
        std::cout << col
                  << "║ " << code_s << " ║ "
                  << path << " ║ "
                  << risk << " ║ "
                  << stat << " ║\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN
              << "╚═══════╩══════════════════════════════════════╩══════════╩══════════╝\n"
              << Color::RESET;

    std::cout << Color::RED    << "  CRITICAL: " << crit << "  "
              << Color::YELLOW << "HIGH: "     << high << "  "
              << Color::CYAN   << "MEDIUM: "   << med  << "  "
              << Color::GREEN  << "INFO: "     << info
              << Color::RESET  << "\n";

    if (crit > 0)
        std::cout << Color::RED
                  << "\n[!!!] CRITICAL: " << crit
                  << " dangerous paths found! Close access immediately!\n"
                  << Color::RESET;
}