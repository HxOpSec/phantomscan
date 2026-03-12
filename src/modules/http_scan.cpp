#include "modules/http_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

// ── Список путей для проверки ─────────────────────────
struct PathEntry {
    const char* path;
    const char* risk;
    const char* desc;
};

static const PathEntry PATHS[] = {
    // CRITICAL — утечка данных / RCE
    {"/.env",                  "CRITICAL", "Файл окружения (пароли/ключи API)"},
    {"/.env.local",            "CRITICAL", "Локальный .env (пароли)"},
    {"/.env.production",       "CRITICAL", "Production .env (пароли)"},
    {"/.env.backup",           "CRITICAL", "Бэкап .env файла"},
    {"/.git/config",           "CRITICAL", "Git конфиг (утечка репозитория)"},
    {"/.git/HEAD",             "CRITICAL", "Git HEAD (исходный код)"},
    {"/backup.sql",            "CRITICAL", "Дамп базы данных"},
    {"/database.sql",          "CRITICAL", "Дамп базы данных"},
    {"/db.sql",                "CRITICAL", "Дамп базы данных"},
    {"/dump.sql",              "CRITICAL", "Дамп базы данных"},
    {"/config.php.bak",        "CRITICAL", "Бэкап конфига PHP"},
    {"/wp-config.php.bak",     "CRITICAL", "Бэкап WordPress конфига"},
    {"/sftp-config.json",      "CRITICAL", "SFTP учётные данные"},
    {"/.ssh/id_rsa",           "CRITICAL", "Приватный SSH ключ"},
    {"/.htpasswd",             "CRITICAL", "HTTP пароли (htpasswd)"},

    // HIGH — панели управления / чувствительные данные
    {"/admin",                 "HIGH", "Панель администратора"},
    {"/admin/",                "HIGH", "Панель администратора"},
    {"/administrator",         "HIGH", "Панель Joomla/общая"},
    {"/wp-admin",              "HIGH", "Панель WordPress"},
    {"/wp-admin/",             "HIGH", "Панель WordPress"},
    {"/phpmyadmin",            "HIGH", "phpMyAdmin — управление БД"},
    {"/phpmyadmin/",           "HIGH", "phpMyAdmin — управление БД"},
    {"/pma",                   "HIGH", "phpMyAdmin (сокращённый путь)"},
    {"/manager",               "HIGH", "Tomcat Manager"},
    {"/manager/html",          "HIGH", "Tomcat Manager HTML"},
    {"/console",               "HIGH", "Консоль управления"},
    {"/dashboard",             "HIGH", "Дашборд"},
    {"/login",                 "HIGH", "Страница входа"},
    {"/admin/login",           "HIGH", "Страница входа (admin)"},
    {"/cp",                    "HIGH", "Control Panel"},
    {"/controlpanel",          "HIGH", "Control Panel"},
    {"/webadmin",              "HIGH", "Web Admin панель"},
    {"/jenkins",               "HIGH", "Jenkins CI/CD"},
    {"/gitlab",                "HIGH", "GitLab"},
    {"/grafana",               "HIGH", "Grafana дашборд"},
    {"/kibana",                "HIGH", "Kibana (Elasticsearch UI)"},

    // HIGH — бэкапы и архивы
    {"/backup",                "HIGH", "Папка бэкапов"},
    {"/backup/",               "HIGH", "Папка бэкапов"},
    {"/backups/",              "HIGH", "Папка бэкапов"},
    {"/backup.zip",            "HIGH", "Архив бэкапа"},
    {"/backup.tar.gz",         "HIGH", "Архив бэкапа"},
    {"/site.zip",              "HIGH", "Архив сайта"},
    {"/www.zip",               "HIGH", "Архив сайта"},
    {"/old/",                  "HIGH", "Старая версия сайта"},
    {"/old.zip",               "HIGH", "Архив старой версии"},
    {"/.DS_Store",             "HIGH", "macOS метаданные (структура папок)"},

    // MEDIUM — конфиги и инфо
    {"/phpinfo.php",           "MEDIUM", "phpinfo() — инфо о сервере"},
    {"/info.php",              "MEDIUM", "phpinfo() — инфо о сервере"},
    {"/test.php",              "MEDIUM", "Тестовый PHP файл"},
    {"/config.php",            "MEDIUM", "Конфигурационный файл PHP"},
    {"/config.yml",            "MEDIUM", "YAML конфиг"},
    {"/config.yaml",           "MEDIUM", "YAML конфиг"},
    {"/config.json",           "MEDIUM", "JSON конфиг"},
    {"/settings.php",          "MEDIUM", "Файл настроек"},
    {"/web.config",            "MEDIUM", "IIS Web.config"},
    {"/server-status",         "MEDIUM", "Apache server-status"},
    {"/server-info",           "MEDIUM", "Apache server-info"},
    {"/.well-known/",          "MEDIUM", "Well-known директория"},
    {"/api",                   "MEDIUM", "API endpoint"},
    {"/api/v1",                "MEDIUM", "API v1 endpoint"},
    {"/api/v2",                "MEDIUM", "API v2 endpoint"},
    {"/swagger",               "MEDIUM", "Swagger API документация"},
    {"/swagger-ui.html",       "MEDIUM", "Swagger UI"},
    {"/api-docs",              "MEDIUM", "API документация"},
    {"/actuator",              "MEDIUM", "Spring Boot Actuator"},
    {"/actuator/health",       "MEDIUM", "Spring Boot Health"},
    {"/actuator/env",          "MEDIUM", "Spring Boot Env (опасно!)"},
    {"/metrics",               "MEDIUM", "Метрики приложения"},
    {"/health",                "MEDIUM", "Health check endpoint"},
    {"/status",                "MEDIUM", "Status endpoint"},

    // INFO — стандартные пути
    {"/robots.txt",            "INFO", "robots.txt (карта сайта)"},
    {"/sitemap.xml",           "INFO", "Sitemap"},
    {"/crossdomain.xml",       "INFO", "Flash crossdomain политика"},
    {"/favicon.ico",           "INFO", "Favicon"},
    {"/.htaccess",             "INFO", "Apache .htaccess"},
    {"/readme.html",           "INFO", "README (версия CMS)"},
    {"/readme.txt",            "INFO", "README (версия CMS)"},
    {"/changelog.txt",         "INFO", "Changelog (версия ПО)"},
    {"/license.txt",           "INFO", "License файл"},
    {"/wp-login.php",          "INFO", "WordPress login"},
    {"/xmlrpc.php",            "INFO", "WordPress XML-RPC"},
    {"/upload",                "INFO", "Папка загрузок"},
    {"/uploads/",              "INFO", "Папка загрузок"},
    {"/files/",                "INFO", "Папка файлов"},
    {"/images/",               "INFO", "Папка изображений"},
    {"/static/",               "INFO", "Статические файлы"},
    {"/assets/",               "INFO", "Assets папка"},
    {"/js/",                   "INFO", "JavaScript файлы"},
    {"/css/",                  "INFO", "CSS файлы"},
    {"/logs/",                 "INFO", "Папка логов"},
    {"/log/",                  "INFO", "Папка логов"},
    {"/temp/",                 "INFO", "Временная папка"},
    {"/tmp/",                  "INFO", "Временная папка"},
};

static const int PATHS_COUNT = sizeof(PATHS) / sizeof(PATHS[0]);

// ── HTTP запрос через raw socket ─────────────────────
int HTTPScanner::check_path(const std::string& host, int port,
                             const std::string& path) {
    // Резолвим хост
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { freeaddrinfo(res); return -1; }

    // Таймаут 3 секунды
    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    // HTTP GET запрос
    std::string request =
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "User-Agent: Mozilla/5.0 (compatible; PhantomScan/1.0)\r\n"
        "Connection: close\r\n"
        "Accept: */*\r\n\r\n";

    send(sock, request.c_str(), request.size(), 0);

    // Читаем первую строку ответа
    char buf[256];
    memset(buf, 0, sizeof(buf));
    int bytes = recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);

    if (bytes <= 0) return -1;

    // Парсим статус код: "HTTP/1.1 200 OK"
    std::string resp(buf);
    size_t sp1 = resp.find(' ');
    if (sp1 == std::string::npos) return -1;
    size_t sp2 = resp.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return -1;

    try {
        return std::stoi(resp.substr(sp1 + 1, sp2 - sp1 - 1));
    } catch (...) {
        return -1;
    }
}

// ── Основное сканирование ─────────────────────────────
std::vector<HTTPPath> HTTPScanner::scan(const std::string& target, int port) {
    std::vector<HTTPPath> results;

    std::cout << Color::INFO << "HTTP директори скан: " << Color::CYAN
              << target << ":" << port
              << Color::RESET << std::endl;
    std::cout << Color::INFO << "Проверяем " << PATHS_COUNT
              << " путей..." << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    int checked  = 0;
    int found    = 0;

    for (int i = 0; i < PATHS_COUNT; i++) {
        std::string path = PATHS[i].path;
        int code = check_path(target, port, path);
        checked++;

        // Прогресс каждые 20 путей
        if (checked % 20 == 0) {
            std::cout << Color::INFO << "[" << checked << "/"
                      << PATHS_COUNT << "] проверено..."
                      << Color::RESET << "\r" << std::flush;
        }

        // Интересуют только 200, 301, 302, 403
        if (code == 200 || code == 301 || code == 302 || code == 403) {
            HTTPPath hp;
            hp.path        = path;
            hp.status_code = code;
            hp.risk        = PATHS[i].risk;
            hp.desc        = PATHS[i].desc;
            results.push_back(hp);
            found++;

            // Цвет по риску
            std::string col = Color::GREEN;
            if      (hp.risk == "CRITICAL") col = Color::RED;
            else if (hp.risk == "HIGH")     col = Color::YELLOW;
            else if (hp.risk == "MEDIUM")   col = Color::CYAN;

            std::cout << col << "[" << code << "] "
                      << Color::RESET
                      << std::left << std::setw(35) << path
                      << col << hp.risk << Color::RESET
                      << " — " << hp.desc << "\n";
        }
    }

    std::cout << "\n";
    return results;
}

// ── Вывод итогов ──────────────────────────────────────
void HTTPScanner::print_results(const std::vector<HTTPPath>& results) {
    if (results.empty()) {
        std::cout << Color::OK << "[+] Скрытых путей не найдено"
                  << Color::RESET << std::endl;
        return;
    }

    int crit = 0, high = 0, med = 0, info = 0;
    for (const auto& r : results) {
        if      (r.risk == "CRITICAL") crit++;
        else if (r.risk == "HIGH")     high++;
        else if (r.risk == "MEDIUM")   med++;
        else                           info++;
    }

    std::cout << Color::CYAN;
    std::cout << "┌──────────────────────────────────────────────────────────────┐\n";
    std::cout << "│              ИТОГ HTTP ДИРЕКТОРИ СКАНА                      │\n";
    std::cout << "├──────────────────────────────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    std::cout << "│  " << Color::RED    << "CRITICAL: " << crit << Color::RESET << "   "
                       << Color::YELLOW << "HIGH: "     << high << Color::RESET << "   "
                       << Color::CYAN   << "MEDIUM: "   << med  << Color::RESET << "   "
                       << Color::GREEN  << "INFO: "     << info << Color::RESET << "\n";

    std::cout << Color::CYAN;
    std::cout << "├──────┬──────────────────────────────────┬──────────┬────────┤\n";
    std::cout << "│ КОД  │  ПУТЬ                            │  РИСК    │ СТАТУС │\n";
    std::cout << "├──────┼──────────────────────────────────┼──────────┼────────┤\n";
    std::cout << Color::RESET;

    for (const auto& r : results) {
        std::string col = Color::GREEN;
        if      (r.risk == "CRITICAL") col = Color::RED;
        else if (r.risk == "HIGH")     col = Color::YELLOW;
        else if (r.risk == "MEDIUM")   col = Color::CYAN;

        std::string path = r.path;
        if (path.size() > 32) path = path.substr(0, 29) + "...";
        while (path.size() < 32) path += " ";

        std::string risk = r.risk;
        while (risk.size() < 8) risk += " ";

        std::string status = (r.status_code == 200) ? "ОТКРЫТ" :
                             (r.status_code == 403) ? "ЗАПРЕЩЁН" : "РЕДИРЕКТ";
        while (status.size() < 6) status += " ";

        std::cout << col
                  << "│ " << r.status_code << "  │ "
                  << path << " │ "
                  << risk << " │ "
                  << status << " │\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└──────┴──────────────────────────────────┴──────────┴────────┘\n";
    std::cout << Color::RESET;

    if (crit > 0)
        std::cout << Color::RED
                  << "[!!!] КРИТИЧНО: " << crit
                  << " опасных путей найдено! Немедленно закройте доступ!\n"
                  << Color::RESET;
}