#include "modules/report.h"
#include "modules/cve.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>

// Генерируем имя файла
std::string Reporter::get_filename(const std::string& target, const std::string& ext) {
    time_t now = time(0);
    struct tm* t = localtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", t);
    return "reports/" + target + "_" + buf + "." + ext;
}

// Текстовый отчёт
void Reporter::save_txt(const ScanReport& report) {
    // Создаём папку reports
    system("mkdir -p reports");

    std::string filename = get_filename(report.target, "txt");
    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cout << Color::FAIL << "Не удалось создать файл!" << Color::RESET << std::endl;
        return;
    }

    f << "=== PhantomScan Report ===\n\n";
    f << "Цель     : " << report.target << "\n";
    f << "IP       : " << report.ip << "\n";
    f << "ОС       : " << report.os << "\n";
    f << "Страна   : " << report.country << "\n";
    f << "Город    : " << report.city << "\n";
    f << "Провайдер: " << report.isp << "\n";
    f << "Фаервол  : " << (report.firewall_detected ? "ОБНАРУЖЕН" : "не обнаружен") << "\n";
    f << "Время    : " << report.scan_time << " сек\n\n";

    f << "=== ОТКРЫТЫЕ ПОРТЫ ===\n";
    for (const auto& p : report.ports) {
        f << "  [+] Порт " << p.port << " | " << p.service << "\n";
    }

    f << "\n=== ПОДДОМЕНЫ ===\n";
    for (const auto& s : report.subdomains) {
        f << "  [+] " << s << "\n";
    }

    f << "\n=== CVE УЯЗВИМОСТИ ===\n";
    CVEScanner cve;
    for (const auto& p : report.ports) {
        auto cves = cve.search(p.service);
        for (const auto& c : cves) {
            f << "  [!] " << c.id << " | " << c.severity
              << " | " << c.description << "\n";
        }
    }

    f.close();
    std::cout << Color::OK << "TXT отчёт сохранён: " << Color::CYAN
              << filename << Color::RESET << std::endl;
}

// JSON отчёт
void Reporter::save_json(const ScanReport& report) {
    system("mkdir -p reports");

    std::string filename = get_filename(report.target, "json");
    std::ofstream f(filename);

    f << "{\n";
    f << "  \"target\": \"" << report.target << "\",\n";
    f << "  \"ip\": \"" << report.ip << "\",\n";
    f << "  \"os\": \"" << report.os << "\",\n";
    f << "  \"country\": \"" << report.country << "\",\n";
    f << "  \"firewall\": " << (report.firewall_detected ? "true" : "false") << ",\n";
    f << "  \"scan_time\": " << report.scan_time << ",\n";

    f << "  \"ports\": [\n";
    for (size_t i = 0; i < report.ports.size(); i++) {
        f << "    {\"port\": " << report.ports[i].port
          << ", \"service\": \"" << report.ports[i].service << "\"}";
        if (i + 1 < report.ports.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";

    f << "  \"subdomains\": [\n";
    for (size_t i = 0; i < report.subdomains.size(); i++) {
        f << "    \"" << report.subdomains[i] << "\"";
        if (i + 1 < report.subdomains.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n";
    f << "}\n";

    f.close();
    std::cout << Color::OK << "JSON отчёт сохранён: " << Color::CYAN
              << filename << Color::RESET << std::endl;
}

// HTML отчёт
void Reporter::save_html(const ScanReport& report) {
    system("mkdir -p reports");

    std::string filename = get_filename(report.target, "html");
    std::ofstream f(filename);

    f << R"(<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PhantomScan Report</title>
<style>
  body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
  h1 { color: #00d4ff; }
  h2 { color: #58a6ff; border-bottom: 1px solid #30363d; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  th { background: #161b22; color: #00d4ff; padding: 8px; text-align: left; }
  td { padding: 8px; border-bottom: 1px solid #30363d; }
  .open { color: #3fb950; }
  .critical { color: #f85149; }
  .high { color: #e3b341; }
  .medium { color: #58a6ff; }
  .info { color: #8b949e; }
  .firewall-yes { color: #f85149; }
  .firewall-no { color: #3fb950; }
</style>
</head>
<body>
)";

    f << "<h1>🔍 PhantomScan Report</h1>\n";
    f << "<h2>📋 Информация о цели</h2>\n";
    f << "<table>\n";
    f << "<tr><th>Параметр</th><th>Значение</th></tr>\n";
    f << "<tr><td>Цель</td><td>" << report.target << "</td></tr>\n";
    f << "<tr><td>IP</td><td>" << report.ip << "</td></tr>\n";
    f << "<tr><td>ОС</td><td>" << report.os << "</td></tr>\n";
    f << "<tr><td>Страна</td><td>" << report.country << "</td></tr>\n";
    f << "<tr><td>Город</td><td>" << report.city << "</td></tr>\n";
    f << "<tr><td>Провайдер</td><td>" << report.isp << "</td></tr>\n";
    f << "<tr><td>Фаервол</td><td class='"
      << (report.firewall_detected ? "firewall-yes'>ОБНАРУЖЕН" : "firewall-no'>не обнаружен")
      << "</td></tr>\n";
    f << "<tr><td>Время сканирования</td><td>" << report.scan_time << " сек</td></tr>\n";
    f << "</table>\n";

    f << "<h2>🔌 Открытые порты</h2>\n";
    f << "<table>\n";
    f << "<tr><th>Порт</th><th>Служба</th></tr>\n";
    for (const auto& p : report.ports) {
        f << "<tr><td class='open'>" << p.port << "</td><td>" << p.service << "</td></tr>\n";
    }
    f << "</table>\n";

    f << "<h2>🌐 Поддомены</h2>\n";
    f << "<table>\n";
    f << "<tr><th>Поддомен</th></tr>\n";
    for (const auto& s : report.subdomains) {
        f << "<tr><td>" << s << "</td></tr>\n";
    }
    f << "</table>\n";

    f << "<h2>⚠️ CVE Уязвимости</h2>\n";
    f << "<table>\n";
    f << "<tr><th>CVE ID</th><th>Severity</th><th>Описание</th></tr>\n";
    CVEScanner cve;
    for (const auto& p : report.ports) {
        auto cves = cve.search(p.service);
        for (const auto& c : cves) {
            std::string cls = "medium";
            if (c.severity == "HIGH") cls = "high";
            if (c.severity == "CRITICAL") cls = "critical";
            f << "<tr><td class='" << cls << "'>" << c.id
              << "</td><td class='" << cls << "'>" << c.severity
              << "</td><td>" << c.description << "</td></tr>\n";
        }
    }
    f << "</table>\n";

    f << "</body></html>\n";
    f.close();

    std::cout << Color::OK << "HTML отчёт сохранён: " << Color::CYAN
              << filename << Color::RESET << std::endl;
}