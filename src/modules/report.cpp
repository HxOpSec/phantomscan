#include "modules/report.h"
#include "modules/cve.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sys/stat.h>   // FIX: вместо system("mkdir")
#include <cerrno>
#include <cstring>

// ── Безопасное создание папки reports/ ──────────────────────────────────────
// FIX #1: Заменили system("mkdir -p reports") на нормальный системный вызов.
// system() — опасен: подвержен инъекциям, создаёт лишний процесс, не portable.
// mkdir() из <sys/stat.h> — правильный способ на POSIX/Linux.
static bool ensure_reports_dir() {
    struct stat st;
    if (stat("reports", &st) == 0) return true;  // папка уже существует
    if (mkdir("reports", 0755) != 0) {
        std::cerr << Color::FAIL
                  << "[-] Ошибка создания папки reports/: "
                  << strerror(errno)
                  << Color::RESET << "\n";
        return false;
    }
    return true;
}

// ── Экранирование спецсимволов для JSON ─────────────────────────────────────
// FIX #2: Без этого JSON ломается если в target/service есть " \ или \n
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ── Экранирование спецсимволов для HTML ─────────────────────────────────────
// FIX #3: Без этого XSS если в target/service/city есть < > & "
static std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;
        }
    }
    return out;
}

// ── Генерируем имя файла ─────────────────────────────────────────────────────
std::string Reporter::get_filename(const std::string& target, const std::string& ext) {
    time_t now = time(nullptr);     // FIX #4: time(0) → time(nullptr) — современный стиль
    struct tm* t = localtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", t);
    return "reports/" + target + "_" + buf + "." + ext;
}

// ── TXT отчёт ────────────────────────────────────────────────────────────────
void Reporter::save_txt(const ScanReport& report) {
    if (!ensure_reports_dir()) return;

    std::string filename = get_filename(report.target, "txt");
    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cout << Color::FAIL << "[-] Не удалось создать: "
                  << filename << Color::RESET << "\n";
        return;
    }

    f << "╔══════════════════════════════════════════╗\n";
    f << "║       PhantomScan Report  v1.0           ║\n";
    f << "╚══════════════════════════════════════════╝\n\n";
    f << "Цель     : " << report.target  << "\n";
    f << "IP       : " << report.ip      << "\n";
    f << "ОС       : " << report.os      << "\n";
    f << "Страна   : " << report.country << "\n";
    f << "Город    : " << report.city    << "\n";
    f << "Провайдер: " << report.isp     << "\n";
    f << "Фаервол  : " << (report.firewall_detected ? "ОБНАРУЖЕН" : "не обнаружен") << "\n";
    f << "Время    : " << report.scan_time << " сек\n\n";

    f << "=== ОТКРЫТЫЕ ПОРТЫ ===\n";
    if (report.ports.empty()) f << "  Открытых портов не найдено\n";
    for (const auto& p : report.ports)
        f << "  [+] " << std::setw(5) << p.port << " | " << p.service << "\n";

    f << "\n=== ПОДДОМЕНЫ ===\n";
    if (report.subdomains.empty()) f << "  Поддоменов не найдено\n";
    for (const auto& s : report.subdomains)
        f << "  [+] " << s << "\n";

    f << "\n=== CVE УЯЗВИМОСТИ ===\n";
    CVEScanner cve;
    bool any = false;
    for (const auto& p : report.ports) {
        for (const auto& c : cve.search(p.service)) {
            f << "  [!] " << std::left << std::setw(18) << c.id
              << " | " << std::setw(9) << c.severity
              << " | CVSS " << std::fixed << std::setprecision(1) << c.cvss
              << " | " << c.description << "\n";
            any = true;
        }
    }
    if (!any) f << "  CVE не найдено\n";

    f.close();
    std::cout << Color::OK << "[+] TXT: " << Color::CYAN
              << filename << Color::RESET << "\n";
}

// ── JSON отчёт ───────────────────────────────────────────────────────────────
void Reporter::save_json(const ScanReport& report) {
    if (!ensure_reports_dir()) return;

    std::string filename = get_filename(report.target, "json");
    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cout << Color::FAIL << "[-] Не удалось создать: "
                  << filename << Color::RESET << "\n";
        return;
    }

    f << "{\n";
    f << "  \"target\": \""  << json_escape(report.target)  << "\",\n";
    f << "  \"ip\": \""      << json_escape(report.ip)      << "\",\n";
    f << "  \"os\": \""      << json_escape(report.os)      << "\",\n";
    f << "  \"country\": \"" << json_escape(report.country) << "\",\n";
    f << "  \"city\": \""    << json_escape(report.city)    << "\",\n";
    f << "  \"isp\": \""     << json_escape(report.isp)     << "\",\n";
    f << "  \"firewall\": "  << (report.firewall_detected ? "true" : "false") << ",\n";
    f << "  \"scan_time\": " << report.scan_time << ",\n";

    f << "  \"ports\": [\n";
    for (size_t i = 0; i < report.ports.size(); i++) {
        f << "    {\"port\": " << report.ports[i].port
          << ", \"service\": \"" << json_escape(report.ports[i].service) << "\""
          << ", \"version\": \"" << json_escape(report.ports[i].version.empty() ? report.ports[i].service : report.ports[i].version) << "\"}";
        if (i + 1 < report.ports.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";

    f << "  \"subdomains\": [\n";
    for (size_t i = 0; i < report.subdomains.size(); i++) {
        f << "    \"" << json_escape(report.subdomains[i]) << "\"";
        if (i + 1 < report.subdomains.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";

    // FIX #5: CVE теперь тоже в JSON экспортируются (раньше не было!)
    f << "  \"cve\": [\n";
    CVEScanner cve;
    std::vector<CVEEntry> all;
    for (const auto& p : report.ports)
        for (const auto& c : cve.search(p.service))
            all.push_back(c);

    for (size_t i = 0; i < all.size(); i++) {
        const auto& c = all[i];
        f << "    {\"id\": \""          << json_escape(c.id)         << "\""
          << ", \"severity\": \""    << json_escape(c.severity)   << "\""
          << ", \"description\": \"" << json_escape(c.description) << "\"}";
        if (i + 1 < all.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n";
    f << "}\n";

    f.close();
    std::cout << Color::OK << "[+] JSON: " << Color::CYAN
              << filename << Color::RESET << "\n";
}

// ── HTML отчёт ───────────────────────────────────────────────────────────────
void Reporter::save_html(const ScanReport& report) {
    if (!ensure_reports_dir()) return;

    std::string filename = get_filename(report.target, "html");
    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cout << Color::FAIL << "[-] Не удалось создать: "
                  << filename << Color::RESET << "\n";
        return;
    }

    // Все данные через html_escape() — защита от XSS
    const std::string ht = html_escape(report.target);
    const std::string hi = html_escape(report.ip);
    const std::string ho = html_escape(report.os);
    const std::string hc = html_escape(report.country);
    const std::string hci = html_escape(report.city);
    const std::string hisp = html_escape(report.isp);

    f << "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n"
      << "<meta charset=\"UTF-8\">\n"
      << "<title>PhantomScan — " << ht << "</title>\n"
      << "<style>\n"
      << "* { box-sizing:border-box; margin:0; padding:0; }\n"
      << "body { background:#0d1117; color:#c9d1d9; font-family:'Courier New',monospace; padding:24px; }\n"
      << ".hdr { border-bottom:2px solid #00d4ff; padding-bottom:14px; margin-bottom:20px; }\n"
      << ".hdr h1 { color:#00d4ff; font-size:26px; letter-spacing:2px; }\n"
      << ".hdr p  { color:#8b949e; margin-top:4px; }\n"
      << "h2 { color:#58a6ff; margin:22px 0 8px; font-size:14px; text-transform:uppercase; letter-spacing:1px; }\n"
      << "table { border-collapse:collapse; width:100%; margin-bottom:6px; }\n"
      << "th { background:#161b22; color:#00d4ff; padding:9px 12px; text-align:left; font-size:12px; }\n"
      << "td { padding:7px 12px; border-bottom:1px solid #21262d; font-size:12px; }\n"
      << "tr:hover td { background:#161b22; }\n"
      << ".open{color:#3fb950;font-weight:bold} .critical{color:#f85149;font-weight:bold}\n"
      << ".high{color:#e3b341} .medium{color:#58a6ff} .low{color:#8b949e}\n"
      << ".fw-yes{color:#f85149} .fw-no{color:#3fb950}\n"
      << ".empty{color:#8b949e;font-style:italic;padding:8px 12px}\n"
      << ".footer{margin-top:36px;color:#8b949e;font-size:11px;border-top:1px solid #21262d;padding-top:10px}\n"
      << "</style>\n</head>\n<body>\n";

    f << "<div class=\"hdr\"><h1>&#x26A1; PhantomScan Report</h1>"
      << "<p>&#128269; <strong>" << ht << "</strong> &nbsp;|&nbsp; "
      << report.scan_time << " сек</p></div>\n";

    f << "<h2>&#128203; Цель</h2><table>\n"
      << "<tr><th>Параметр</th><th>Значение</th></tr>\n"
      << "<tr><td>IP</td><td>"        << hi   << "</td></tr>\n"
      << "<tr><td>ОС</td><td>"        << ho   << "</td></tr>\n"
      << "<tr><td>Страна</td><td>"    << hc   << "</td></tr>\n"
      << "<tr><td>Город</td><td>"     << hci  << "</td></tr>\n"
      << "<tr><td>Провайдер</td><td>" << hisp << "</td></tr>\n"
      << "<tr><td>Фаервол</td><td class='"
      << (report.firewall_detected ? "fw-yes'>&#128308; ОБНАРУЖЕН" : "fw-no'>&#128994; не обнаружен")
      << "</td></tr>\n</table>\n";

    f << "<h2>&#128268; Открытые порты</h2><table>\n"
      << "<tr><th>Порт</th><th>Служба</th></tr>\n";
    if (report.ports.empty())
        f << "<tr><td colspan='2' class='empty'>Открытых портов не найдено</td></tr>\n";
    for (const auto& p : report.ports)
        f << "<tr><td class='open'>" << p.port << "</td><td>"
          << html_escape(p.service) << "</td></tr>\n";
    f << "</table>\n";

    f << "<h2>&#127758; Поддомены</h2><table>\n<tr><th>Поддомен</th></tr>\n";
    if (report.subdomains.empty())
        f << "<tr><td class='empty'>Поддоменов не найдено</td></tr>\n";
    for (const auto& s : report.subdomains)
        f << "<tr><td>" << html_escape(s) << "</td></tr>\n";
    f << "</table>\n";

    f << "<h2>&#9888;&#65039; CVE Уязвимости</h2><table>\n"
      << "<tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Служба</th><th>Описание</th></tr>\n";
    CVEScanner cve;
    bool any = false;
    for (const auto& p : report.ports) {
        for (const auto& c : cve.search(p.service)) {
            std::string cls = "low";
            if      (c.severity == "CRITICAL") cls = "critical";
            else if (c.severity == "HIGH")     cls = "high";
            else if (c.severity == "MEDIUM")   cls = "medium";
            f << "<tr>"
              << "<td class='" << cls << "'>" << html_escape(c.id)          << "</td>"
              << "<td class='" << cls << "'>" << html_escape(c.severity)    << "</td>"
              << "<td class='" << cls << "'>" << std::fixed << std::setprecision(1) << c.cvss << "</td>"
              << "<td>"                       << html_escape(p.service)     << "</td>"
              << "<td>"                       << html_escape(c.description) << "</td>"
              << "</tr>\n";
            any = true;
        }
    }
    if (!any) f << "<tr><td colspan='5' class='empty'>CVE не найдено</td></tr>\n";
    f << "</table>\n";

    f << "<div class='footer'>PhantomScan v1.0 &nbsp;&middot;&nbsp; by Umedjon "
      << "&nbsp;&middot;&nbsp; github.com/HxOpSec/phantomscan</div>\n"
      << "</body></html>\n";

    f.close();
    std::cout << Color::OK << "[+] HTML: " << Color::CYAN
              << filename << Color::RESET << "\n";
}
