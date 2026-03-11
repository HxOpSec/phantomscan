#include "modules/cve.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

CVEScanner::CVEScanner() {}

// ── читаем файл ──────────────────────────────────────
static std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::stringstream buf;
    buf << file.rdbuf();
    return buf.str();
}

// ── вспомогательно: извлечь строку между кавычками ──
static std::string extract_str(const std::string& s, size_t from) {
    size_t start = s.find('"', from);
    if (start == std::string::npos) return "";
    start++;
    size_t end = s.find('"', start);
    if (end == std::string::npos) return "";
    return s.substr(start, end - start);
}

// ── вспомогательно: извлечь число (cvss) ────────────
static double extract_double(const std::string& s, size_t from) {
    size_t colon = s.find(':', from);
    if (colon == std::string::npos) return 0.0;
    size_t num_start = s.find_first_of("0123456789", colon);
    if (num_start == std::string::npos) return 0.0;
    return std::stod(s.substr(num_start));
}

// ── парсим секцию сервиса из JSON ────────────────────
std::vector<CVEEntry> CVEScanner::parse(const std::string& json,
                                         const std::string& service) {
    std::vector<CVEEntry> results;

    std::string key = "\"" + service + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return results;

    size_t arr_start = json.find('[', pos);
    if (arr_start == std::string::npos) return results;

    // считаем вложенность скобок чтобы найти правильный ]
    int depth = 1;
    size_t cur = arr_start + 1;
    while (cur < json.size() && depth > 0) {
        if (json[cur] == '[') depth++;
        else if (json[cur] == ']') depth--;
        cur++;
    }
    std::string section = json.substr(arr_start, cur - arr_start);

    // парсим каждый { ... }
    size_t obj_pos = 0;
    while (true) {
        size_t obj_start = section.find('{', obj_pos);
        if (obj_start == std::string::npos) break;
        size_t obj_end = section.find('}', obj_start);
        if (obj_end == std::string::npos) break;

        std::string obj = section.substr(obj_start, obj_end - obj_start + 1);
        CVEEntry entry;

        // id
        size_t id_pos = obj.find("\"id\"");
        if (id_pos != std::string::npos)
            entry.id = extract_str(obj, id_pos + 4);

        // severity
        size_t sev_pos = obj.find("\"severity\"");
        if (sev_pos != std::string::npos)
            entry.severity = extract_str(obj, sev_pos + 10);

        // cvss
        size_t cvss_pos = obj.find("\"cvss\"");
        entry.cvss = (cvss_pos != std::string::npos)
                     ? extract_double(obj, cvss_pos + 6)
                     : 0.0;

        // desc
        size_t desc_pos = obj.find("\"desc\"");
        if (desc_pos != std::string::npos)
            entry.description = extract_str(obj, desc_pos + 6);

        if (!entry.id.empty())
            results.push_back(entry);

        obj_pos = obj_end + 1;
    }

    // сортируем по CVSS убыванию
    std::sort(results.begin(), results.end(),
              [](const CVEEntry& a, const CVEEntry& b) {
                  return a.cvss > b.cvss;
              });

    return results;
}

// ── поиск с очисткой имени сервиса ──────────────────
std::vector<CVEEntry> CVEScanner::search(const std::string& service) {
    std::string clean = service;

    // убираем версию и лишнее
    for (char stop : {' ', '[', '/', '('}) {
        size_t p = clean.find(stop);
        if (p != std::string::npos) clean = clean.substr(0, p);
    }

    // первая буква заглавная (SSH, Http → HTTP)
    if (!clean.empty()) {
        // пробуем оригинал, потом uppercase первой буквы
        std::string upper = clean;
        upper[0] = std::toupper(upper[0]);

        std::string json = read_file(cve_file);
        if (json.empty()) return {};

        auto res = parse(json, clean);
        if (res.empty()) res = parse(json, upper);

        // пробуем uppercase всего слова (http → HTTP)
        if (res.empty()) {
            std::string all_upper = clean;
            for (char& c : all_upper) c = std::toupper(c);
            res = parse(json, all_upper);
        }
        return res;
    }
    return {};
}

// ── риск-скор для scorecard ──────────────────────────
int CVEScanner::get_risk_score(const std::vector<CVEEntry>& entries) {
    int score = 0;
    for (const auto& e : entries) {
        if      (e.severity == "CRITICAL") score += 30;
        else if (e.severity == "HIGH")     score += 15;
        else if (e.severity == "MEDIUM")   score += 7;
        else if (e.severity == "LOW")      score += 2;
    }
    return std::min(score, 100);
}

// ── вывод результатов ────────────────────────────────
void CVEScanner::print_results(const std::string& service,
                                const std::vector<CVEEntry>& entries) {
    if (entries.empty()) {
        std::cout << Color::INFO << "[i] CVE для '" << service
                  << "' не найдено в базе" << Color::RESET << "\n";
        return;
    }

    // подсчёт по критичности
    int crit = 0, high = 0, med = 0, low = 0;
    for (const auto& e : entries) {
        if      (e.severity == "CRITICAL") crit++;
        else if (e.severity == "HIGH")     high++;
        else if (e.severity == "MEDIUM")   med++;
        else                               low++;
    }

    std::cout << "\n";
    std::cout << Color::RED << Color::BOLD;
    std::cout << " ╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << " ║  CVE БАЗА  │  " << service;
    // отступ
    int pad = 46 - (int)service.size();
    for (int i = 0; i < pad; i++) std::cout << ' ';
    std::cout << "║\n";
    std::cout << " ╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << Color::RESET;

    // статистика
    std::cout << Color::RED << " ║ " << Color::RESET;
    std::cout << Color::RED   << Color::BOLD << " CRITICAL: " << crit << Color::RESET;
    std::cout << "   ";
    std::cout << Color::YELLOW << Color::BOLD << "HIGH: " << high << Color::RESET;
    std::cout << "   ";
    std::cout << Color::CYAN  << "MEDIUM: " << med << Color::RESET;
    std::cout << "   ";
    std::cout << Color::GREEN << "LOW: " << low << Color::RESET;
    std::cout << Color::RED << "\n ╠══════════════════════════════════════════════════════════════╣\n" << Color::RESET;

    // заголовок таблицы
    std::cout << Color::RED << " ║ " << Color::RESET;
    std::cout << Color::BOLD << Color::CYAN
              << std::left << std::setw(18) << "CVE ID"
              << std::setw(10) << "SEVERITY"
              << std::setw(6)  << "CVSS"
              << "ОПИСАНИЕ"
              << Color::RESET
              << Color::RED << "\n ╠══════════════════════════════════════════════════════════════╣\n" << Color::RESET;

    for (const auto& e : entries) {
        // цвет по критичности
        std::string col = Color::GREEN;
        if      (e.severity == "CRITICAL") col = Color::RED;
        else if (e.severity == "HIGH")     col = Color::YELLOW;
        else if (e.severity == "MEDIUM")   col = Color::CYAN;

        std::cout << Color::RED << " ║ " << Color::RESET;
        std::cout << Color::CYAN << std::left << std::setw(18) << e.id << Color::RESET;
        std::cout << col         << std::setw(10) << e.severity << Color::RESET;

        // cvss
        if (e.cvss > 0) {
            std::cout << col << std::fixed << std::setprecision(1)
                      << std::setw(5) << e.cvss << Color::RESET << " ";
        } else {
            std::cout << std::setw(6) << "  -   ";
        }

        // описание (обрезаем до 28 символов)
        std::string desc = e.description;
        if (desc.size() > 28) desc = desc.substr(0, 25) + "...";
        std::cout << Color::WHITE << desc << Color::RESET << "\n";
    }

    std::cout << Color::RED << Color::BOLD;
    std::cout << " ╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << Color::RESET;

    // риск
    int risk = get_risk_score(entries);
    std::cout << Color::WARN << " [!] Риск-индекс для " << service
              << ": " << risk << "/100" << Color::RESET << "\n\n";
}
