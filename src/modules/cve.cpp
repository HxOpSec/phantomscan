#include "modules/cve.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <sstream>

CVEScanner::CVEScanner() {}

// Читаем файл
static std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::stringstream buf;
    buf << file.rdbuf();
    return buf.str();
}

// Простой парсер — ищем секцию службы в JSON
std::vector<CVEEntry> CVEScanner::parse(const std::string& json,
                                         const std::string& service) {
    std::vector<CVEEntry> results;

    // Ищем секцию службы
    std::string key = "\"" + service + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return results;

    // Находим начало массива [
    size_t arr_start = json.find('[', pos);
    if (arr_start == std::string::npos) return results;

    // Находим конец массива ]
    size_t arr_end = json.find(']', arr_start);
    if (arr_end == std::string::npos) return results;

    std::string section = json.substr(arr_start, arr_end - arr_start);

    // Парсим каждый CVE объект
    size_t cur = 0;
    while (true) {
        CVEEntry entry;

        // Ищем id
        size_t id_pos = section.find("\"id\"", cur);
        if (id_pos == std::string::npos) break;
        size_t id_start = section.find('"', id_pos + 5) + 1;
        size_t id_end   = section.find('"', id_start);
        entry.id = section.substr(id_start, id_end - id_start);

        // Ищем severity
        size_t sev_pos   = section.find("\"severity\"", cur);
        size_t sev_start = section.find('"', sev_pos + 11) + 1;
        size_t sev_end   = section.find('"', sev_start);
        entry.severity   = section.substr(sev_start, sev_end - sev_start);

        // Ищем desc
        size_t desc_pos   = section.find("\"desc\"", cur);
        size_t desc_start = section.find('"', desc_pos + 7) + 1;
        size_t desc_end   = section.find('"', desc_start);
        entry.description = section.substr(desc_start, desc_end - desc_start);

        results.push_back(entry);
        cur = desc_end + 1;
    }

    return results;
}

std::vector<CVEEntry> CVEScanner::search(const std::string& service) {
    // Очищаем имя службы (убираем версию)
    std::string clean_service = service;
    size_t space = service.find(' ');
    if (space != std::string::npos) {
        clean_service = service.substr(0, space);
    }
    // Убираем скобки если есть
    size_t bracket = clean_service.find('[');
    if (bracket != std::string::npos) {
        clean_service = clean_service.substr(0, bracket);
    }

    std::string json = read_file(cve_file);
    if (json.empty()) return {};

    return parse(json, clean_service);
}

void CVEScanner::print_results(const std::string& service,
                                const std::vector<CVEEntry>& entries) {
    if (entries.empty()) {
        std::cout << Color::INFO << "CVE для " << service
                  << " не найдено" << Color::RESET << std::endl;
        return;
    }

    std::cout << Color::WARN << "Найдено уязвимостей: "
              << entries.size() << Color::RESET << std::endl;

    // Таблица CVE
    std::cout << Color::BOLD << Color::RED;
    std::cout << "┌──────────────────┬──────────┬─────────────────────────────────────┐\n";
    std::cout << "│      CVE ID      │ SEVERITY │           ОПИСАНИЕ                  │\n";
    std::cout << "├──────────────────┼──────────┼─────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    for (const auto& e : entries) {
        // Цвет по критичности
        std::string sev_color = Color::GREEN;
        if (e.severity == "HIGH")     sev_color = Color::YELLOW;
        if (e.severity == "CRITICAL") sev_color = Color::RED;

        std::cout << Color::RED << "│" << Color::RESET;
        std::cout << " " << Color::CYAN << std::left;

        // Выравниваем CVE ID
        std::string id_padded = e.id;
        while (id_padded.size() < 16) id_padded += " ";
        std::cout << id_padded << Color::RESET;

        std::cout << Color::RED << " │" << Color::RESET;
        std::cout << " " << sev_color;

        std::string sev_padded = e.severity;
        while (sev_padded.size() < 8) sev_padded += " ";
        std::cout << sev_padded << Color::RESET;

        std::cout << Color::RED << " │" << Color::RESET;
        std::cout << " " << Color::WHITE;

        std::string desc_padded = e.description;
        if (desc_padded.size() > 35) desc_padded = desc_padded.substr(0, 35);
        while (desc_padded.size() < 35) desc_padded += " ";
        std::cout << desc_padded << Color::RESET;

        std::cout << Color::RED << " │\n" << Color::RESET;
    }

    std::cout << Color::BOLD << Color::RED;
    std::cout << "└──────────────────┴──────────┴─────────────────────────────────────┘\n";
    std::cout << Color::RESET;
}