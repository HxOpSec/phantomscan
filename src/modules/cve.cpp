#include "modules/cve.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cctype>
#include <mutex>
#include <unordered_map>

CVEScanner::CVEScanner() {}

// ── читаем файл ──────────────────────────────────────
static std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::stringstream buf;
    buf << file.rdbuf();
    return buf.str();
}

// ── Простенький токенизатор JSON (ограничен форматом файла cve.json) ──────
namespace {
struct Tokenizer {
    explicit Tokenizer(const std::string& data_) : data(data_), pos(0) {}
    const std::string& data;
    size_t pos;

    void skip_ws() {
        while (pos < data.size() && std::isspace(static_cast<unsigned char>(data[pos])))
            ++pos;
    }

    bool consume(char ch) {
        skip_ws();
        if (pos < data.size() && data[pos] == ch) { ++pos; return true; }
        return false;
    }

    bool parse_string(std::string& out) {
        skip_ws();
        if (pos >= data.size() || data[pos] != '"') return false;
        ++pos;
        out.clear();
        while (pos < data.size()) {
            char ch = data[pos++];
            if (ch == '\\') {
                if (pos >= data.size()) return false;
                char esc = data[pos++];
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    default: out.push_back(esc); break;
                }
            } else if (ch == '"') {
                return true;
            } else {
                out.push_back(ch);
            }
        }
        return false;
    }

    bool parse_number(double& out) {
        skip_ws();
        size_t start = pos;
        while (pos < data.size() &&
               (std::isdigit(static_cast<unsigned char>(data[pos])) || data[pos] == '.' || data[pos] == '-'))
            ++pos;
        if (start == pos) return false;
        try {
            out = std::stod(data.substr(start, pos - start));
            return true;
        } catch (...) {
            return false;
        }
    }

    bool skip_value() {
        skip_ws();
        if (pos >= data.size()) return false;
        if (data[pos] == '"') {
            std::string dummy;
            return parse_string(dummy);
        }
        if (data[pos] == '{') {
            int depth = 0;
            do {
                if (data[pos] == '{') depth++;
                else if (data[pos] == '}') depth--;
                ++pos;
            } while (pos < data.size() && depth > 0);
            return depth == 0;
        }
        if (data[pos] == '[') {
            int depth = 0;
            do {
                if (data[pos] == '[') depth++;
                else if (data[pos] == ']') depth--;
                ++pos;
            } while (pos < data.size() && depth > 0);
            return depth == 0;
        }
        // number / literal
        double num;
        return parse_number(num);
    }
};

bool parse_entry(Tokenizer& tk, CVEEntry& entry) {
    if (!tk.consume('{')) return false;
    while (true) {
        tk.skip_ws();
        if (tk.consume('}')) break;
        std::string key;
        if (!tk.parse_string(key)) return false;
        if (!tk.consume(':')) return false;

        if (key == "id") {
            if (!tk.parse_string(entry.id)) return false;
        } else if (key == "severity") {
            if (!tk.parse_string(entry.severity)) return false;
        } else if (key == "cvss") {
            if (!tk.parse_number(entry.cvss)) return false;
        } else if (key == "desc") {
            if (!tk.parse_string(entry.description)) return false;
        } else {
            if (!tk.skip_value()) return false;
        }

        tk.skip_ws();
        if (tk.consume('}')) break;
        if (tk.consume(',')) continue;
        break;
    }
    return !entry.id.empty();
}

bool parse_array(Tokenizer& tk, std::vector<CVEEntry>& out) {
    if (!tk.consume('[')) return false;
    while (true) {
        tk.skip_ws();
        if (tk.consume(']')) break;
        CVEEntry e;
        if (!parse_entry(tk, e)) return false;
        out.push_back(std::move(e));
        tk.skip_ws();
        if (tk.consume(']')) break;
        if (!tk.consume(',')) break;
    }
    return true;
}

bool parse_database(const std::string& json,
                    std::unordered_map<std::string, std::vector<CVEEntry>>& out) {
    Tokenizer tk(json);
    if (!tk.consume('{')) return false;
    while (true) {
        tk.skip_ws();
        if (tk.consume('}')) break;
        std::string key;
        if (!tk.parse_string(key)) return false;
        if (!tk.consume(':')) return false;
        std::vector<CVEEntry> entries;
        if (!parse_array(tk, entries)) return false;
        // сортируем по CVSS убыванию
        std::sort(entries.begin(), entries.end(),
                  [](const CVEEntry& a, const CVEEntry& b) {
                      return a.cvss > b.cvss;
                  });
        out[key] = std::move(entries);
        tk.skip_ws();
        if (tk.consume('}')) break;
        if (!tk.consume(',')) break;
    }
    return true;
}

const std::unordered_map<std::string, std::vector<CVEEntry>>& get_cached_db(const std::string& path) {
    static std::unordered_map<std::string, std::vector<CVEEntry>> cache;
    static std::once_flag loaded;
    std::call_once(loaded, [&] {
        std::string json = read_file(path);
        if (!json.empty()) {
            parse_database(json, cache);
        }
    });
    return cache;
}

std::string normalize_key(std::string key_in) {
    std::string key = std::move(key_in);
    for (char stop : {' ', '[', '/', '('}) {
        size_t p = key.find(stop);
        if (p != std::string::npos) {
            key = key.substr(0, p);
            break;
        }
    }
    for (char& c : key) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return key;
}
} // namespace

// ── парсим секцию сервиса из JSON (используем кэш) ─────────────────────────
std::vector<CVEEntry> CVEScanner::parse(const std::string& json,
                                         const std::string& service) {
    (void)json;
    const auto& db = get_cached_db(cve_file);
    auto key = normalize_key(service);
    auto it  = db.find(key);
    if (it == db.end()) return {};
    return it->second;
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
        // пробуем оригинал и варианты регистра
        std::string upper = clean;
        upper[0] = std::toupper(static_cast<unsigned char>(upper[0]));

        auto res = parse("", clean);
        if (res.empty()) res = parse("", upper);

        if (res.empty()) {
            std::string all_upper = clean;
            for (char& c : all_upper) c = std::toupper(static_cast<unsigned char>(c));
            res = parse("", all_upper);
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
