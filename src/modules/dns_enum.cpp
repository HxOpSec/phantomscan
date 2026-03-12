#include "modules/dns_enum.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <sstream>
#include <algorithm>

// ── Запускаем dig через popen ─────────────────────────
static std::vector<std::string> run_dig(const std::string& cmd) {
    std::vector<std::string> lines;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return lines;

    char buf[512];
    while (fgets(buf, sizeof(buf), pipe)) {
        std::string line(buf);
        // убираем \n
        if (!line.empty() && line.back() == '\n') line.pop_back();
        if (!line.empty()) lines.push_back(line);
    }
    pclose(pipe);
    return lines;
}

// ── Запрос DNS записей через dig ─────────────────────
std::vector<DNSRecord> DNSEnum::query(const std::string& domain,
                                       const std::string& type) {
    std::vector<DNSRecord> records;

    // dig +short возвращает только значения без лишнего
    std::string cmd = "dig +short " + domain + " " + type
                    + " 2>/dev/null";
    auto lines = run_dig(cmd);

    for (const auto& line : lines) {
        if (line.empty() || line[0] == ';') continue;

        DNSRecord rec;
        rec.type     = type;
        rec.priority = 0;

        if (type == "MX") {
            // MX формат: "10 mail.example.com."
            std::istringstream ss(line);
            std::string prio, host;
            if (ss >> prio >> host) {
                try { rec.priority = std::stoi(prio); } catch (...) {}
                // убираем точку в конце
                if (!host.empty() && host.back() == '.')
                    host.pop_back();
                rec.value = host;
            }
        } else {
            rec.value = line;
            // убираем точку в конце для NS/CNAME
            if (!rec.value.empty() && rec.value.back() == '.')
                rec.value.pop_back();
        }

        if (!rec.value.empty())
            records.push_back(rec);
    }

    return records;
}

// ── Попытка Zone Transfer (AXFR) ─────────────────────
std::vector<std::string> DNSEnum::try_zone_transfer(
    const std::string& domain, const std::string& ns) {

    std::vector<std::string> results;

    std::string cmd = "timeout 5 dig axfr " + domain
                    + " @" + ns + " 2>/dev/null";
    auto lines = run_dig(cmd);

    for (const auto& line : lines) {
        if (line.empty() || line[0] == ';') continue;
        // Проверяем что это не ошибка
        if (line.find("Transfer failed") != std::string::npos) break;
        if (line.find("REFUSED")         != std::string::npos) break;
        if (line.find("connection")      != std::string::npos) break;
        results.push_back(line);
    }

    // Меньше 3 строк — transfer не удался
    if (results.size() < 3) results.clear();
    return results;
}

// ── Основная функция ─────────────────────────────────
DNSResult DNSEnum::enumerate(const std::string& domain) {
    DNSResult result;
    result.target       = domain;
    result.axfr_success = false;

    std::cout << Color::INFO << "DNS enum: " << Color::CYAN
              << domain << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    // Все типы записей которые запрашиваем
    std::vector<std::string> types = {
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"
    };

    for (const auto& type : types) {
        std::cout << Color::INFO << "[*] Запрашиваем "
                  << std::left << std::setw(6) << type
                  << "... " << Color::RESET << std::flush;

        auto recs = query(domain, type);

        if (recs.empty()) {
            std::cout << Color::WARN << "нет записей" << Color::RESET << "\n";
            continue;
        }

        std::cout << Color::OK << recs.size() << " записей" << Color::RESET << "\n";

        for (const auto& r : recs) {
            result.records.push_back(r);

            // Сразу выводим
            std::string col = Color::GREEN;
            if (r.type == "A"    || r.type == "AAAA") col = Color::CYAN;
            if (r.type == "MX")                       col = Color::YELLOW;
            if (r.type == "TXT")                      col = Color::WHITE;
            if (r.type == "NS")                       col = Color::GREEN;

            std::cout << "    " << col
                      << std::left << std::setw(7) << r.type;

            if (r.type == "MX")
                std::cout << "[" << r.priority << "] ";
            else
                std::cout << "     ";

            std::cout << r.value << Color::RESET << "\n";
        }
    }

    std::cout << "──────────────────────────────────────────\n";

    // Zone Transfer — пробуем на каждом NS сервере
    std::cout << Color::WARN << "[*] Пробуем Zone Transfer (AXFR)..."
              << Color::RESET << "\n";

    // Берём NS из уже найденных записей
    std::vector<std::string> ns_servers;
    for (const auto& r : result.records) {
        if (r.type == "NS") ns_servers.push_back(r.value);
    }

    if (ns_servers.empty()) {
        std::cout << Color::WARN << "    NS серверы не найдены\n" << Color::RESET;
    } else {
        for (const auto& ns : ns_servers) {
            std::cout << Color::INFO << "    Пробуем: " << ns
                      << "... " << Color::RESET << std::flush;

            auto axfr = try_zone_transfer(domain, ns);

            if (!axfr.empty()) {
                std::cout << Color::RED << Color::BOLD
                          << "УСПЕХ! Zone Transfer сработал!\n"
                          << Color::RESET;
                result.axfr_success  = true;
                result.zone_transfer = axfr;
                break;
            } else {
                std::cout << Color::OK << "REFUSED (защита включена)\n"
                          << Color::RESET;
            }
        }
    }

    return result;
}

// ── Итоговый вывод ───────────────────────────────────
void DNSEnum::print_results(const DNSResult& result) {
    std::cout << "\n" << Color::CYAN << Color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                  ИТОГ DNS РАЗВЕДКИ                          ║\n";
    std::cout << "║  Домен: " << result.target;
    int pad = 52 - (int)result.target.size();
    for (int i = 0; i < pad; i++) std::cout << ' ';
    std::cout << "║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << Color::RESET;

    // Группируем по типу
    std::vector<std::string> order = {"A","AAAA","MX","NS","TXT","CNAME","SOA"};
    for (const auto& type : order) {
        bool first = true;
        for (const auto& r : result.records) {
            if (r.type != type) continue;
            if (first) {
                std::cout << Color::CYAN << Color::BOLD
                          << "  " << type << " записи:\n"
                          << Color::RESET;
                first = false;
            }

            std::string col = Color::GREEN;
            if (type == "A" || type == "AAAA") col = Color::CYAN;
            if (type == "MX")                  col = Color::YELLOW;
            if (type == "TXT")                 col = Color::WHITE;

            std::cout << "    " << col;
            if (type == "MX")
                std::cout << "[pri=" << r.priority << "] ";
            std::cout << r.value << Color::RESET << "\n";
        }
    }

    // Zone Transfer результат
    std::cout << "\n";
    if (result.axfr_success) {
        std::cout << Color::RED << Color::BOLD
                  << "  [!!!] ZONE TRANSFER УСПЕШЕН — сервер уязвим!\n"
                  << "  Получено " << result.zone_transfer.size()
                  << " DNS записей:\n" << Color::RESET;
        // Первые 20 строк
        int show = std::min((int)result.zone_transfer.size(), 20);
        for (int i = 0; i < show; i++)
            std::cout << Color::RED << "    " << result.zone_transfer[i]
                      << Color::RESET << "\n";
        if ((int)result.zone_transfer.size() > 20)
            std::cout << Color::WARN << "    ... и ещё "
                      << result.zone_transfer.size() - 20
                      << " записей\n" << Color::RESET;
    } else {
        std::cout << Color::OK
                  << "  [+] Zone Transfer запрещён (хорошая защита)\n"
                  << Color::RESET;
    }

    std::cout << Color::CYAN << Color::BOLD;
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << Color::RESET;

    std::cout << Color::INFO << "Всего записей: " << Color::GREEN
              << result.records.size() << Color::RESET << "\n\n";
}