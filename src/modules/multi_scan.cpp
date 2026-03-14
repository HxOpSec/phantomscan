#include "modules/multi_scan.h"
#include "modules/threads.h"
#include "modules/os_detect.h"
#include "modules/firewall.h"
#include "modules/cve.h"
#include "modules/report.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>

// ── мьютекс для вывода в терминал ────────────────────
static std::mutex g_print_mutex;

// ── резолвинг домена в IP ─────────────────────────────
static std::string resolve(const std::string& host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return "";

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,
              &((struct sockaddr_in*)res->ai_addr)->sin_addr,
              buf, sizeof(buf));
    freeaddrinfo(res);
    return std::string(buf);
}

// ── сканирование одной цели ───────────────────────────
TargetResult MultiScanner::scan_one(const std::string& target,
                                     int p_start, int p_end) {
    TargetResult res;
    res.target = target;

    // Резолвинг
    std::string ip = resolve(target);
    if (ip.empty()) {
        res.error     = true;
        res.error_msg = "не удалось разрезолвить";
        res.done      = true;
        return res;
    }
    res.ip = ip;

    // Лог старта
    {
        std::lock_guard<std::mutex> lock(g_print_mutex);
        std::cout << Color::INFO << "[>>] Начинаем: "
                  << Color::CYAN << target
                  << Color::RESET << " (" << ip << ")\n";
    }

    // Порты
    ThreadScanner scanner(ip, 50);
    auto ports = scanner.scan(p_start, p_end);
    res.open_ports = (int)ports.size();

    // CVE
    CVEScanner cve;
    for (const auto& p : ports) {
        auto cves = cve.search(p.service);
        res.cve_count += (int)cves.size();
    }

    // ОС
    OSDetector os_det;
    res.os = os_det.detect(ip);

    // Firewall
    FirewallDetector fw;
    res.firewall = fw.detect(ip).detected;

    // Отчёт — сохраняем TXT для каждой цели
    ScanReport report;
    report.target            = target;
    report.ip                = ip;
    report.os                = res.os;
    report.firewall_detected = res.firewall;
    report.ports             = ports;
    Reporter reporter;
    reporter.save_txt(report);

    // Лог завершения
    {
        std::lock_guard<std::mutex> lock(g_print_mutex);
        std::cout << Color::OK << "[OK] Готово:   "
                  << Color::CYAN << target << Color::RESET
                  << " | портов: " << res.open_ports
                  << " | CVE: "    << res.cve_count
                  << " | ОС: "     << res.os << "\n";
    }

    res.done = true;
    return res;
}

// ── скан из файла ─────────────────────────────────────
std::vector<TargetResult> MultiScanner::scan_from_file(
    const std::string& filename, int p_start, int p_end) {

    std::vector<std::string> targets;
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cout << Color::FAIL << "[-] Файл не найден: "
                  << filename << Color::RESET << "\n";
        return {};
    }

    std::string line;
    while (std::getline(file, line)) {
        // Убираем пробелы и пустые строки
        while (!line.empty() && (line.back() == ' ' || line.back() == '\r'))
            line.pop_back();
        if (!line.empty() && line[0] != '#')  // # = комментарий
            targets.push_back(line);
    }

    if (targets.empty()) {
        std::cout << Color::WARN << "[!] Файл пустой\n" << Color::RESET;
        return {};
    }

    return scan_targets(targets, p_start, p_end);
}

// ── параллельный скан списка целей ────────────────────
std::vector<TargetResult> MultiScanner::scan_targets(
    const std::vector<std::string>& targets, int p_start, int p_end) {

    const int MAX_THREADS = 5; // максимум 5 целей одновременно
    int total = (int)targets.size();

    std::cout << Color::INFO << "Целей для скана: " << Color::CYAN
              << total << Color::RESET
              << " | Потоков: " << MAX_THREADS
              << " | Порты: " << p_start << "-" << p_end << "\n";
    std::cout << "──────────────────────────────────────────\n";

    std::vector<TargetResult> results(total);
    std::vector<std::thread> threads;
    int idx = 0;

    // Запускаем пачками по MAX_THREADS
    while (idx < total) {
        threads.clear();
        int batch_end = std::min(idx + MAX_THREADS, total);

        for (int i = idx; i < batch_end; i++) {
            int capture_i = i;
            threads.emplace_back([&, capture_i]() {
                results[capture_i] = scan_one(targets[capture_i],
                                               p_start, p_end);
            });
        }

        // Ждём завершения всей пачки
        for (auto& t : threads) t.join();
        idx = batch_end;
    }

    return results;
}

// ── итоговая таблица ──────────────────────────────────
void MultiScanner::print_results(const std::vector<TargetResult>& results) {
    std::cout << "\n" << Color::CYAN << Color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                   ИТОГ ПАРАЛЛЕЛЬНОГО СКАНА                         ║\n";
    std::cout << "╠═══════════════════╦════════════════╦═══════╦═══════╦════════╦══════╣\n";
    std::cout << "║ ЦЕЛЬ              ║ IP             ║ ПОРТЫ ║  CVE  ║  ОС    ║  FW  ║\n";
    std::cout << "╠═══════════════════╬════════════════╬═══════╬═══════╬════════╬══════╣\n";
    std::cout << Color::RESET;

    int total_ports = 0;
    int total_cve   = 0;

    for (const auto& r : results) {
        if (r.error) {
            // Строка с ошибкой
            std::string t = r.target;
            if (t.size() > 17) t = t.substr(0, 14) + "...";
            while (t.size() < 17) t += " ";

            std::cout << Color::FAIL
                      << "║ " << t << " ║ ERROR          ║       ║       ║        ║      ║\n"
                      << Color::RESET;
            continue;
        }

        // Форматируем поля
        std::string t  = r.target; if (t.size()  > 17) t  = t.substr(0,14)+"...";
        std::string ip = r.ip;     if (ip.size() > 14) ip = ip.substr(0,11)+"...";
        std::string os = r.os;     if (os.size() > 6)  os = os.substr(0,6);

        while (t.size()  < 17) t  += " ";
        while (ip.size() < 14) ip += " ";
        while (os.size() < 6)  os += " ";

        std::string fw_str = r.firewall ? " ДА  " : " НЕТ ";

        // Цвет по количеству CVE
        std::string col = Color::GREEN;
        if (r.cve_count > 10) col = Color::RED;
        else if (r.cve_count > 3) col = Color::YELLOW;

        std::cout << col
                  << "║ " << t
                  << " ║ " << ip
                  << " ║ " << std::setw(5) << r.open_ports << " "
                  << " ║ " << std::setw(5) << r.cve_count  << " "
                  << " ║ " << os
                  << " ║" << fw_str << "║\n"
                  << Color::RESET;

        total_ports += r.open_ports;
        total_cve   += r.cve_count;
    }

    std::cout << Color::CYAN;
    std::cout << "╠═══════════════════╩════════════════╩═══════╩═══════╩════════╩══════╣\n";
    std::cout << "║ Итого: " << std::setw(2) << results.size()
              << " целей"
              << "   |  Открытых портов: " << std::setw(4) << total_ports
              << "  |  Найдено CVE: " << std::setw(4) << total_cve
              << "          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";
    std::cout << Color::RESET;

    std::cout << Color::INFO << "Отчёты сохранены в reports/\n" << Color::RESET;
}