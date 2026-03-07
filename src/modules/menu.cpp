#include "modules/menu.h"
#include "modules/threads.h"
#include "modules/os_detect.h"
#include "modules/firewall.h"
#include "modules/subdomain.h"
#include "modules/whois.h"
#include "modules/cve.h"
#include "modules/report.h"
#include "modules/packet_capture.h"
#include "utils/colors.h"
#include "utils/progress.h"
#include "utils/banner.h"
#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include <chrono>

void Menu::show_help() {
    std::cout << Color::CYAN << Color::BOLD;
    std::cout << "┌─────────────────────────────────────────┐\n";
    std::cout << "│           ДОСТУПНЫЕ КОМАНДЫ             │\n";
    std::cout << "├─────────────────────────────────────────┤\n";
    std::cout << "│  1 - Полное сканирование                │\n";
    std::cout << "│  2 - Быстрый скан (топ 100 портов)      │\n";
    std::cout << "│  3 - Поиск поддоменов                   │\n";
    std::cout << "│  4 - Мониторинг пакетов                 │\n";
    std::cout << "│  5 - Сменить цель                       │\n";
    std::cout << "│  0 - Выход                              │\n";
    std::cout << "└─────────────────────────────────────────┘\n";
    std::cout << Color::RESET << std::endl;
}

bool Menu::get_target() {
    std::cout << Color::INFO << "Введите IP или домен: " << Color::CYAN;
    std::cin >> target;
    original_target = target;  
    std::cout << Color::RESET;

    // Резолвинг домена в IP
    struct hostent* host = gethostbyname(target.c_str());
    if (!host) {
        std::cout << Color::FAIL << "[-] Не удалось разрезолвить: " 
                  << target << Color::RESET << std::endl;
        return false;
    }

    std::string ip = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
    if (ip != target) {
        std::cout << Color::INFO << " Резолвинг: " << Color::YELLOW 
                  << target << " -> " << ip << Color::RESET << std::endl;
    }
    target = ip;  // ВАЖНО: заменяем домен на IP!
    return true;
}

void Menu::full_scan() {
    std::cout << "\n" << Color::INFO << "Полное сканирование: " 
              << Color::CYAN << target << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    auto scan_start = std::chrono::steady_clock::now();

    // WHOIS
    Whois whois;
    WhoisResult wi = whois.lookup(target);
    std::cout << Color::INFO << "Страна: " << Color::YELLOW 
              << wi.country << Color::RESET << std::endl;
    std::cout << Color::INFO << "Город : " << Color::YELLOW 
              << wi.city << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    // OS
    OSDetector os_det;
    std::string os = os_det.detect(target);
    std::cout << Color::INFO << "ОС: " << Color::YELLOW 
              << os << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    // Порты
    std::cout << Color::INFO << "Сканируем порты 1-1024..." << Color::RESET << std::endl;
    ThreadScanner scanner(target, 10);
    auto results = scanner.scan(1, 1024);
    print_table(results);

    // CVE
    std::cout << Color::WARN << "Проверяем CVE..." << Color::RESET << std::endl;
    CVEScanner cve;
    for (const auto& r : results) {
        auto cves = cve.search(r.service);
        if (!cves.empty()) {
            std::cout << Color::INFO << "Порт " << r.port 
                      << " (" << r.service << "):" << Color::RESET << std::endl;
            cve.print_results(r.service, cves);
        }
    }
    std::cout << "──────────────────────────────────────────\n";

    // Firewall
    FirewallDetector fw;
    FirewallResult fw_result = fw.detect(target);
    if (fw_result.detected) {
        std::cout << Color::WARN << fw_result.status << Color::RESET << std::endl;
    } else {
        std::cout << Color::OK << fw_result.status << Color::RESET << std::endl;
    }
    std::cout << "──────────────────────────────────────────\n";

    // Subdomains
    SubdomainEnum sub;
    auto subs = sub.enumerate(original_target);
    std::cout << "──────────────────────────────────────────\n";

    auto scan_end = std::chrono::steady_clock::now();
    int scan_sec = std::chrono::duration_cast<std::chrono::seconds>
                   (scan_end - scan_start).count();

    // Summary
    print_summary(target, os, results.size(), scan_sec);

    // Reports
    std::cout << Color::INFO << "Сохраняем отчёты..." << Color::RESET << std::endl;
    ScanReport report;
    report.target = target;
    report.ip = target;
    report.os = os;
    report.country = wi.country;
    report.city = wi.city;
    report.isp = wi.isp;
    report.firewall_detected = fw_result.detected;
    report.ports = results;
    report.scan_time = scan_sec;
    for (const auto& s : subs) {
        report.subdomains.push_back(s.subdomain + " → " + s.ip);
    }

    Reporter reporter;
    reporter.save_txt(report);
    reporter.save_json(report);
    reporter.save_html(report);
}

void Menu::quick_scan() {
    std::cout << "\n" << Color::INFO << "Быстрый скан топ 100 портов..." 
              << Color::RESET << std::endl;

    // Топ 100 популярных портов
    int top_ports[] = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        8443, 8888, 9200, 27017, 5432, 6379, 2181, 8161, 61616, 9092,
        1433, 1521, 5984, 7474, 9300, 11211, 28017, 50000, 7000, 7001
    };

    ThreadScanner scanner(target, 10);
    auto results = scanner.scan(1, 1024);
    print_table(results);
}

void Menu::subdomain_scan() {
    std::cout << "\n" << Color::INFO << "Поиск поддоменов..." 
              << Color::RESET << std::endl;
    SubdomainEnum sub;
    auto results = sub.enumerate(target);
    std::cout << Color::INFO << "Найдено: " << Color::GREEN 
              << results.size() << Color::RESET << std::endl;
}

void Menu::packet_monitor() {
    std::cout << "\n" << Color::INFO << "Мониторинг пакетов (lo)..." 
              << Color::RESET << std::endl;
    PacketCapture capture("lo");
    capture.start(20);
}

void Menu::run() {
    print_banner();

    if (!get_target()) {
        std::cout << Color::FAIL << "Ошибка ввода цели!" << Color::RESET << std::endl;
        return;
    }

    while (true) {
        std::cout << "\n" << Color::BOLD << Color::CYAN;
        std::cout << "┌─────────────────────────────────────────┐\n";
        std::cout << "│   PhantomScan  │  Цель: ";
        std::string t = target;
        if (t.size() > 15) t = t.substr(0, 15);
        while (t.size() < 15) t += " ";
        std::cout << t << "  │\n";
        std::cout << "├─────────────────────────────────────────┤\n";
        std::cout << "│  [1] Полное сканирование                │\n";
        std::cout << "│  [2] Быстрый скан                       │\n";
        std::cout << "│  [3] Поиск поддоменов                   │\n";
        std::cout << "│  [4] Мониторинг пакетов                 │\n";
        std::cout << "│  [5] Сменить цель                       │\n";
        std::cout << "│  [0] Выход                              │\n";
        std::cout << "└─────────────────────────────────────────┘\n";
        std::cout << Color::RESET;

        std::cout << Color::YELLOW << "Выбор: " << Color::RESET;
        int choice;
        std::cin >> choice;

        switch (choice) {
            case 1: full_scan();      break;
            case 2: quick_scan();     break;
            case 3: subdomain_scan(); break;
            case 4: packet_monitor(); break;
            case 5: get_target();     break;
            case 0:
                std::cout << Color::INFO << "До свидания! " 
                          << Color::RESET << std::endl;
                return;
            default:
                std::cout << Color::FAIL << "Неверный выбор!" 
                          << Color::RESET << std::endl;
        }
    }
}