#include "modules/exploit.h"
#include "modules/topology.h"
#include "modules/vuln_scan.h"
#include "modules/wordlist.h"
#include "modules/shodan.h"
#include "modules/syn_scan.h"
#include "modules/ssl_scan.h"
#include "modules/waf_detect.h"
#include "modules/arp_scan.h"
#include "modules/traceroute.h"
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

void Menu::arp_scan() {
    std::cout << Color::INFO << "Введите подсеть (например 192.168.1.0/24): " 
              << Color::CYAN;
    std::string subnet;
    std::cin >> subnet;
    std::cout << Color::RESET;

    ARPScanner arp;
    auto hosts = arp.scan(subnet);
    arp.print_results(hosts);
}

void Menu::traceroute_scan() {
    Traceroute tr;
    auto hops = tr.trace(original_target);
    tr.print_results(hops);
}

void Menu::syn_scan() {
    std::cout << Color::INFO << "Порты для SYN скана (например 1-1024): "
              << Color::CYAN;
    std::string range;
    std::cin >> range;
    std::cout << Color::RESET;

    int p_start = 1, p_end = 1024;
    size_t dash = range.find('-');
    if (dash != std::string::npos) {
        p_start = std::stoi(range.substr(0, dash));
        p_end   = std::stoi(range.substr(dash + 1));
    }

    SYNScanner syn;
    auto results = syn.scan(target, p_start, p_end);
    syn.print_results(results);
}

void Menu::ssl_scan() {
    SSLScanner ssl;
    auto info = ssl.scan(original_target);
    ssl.print_results(info);
}

void Menu::waf_detect() {
    WAFDetector waf;
    auto result = waf.detect(original_target);
    waf.print_results(result);
}

void Menu::vuln_scan() {
    VulnScanner vuln;
    auto results = vuln.scan(target, 1, 9999);
    vuln.print_results(results);
}

void Menu::wordlist_scan() {
    WordlistGenerator wl;
    auto found = wl.generate(original_target);
    wl.print_results(found);

    if (!found.empty()) {
        std::string filename = "reports/" + original_target
                             + "_wordlist.txt";
        wl.save_to_file(found, filename);
    }
}

void Menu::shodan_lookup() {
    std::cout << Color::INFO << "Введите Shodan API ключ: "
              << Color::CYAN;
    std::string key;
    std::cin >> key;
    std::cout << Color::RESET;

    ShodanAPI shodan;
    shodan.set_api_key(key);
    auto result = shodan.lookup(target);
    shodan.print_results(result);
}

void Menu::exploit_search() {
    std::cout << Color::INFO << "Введите сервис (SSH/HTTP/FTP/MySQL): "
              << Color::CYAN;
    std::string service;
    std::cin >> service;
    std::cout << Color::RESET;

    ExploitSuggester es;
    auto results = es.search(service, "");
    es.print_results(results);
}

void Menu::topology_scan() {
    std::cout << Color::INFO << "Запускаем трассировку для топологии..."
              << Color::RESET << std::endl;

    Traceroute tr;
    auto hops = tr.trace(original_target);

    // Конвертируем TraceHop в TopoNode
    std::vector<TopoNode> nodes;
    for (const auto& h : hops) {
        TopoNode n;
        n.hop      = h.hop;
        n.ip       = h.ip;
        n.hostname = h.hostname;
        n.rtt_ms   = h.rtt_ms;
        n.timeout  = h.timeout;
        nodes.push_back(n);
    }

    NetworkTopology topo;
    topo.build(nodes, original_target);
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
        std::cout << "│  [1]  Полное сканирование               │\n";
        std::cout << "│  [2]  Быстрый скан                      │\n";
        std::cout << "│  [3]  Поиск поддоменов                  │\n";
        std::cout << "│  [4]  Мониторинг пакетов                │\n";
        std::cout << "│  [5]  ARP скан сети                     │\n";
        std::cout << "│  [6]  Трассировка маршрута              │\n";
        std::cout << "│  [7]  SYN Stealth скан                  │\n";
        std::cout << "│  [8]  SSL/TLS анализ                    │\n";
        std::cout << "│  [9]  Определение WAF                   │\n";
        std::cout << "│  [10] Сканер уязвимых версий            │\n";
        std::cout << "│  [11] Генератор wordlist                │\n";
        std::cout << "│  [12] Shodan поиск                      │\n";
        std::cout << "│  [13] Exploit Suggester                 │\n";
        std::cout << "│  [14] Топология сети                    │\n";
        std::cout << "│  [15] Сменить цель                      │\n";
        std::cout << "│  [0]  Выход                             │\n";
        std::cout << Color::RESET;

        std::cout << Color::YELLOW << "Выбор: " << Color::RESET;
        int choice;
        std::cin >> choice;

        switch (choice) {
    case 1:  full_scan();         break;
    case 2:  quick_scan();        break;
    case 3:  subdomain_scan();    break;
    case 4:  packet_monitor();    break;
    case 5:  arp_scan();          break;
    case 6:  traceroute_scan();   break;
    case 7:  syn_scan();          break;
    case 8:  ssl_scan();          break;
    case 9:  waf_detect();        break;
    case 10: vuln_scan();         break;
    case 11: wordlist_scan();     break;
    case 12: shodan_lookup();     break;
    case 13: exploit_search();    break;
    case 14: topology_scan();     break;
    case 15: get_target();        break;
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

void Menu::run_cli(const std::string& t, int p_start, int p_end,
                   const std::string& output) {
    print_banner();

    original_target = t;
    struct hostent* host = gethostbyname(t.c_str());
    if (!host) {
        std::cout << Color::FAIL << "[-] Не удалось разрезолвить: " 
                  << t << Color::RESET << std::endl;
        return;
    }
    target = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
    if (target != t) {
        std::cout << Color::INFO << "Резолвинг: " << Color::YELLOW
                  << t << " -> " << target << Color::RESET << std::endl;
    }

    std::cout << Color::INFO << "Порты: " << Color::CYAN 
              << p_start << "-" << p_end << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    auto scan_start = std::chrono::steady_clock::now();

    Whois whois;
    WhoisResult wi = whois.lookup(target);
    std::cout << Color::INFO << "Страна: " << Color::YELLOW 
              << wi.country << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    OSDetector os_det;
    std::string os = os_det.detect(target);
    std::cout << Color::INFO << "ОС: " << Color::YELLOW 
              << os << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────\n";

    ThreadScanner scanner(target, 10);
    auto results = scanner.scan(p_start, p_end);
    print_table(results);

    CVEScanner cve;
    for (const auto& r : results) {
        auto cves = cve.search(r.service);
        if (!cves.empty()) cve.print_results(r.service, cves);
    }

    FirewallDetector fw;
    FirewallResult fw_result = fw.detect(target);
    std::cout << (fw_result.detected ? Color::WARN : Color::OK)
              << fw_result.status << Color::RESET << std::endl;

    SubdomainEnum sub;
    auto subs = sub.enumerate(original_target);

    auto scan_end = std::chrono::steady_clock::now();
    int scan_sec = std::chrono::duration_cast<std::chrono::seconds>
                   (scan_end - scan_start).count();

    print_summary(target, os, results.size(), scan_sec);

    ScanReport report;
    report.target = original_target;
    report.ip = target;
    report.os = os;
    report.country = wi.country;
    report.city = wi.city;
    report.isp = wi.isp;
    report.firewall_detected = fw_result.detected;
    report.ports = results;
    report.scan_time = scan_sec;
    for (const auto& s : subs)
        report.subdomains.push_back(s.subdomain + " → " + s.ip);

    Reporter reporter;
    if (output == "txt" || output == "all") reporter.save_txt(report);
    if (output == "json" || output == "all") reporter.save_json(report);
    if (output == "html" || output == "all") reporter.save_html(report);
}
