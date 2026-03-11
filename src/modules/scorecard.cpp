#include "modules/scorecard.h"
#include "utils/colors.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

ScoreCard Scorecard::calculate(const ScanResult& result) {
    ScoreCard sc;
    int score = 100;

    int cve_pen = 0;
    for (const auto& sev : result.cve_severities) {
        if      (sev == "CRITICAL") cve_pen += 15;
        else if (sev == "HIGH")     cve_pen += 8;
        else if (sev == "MEDIUM")   cve_pen += 3;
        else if (sev == "LOW")      cve_pen += 1;
    }
    cve_pen = std::min(cve_pen, 50);
    sc.cve_penalty = cve_pen;
    score -= cve_pen;

    int ports_pen = 0;
    int count = result.open_port_count;
    if      (count > 20) ports_pen = 20;
    else if (count > 10) ports_pen = 12;
    else if (count > 5)  ports_pen = 6;
    else if (count > 2)  ports_pen = 3;
    sc.ports_penalty = ports_pen;
    score -= ports_pen;

    int svc_pen = 0;
    if (result.has_telnet) svc_pen += 10;
    if (result.has_ftp)    svc_pen += 6;
    if (result.has_rdp)    svc_pen += 5;
    svc_pen = std::min(svc_pen, 20);
    sc.services_penalty = svc_pen;
    score -= svc_pen;

    int ssl_pen = 0;
    if (!result.has_ssl)    ssl_pen += 10;
    if (result.ssl_expired) ssl_pen += 8;
    if (result.has_ssl && !result.ssl_valid) ssl_pen += 5;
    sc.ssl_penalty = ssl_pen;
    score -= ssl_pen;

    if (result.waf_detected)      score += 5;
    if (result.firewall_detected) score += 3;

    score = std::max(0, std::min(100, score));
    sc.total = score;

    if      (score >= 90) { sc.grade = "A+"; sc.verdict = "Отличная защита"; }
    else if (score >= 80) { sc.grade = "A";  sc.verdict = "Хорошая защита"; }
    else if (score >= 70) { sc.grade = "B";  sc.verdict = "Средняя защита"; }
    else if (score >= 55) { sc.grade = "C";  sc.verdict = "Слабая защита"; }
    else if (score >= 40) { sc.grade = "D";  sc.verdict = "Плохая защита"; }
    else                  { sc.grade = "F";  sc.verdict = "Критическая уязвимость!"; }

    return sc;
}

static void print_ring(int score) {
    std::string col;
    if      (score >= 80) col = "\033[32m";
    else if (score >= 60) col = "\033[33m";
    else if (score >= 40) col = "\033[38;5;208m";
    else                  col = "\033[31m";

    std::cout << "\n";
    std::cout << "         ╭─────────────╮\n";
    std::cout << "         │             │\n";
    std::cout << "         │   " << col << "\033[1m";
    if (score < 10)  std::cout << "  ";
    if (score < 100) std::cout << " ";
    std::cout << score << " / 100";
    std::cout << "\033[0m" << "  │\n";
    std::cout << "         │             │\n";
    std::cout << "         ╰─────────────╯\n\n";
}

static void print_bar(const std::string& label, int penalty,
                      int max_pen, const std::string& col) {
    int filled = (max_pen > 0) ? (penalty * 20 / max_pen) : 0;
    filled = std::min(filled, 20);
    std::cout << "  " << std::left << std::setw(18) << label << " ";
    std::cout << col;
    for (int i = 0; i < filled; i++)  std::cout << "█";
    std::cout << "\033[0m";
    for (int i = filled; i < 20; i++) std::cout << "░";
    std::cout << "  -" << penalty << " pts\n";
}

void Scorecard::print(const ScoreCard& sc, const std::string& target) {
    std::string grade_col;
    if      (sc.grade == "A+" || sc.grade == "A") grade_col = "\033[32m";
    else if (sc.grade == "B")                      grade_col = "\033[36m";
    else if (sc.grade == "C")                      grade_col = "\033[33m";
    else                                           grade_col = "\033[31m";

    std::cout << "\n\033[36m\033[1m";
    std::cout << " ╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << " ║              SCORECARD БЕЗОПАСНОСТИ                         ║\n";
    std::cout << " ║  Цель: " << target;
    int pad = 53 - (int)target.size();
    for (int i = 0; i < pad; i++) std::cout << ' ';
    std::cout << "║\n";
    std::cout << " ╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "\033[0m";

    print_ring(sc.total);

    std::cout << "      Оценка: " << grade_col << "\033[1m"
              << sc.grade << "\033[0m" << "   —   "
              << grade_col << sc.verdict << "\033[0m" << "\n\n";

    std::cout << "\033[1m  АНАЛИЗ ШТРАФОВ:\n\033[0m";
    print_bar("CVE уязвимости",  sc.cve_penalty,      50, "\033[31m");
    print_bar("Открытые порты",  sc.ports_penalty,     20, "\033[33m");
    print_bar("Опасные сервисы", sc.services_penalty,  20, "\033[38;5;208m");
    print_bar("SSL/TLS",         sc.ssl_penalty,       10, "\033[36m");

    std::cout << "\n\033[1m  РЕКОМЕНДАЦИИ:\n\033[0m";
    if (sc.cve_penalty > 20)
        std::cout << "\033[31m  [!] Обновите ПО — обнаружены CRITICAL уязвимости\n\033[0m";
    if (sc.ports_penalty > 10)
        std::cout << "\033[33m  [!] Закройте лишние порты через firewall\n\033[0m";
    if (sc.services_penalty >= 10)
        std::cout << "\033[33m  [!] Замените Telnet/FTP на SSH/SFTP\n\033[0m";
    if (sc.ssl_penalty >= 8)
        std::cout << "\033[36m  [i] Обновите или установите SSL-сертификат\n\033[0m";
    if (sc.total >= 80)
        std::cout << "\033[32m  [+] Хорошая защита. Продолжайте следить за CVE.\n\033[0m";

    std::cout << "\n\033[36m\033[1m";
    std::cout << " ╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}
