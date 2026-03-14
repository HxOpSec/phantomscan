#include "modules/ssl_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <string>

SSLInfo SSLScanner::scan(const std::string& target, int port) {
    SSLInfo info;
    info.expired     = false;
    info.self_signed = false;

    std::cout << Color::INFO << "SSL/TLS анализ: " << Color::CYAN
              << target << ":" << port << Color::RESET << "\n";

    std::string cmd =
        "echo | timeout 8 openssl s_client"
        " -connect " + target + ":" + std::to_string(port) +
        " -servername " + target +
        " 2>/dev/null"
        " | openssl x509 -noout"
        " -subject -issuer -dates -checkend 0 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cout << Color::FAIL << "Не удалось запустить openssl!\n"
                  << Color::RESET;
        return info;
    }

    char line[2048];
    while (fgets(line, sizeof(line), pipe)) {
        std::string s(line);
        if (!s.empty() && s.back() == '\n') s.pop_back();
        if (!s.empty() && s.back() == '\r') s.pop_back();

        auto after = [&](const std::string& key) -> std::string {
            size_t pos = s.find(key);
            if (pos == std::string::npos) return "";
            return s.substr(pos + key.size());
        };

        if      (s.find("subject=")    != std::string::npos) info.subject    = after("subject=");
        else if (s.find("issuer=")     != std::string::npos) info.issuer     = after("issuer=");
        else if (s.find("notBefore=")  != std::string::npos) info.valid_from = after("notBefore=");
        else if (s.find("notAfter=")   != std::string::npos) info.valid_to   = after("notAfter=");
        else if (s.find("Protocol  :") != std::string::npos) info.protocol   = after("Protocol  : ");
        else if (s.find("Cipher    :") != std::string::npos) info.cipher     = after("Cipher    : ");
        else if (s.find("will expire") != std::string::npos) info.expired    = true;
    }
    pclose(pipe);

    if (!info.subject.empty() && !info.issuer.empty())
        info.self_signed = (info.subject == info.issuer);

    return info;
}

void SSLScanner::print_results(const SSLInfo& info) {
    if (info.subject.empty()) {
        std::cout << Color::FAIL
                  << "[-] SSL сертификат не найден или порт закрыт\n"
                  << Color::RESET;
        return;
    }

    // W = ширина поля значения (после "║  Label    : ")
    // Строка: "║  " + label(9) + " : " + value(W) + " ║"
    // Итого:   2   +    9      +  3   +    W      +  2  = W+16
    // Рамка:  "╔" + "═"*(W+14) + "╗" 
    // W=36 => строка=52 символа => рамка из 50 "═"
    const size_t W = 36;

    auto fit = [](std::string s, size_t w) -> std::string {
        if (s.size() > w) return s.substr(0, w - 3) + "...";
        while (s.size() < w) s += " ";
        return s;
    };

    // Рамка ровно 50 символов между ╔ и ╗
    #define LINE "══════════════════════════════════════════════════"
    #define ROW(label, val) \
        "║  " label " : " << val << " ║\n"

    std::cout << "\n" << Color::CYAN
              << "╔" LINE "╗\n"
              << "║       SSL / TLS  CERTIFICATE                     ║\n"
              << "╠" LINE "╣\n"
              << Color::RESET;

    std::cout << Color::WHITE
              << "║  Subject  : " << Color::YELLOW << fit(info.subject,    W) << Color::WHITE << " ║\n"
              << "║  Issuer   : " << Color::YELLOW << fit(info.issuer,     W) << Color::WHITE << " ║\n"
              << Color::CYAN << "╠" LINE "╣\n" << Color::WHITE
              << "║  Valid  C : " << Color::CYAN  << fit(info.valid_from,  W) << Color::WHITE << " ║\n"
              << "║  Valid  D : " << Color::CYAN  << fit(info.valid_to,    W) << Color::WHITE << " ║\n";

    if (!info.protocol.empty())
        std::cout << "║  Protocol : " << Color::CYAN << fit(info.protocol, W) << Color::WHITE << " ║\n";
    if (!info.cipher.empty())
        std::cout << "║  Cipher   : " << Color::CYAN << fit(info.cipher,   W) << Color::WHITE << " ║\n";

    std::cout << Color::CYAN << "╠" LINE "╣\n" << Color::RESET;

    if (info.expired)
        std::cout << Color::RED    << "║  Status   : EXPIRED  [!]" << std::string(25, ' ') << "║\n" << Color::RESET;
    else
        std::cout << Color::GREEN  << "║  Status   : Valid    [OK]" << std::string(24, ' ') << "║\n" << Color::RESET;

    if (info.self_signed)
        std::cout << Color::YELLOW << "║  Type     : Self-Signed  [WARN]" << std::string(18, ' ') << "║\n" << Color::RESET;
    else
        std::cout << Color::GREEN  << "║  Type     : Trusted CA   [OK]" << std::string(20, ' ') << "║\n" << Color::RESET;

    std::cout << Color::CYAN << "╚" LINE "╝\n" << Color::RESET;

    #undef LINE
    #undef ROW
}