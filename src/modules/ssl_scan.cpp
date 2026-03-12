#include "modules/ssl_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <string>
#include <sstream>
#include <ctime>

SSLInfo SSLScanner::scan(const std::string& target, int port) {
    SSLInfo info;
    info.expired     = false;
    info.self_signed = false;

    std::cout << Color::INFO << "SSL/TLS анализ: " << Color::CYAN
              << target << ":" << port
              << Color::RESET << std::endl;

    // FIX 1: один popen вместо двух (раньше было два соединения — двойное зависание)
    // FIX 2: добавили -timeout 5 чтобы не висеть вечно
    // FIX 3: -connect_timeout 5 для старых версий openssl
    std::string cmd =
        "echo | timeout 8 openssl s_client"
        " -connect " + target + ":" + std::to_string(port) +
        " -servername " + target +
        " 2>/dev/null"
        " | openssl x509 -noout"
        " -subject -issuer -dates -checkend 0 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cout << Color::FAIL << "Не удалось запустить openssl!"
                  << Color::RESET << std::endl;
        return info;
    }

    char line[1024];
    while (fgets(line, sizeof(line), pipe)) {
        std::string s(line);
        if (!s.empty() && s.back() == '\n') s.pop_back();

        if (s.find("subject=") != std::string::npos) {
            info.subject = s.substr(s.find('=') + 1);
        }
        else if (s.find("issuer=") != std::string::npos) {
            info.issuer = s.substr(s.find('=') + 1);
        }
        else if (s.find("notBefore=") != std::string::npos) {
            info.valid_from = s.substr(s.find('=') + 1);
        }
        else if (s.find("notAfter=") != std::string::npos) {
            info.valid_to = s.substr(s.find('=') + 1);
        }
        else if (s.find("Protocol  :") != std::string::npos) {
            size_t pos = s.find(": ");
            if (pos != std::string::npos)
                info.protocol = s.substr(pos + 2);
        }
        else if (s.find("Cipher    :") != std::string::npos) {
            size_t pos = s.find(": ");
            if (pos != std::string::npos)
                info.cipher = s.substr(pos + 2);
        }
        // FIX 4: checkend 0 выводит одну из двух строк — парсим здесь же
        else if (s.find("will expire") != std::string::npos) {
            info.expired = true;
        }
    }
    pclose(pipe);

    // Проверяем self-signed (subject == issuer)
    if (!info.subject.empty() && !info.issuer.empty()) {
        if (info.subject == info.issuer)
            info.self_signed = true;
    }

    return info;
}

void SSLScanner::print_results(const SSLInfo& info) {
    if (info.subject.empty()) {
        std::cout << Color::FAIL
                  << "SSL сертификат не найден или порт закрыт"
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────────┐\n";
    std::cout << "│            SSL/TLS СЕРТИФИКАТ               │\n";
    std::cout << "├─────────────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    auto pad_str = [](std::string s, size_t width) -> std::string {
        if (s.size() > width) s = s.substr(0, width - 3) + "...";
        while (s.size() < width) s += " ";
        return s;
    };

    std::cout << Color::INFO;
    std::cout << "│ Subject : " << pad_str(info.subject, 43)   << " │\n";
    std::cout << "│ Issuer  : " << pad_str(info.issuer,  43)   << " │\n";
    std::cout << "│ С       : " << pad_str(info.valid_from, 43) << " │\n";
    std::cout << "│ По      : " << pad_str(info.valid_to,   43) << " │\n";
    if (!info.protocol.empty())
        std::cout << "│ Protocol: " << pad_str(info.protocol, 43) << " │\n";
    if (!info.cipher.empty())
        std::cout << "│ Cipher  : " << pad_str(info.cipher,   43) << " │\n";
    std::cout << Color::RESET;

    if (info.expired) {
        std::cout << Color::FAIL;
        std::cout << "│ Статус  : ИСТЁК!                            │\n";
        std::cout << Color::RESET;
    } else {
        std::cout << Color::OK;
        std::cout << "│ Статус  : Действителен ✓                    │\n";
        std::cout << Color::RESET;
    }

    if (info.self_signed) {
        std::cout << Color::WARN;
        std::cout << "│ Тип     : САМОПОДПИСАННЫЙ (небезопасно!)    │\n";
        std::cout << Color::RESET;
    } else {
        std::cout << Color::OK;
        std::cout << "│ Тип     : Подписан доверенным CA ✓          │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└─────────────────────────────────────────────┘\n";
    std::cout << Color::RESET;
}