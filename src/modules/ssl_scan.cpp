#include "modules/ssl_scan.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <string>
#include <sstream>

SSLInfo SSLScanner::scan(const std::string& target, int port) {
    SSLInfo info;
    info.expired     = false;
    info.self_signed = false;

    std::cout << Color::INFO << "SSL/TLS анализ: " << Color::CYAN
              << target << ":" << port
              << Color::RESET << std::endl;

    // Используем openssl через popen
    std::string cmd = "echo | openssl s_client -connect "
                    + target + ":" + std::to_string(port)
                    + " -servername " + target
                    + " 2>/dev/null | openssl x509 -noout"
                    + " -subject -issuer -dates -text 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cout << Color::FAIL << "Не удалось запустить openssl!"
                  << Color::RESET << std::endl;
        return info;
    }

    char line[1024];
    while (fgets(line, sizeof(line), pipe)) {
        std::string s(line);

        // Убираем \n
        if (!s.empty() && s.back() == '\n') s.pop_back();

        // subject
        if (s.find("subject=") != std::string::npos ||
            s.find("subject :") != std::string::npos) {
            info.subject = s.substr(s.find('=') + 1);
        }
        // issuer
        else if (s.find("issuer=") != std::string::npos) {
            info.issuer = s.substr(s.find('=') + 1);
        }
        // notBefore
        else if (s.find("notBefore=") != std::string::npos) {
            info.valid_from = s.substr(s.find('=') + 1);
        }
        // notAfter
        else if (s.find("notAfter=") != std::string::npos) {
            info.valid_to = s.substr(s.find('=') + 1);
        }
        // Protocol
        else if (s.find("Protocol  :") != std::string::npos) {
            size_t pos = s.find(": ");
            if (pos != std::string::npos)
                info.protocol = s.substr(pos + 2);
        }
        // Cipher
        else if (s.find("Cipher    :") != std::string::npos) {
            size_t pos = s.find(": ");
            if (pos != std::string::npos)
                info.cipher = s.substr(pos + 2);
        }
    }
    pclose(pipe);

    // Проверяем self-signed (subject == issuer)
    if (!info.subject.empty() && !info.issuer.empty()) {
        if (info.subject == info.issuer)
            info.self_signed = true;
    }

    // Проверяем истёк ли сертификат через openssl verify
    std::string verify_cmd = "echo | openssl s_client -connect "
                           + target + ":" + std::to_string(port)
                           + " -servername " + target
                           + " 2>/dev/null | openssl x509 -noout"
                           + " -checkend 0 2>/dev/null";
    FILE* vp = popen(verify_cmd.c_str(), "r");
    if (vp) {
        char vbuf[256];
        if (fgets(vbuf, sizeof(vbuf), vp)) {
            std::string vs(vbuf);
            if (vs.find("will expire") != std::string::npos)
                info.expired = true;
        }
        pclose(vp);
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

    // Subject (обрезаем если длинный)
    std::string subj = info.subject;
    if (subj.size() > 43) subj = subj.substr(0, 40) + "...";
    while (subj.size() < 43) subj += " ";

    std::string iss = info.issuer;
    if (iss.size() > 43) iss = iss.substr(0, 40) + "...";
    while (iss.size() < 43) iss += " ";

    std::cout << Color::INFO;
    std::cout << "│ Subject : " << subj << " │\n";
    std::cout << "│ Issuer  : " << iss  << " │\n";
    std::cout << "│ С       : " << info.valid_from;
    // Дополняем пробелами
    int pad = 43 - (int)info.valid_from.size();
    for (int i = 0; i < pad; i++) std::cout << " ";
    std::cout << " │\n";
    std::cout << "│ По      : " << info.valid_to;
    pad = 43 - (int)info.valid_to.size();
    for (int i = 0; i < pad; i++) std::cout << " ";
    std::cout << " │\n";
    std::cout << Color::RESET;

    // Статус сертификата
    if (info.expired) {
        std::cout << Color::FAIL;
        std::cout << "│ Статус  : ИСТЁК!                            │\n";
        std::cout << Color::RESET;
    } else {
        std::cout << Color::OK;
        std::cout << "│ Статус  : Действителен                      │\n";
        std::cout << Color::RESET;
    }

    if (info.self_signed) {
        std::cout << Color::WARN;
        std::cout << "│ Тип     : САМОПОДПИСАННЫЙ (небезопасно!)    │\n";
        std::cout << Color::RESET;
    } else {
        std::cout << Color::OK;
        std::cout << "│ Тип     : Подписан доверенным CA            │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└─────────────────────────────────────────────┘\n";
    std::cout << Color::RESET;
}