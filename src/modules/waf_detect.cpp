#include "modules/waf_detect.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <string>

WAFResult WAFDetector::detect(const std::string& target) {
    WAFResult result;
    result.detected = false;
    result.name     = "Не обнаружен";
    result.evidence = "";

    std::cout << Color::INFO << "Определяем WAF: " << Color::CYAN
              << target << Color::RESET << std::endl;

    // Получаем заголовки через curl
    std::string cmd = "curl -sI -m 5 --insecure https://" 
                    + target + " 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return result;

    std::string headers = "";
    char line[1024];
    while (fgets(line, sizeof(line), pipe)) {
        headers += std::string(line);
    }
    pclose(pipe);

    // Если https не ответил — пробуем http
    if (headers.empty()) {
        cmd = "curl -sI -m 5 http://" + target + " 2>/dev/null";
        pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            while (fgets(line, sizeof(line), pipe))
                headers += std::string(line);
            pclose(pipe);
        }
    }

    if (headers.empty()) {
        std::cout << Color::WARN << "Сервер не отвечает"
                  << Color::RESET << std::endl;
        return result;
    }

    // Определяем WAF по заголовкам
    auto contains = [&](const std::string& s) {
        return headers.find(s) != std::string::npos;
    };

    if (contains("cloudflare") || contains("Cloudflare") ||
        contains("cf-ray") || contains("CF-RAY")) {
        result.detected  = true;
        result.name      = "Cloudflare";
        result.evidence  = "Заголовок: cf-ray / cloudflare";
    }
    else if (contains("X-Sucuri") || contains("sucuri") ||
             contains("Sucuri")) {
        result.detected  = true;
        result.name      = "Sucuri";
        result.evidence  = "Заголовок: X-Sucuri";
    }
    else if (contains("X-CDN: Incapsula") || 
             contains("incap_ses") ||
             contains("visid_incap")) {
        result.detected  = true;
        result.name      = "Imperva Incapsula";
        result.evidence  = "Заголовок: X-CDN / Cookie: incap_ses";
    }
    else if (contains("X-Akamai") || contains("AkamaiGHost") ||
             contains("akamai")) {
        result.detected  = true;
        result.name      = "Akamai";
        result.evidence  = "Заголовок: X-Akamai / AkamaiGHost";
    }
    else if (contains("X-Powered-By: AWS") || 
             contains("awselb") ||
             contains("x-amzn")) {
        result.detected  = true;
        result.name      = "AWS WAF";
        result.evidence  = "Заголовок: x-amzn / awselb";
    }
    else if (contains("X-Azure") || contains("Azure")) {
        result.detected  = true;
        result.name      = "Azure Front Door";
        result.evidence  = "Заголовок: X-Azure";
    }
    else if (contains("X-FireWall") || contains("Barracuda")) {
        result.detected  = true;
        result.name      = "Barracuda WAF";
        result.evidence  = "Заголовок: X-FireWall";
    }
    else if (contains("mod_security") || 
             contains("Mod_Security") ||
             contains("NOYB")) {
        result.detected  = true;
        result.name      = "ModSecurity";
        result.evidence  = "Заголовок: mod_security";
    }

    return result;
}

void WAFDetector::print_results(const WAFResult& result) {
    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────────┐\n";
    std::cout << "│              WAF ДЕТЕКТОР                   │\n";
    std::cout << "├─────────────────────────────────────────────┤\n";
    std::cout << Color::RESET;

    if (result.detected) {
        std::string name = result.name;
        while (name.size() < 43) name += " ";
        std::string ev = result.evidence;
        if (ev.size() > 43) ev = ev.substr(0, 40) + "...";
        while (ev.size() < 43) ev += " ";

        std::cout << Color::FAIL;
        std::cout << "│ WAF     : ОБНАРУЖЕН!                        │\n";
        std::cout << Color::RESET;
        std::cout << Color::WARN;
        std::cout << "│ Тип     : " << name << " │\n";
        std::cout << "│ Признак : " << ev   << " │\n";
        std::cout << Color::RESET;
    } else {
        std::cout << Color::OK;
        std::cout << "│ WAF     : Не обнаружен                      │\n";
        std::cout << Color::RESET;
        std::cout << Color::INFO;
        std::cout << "│ Внимание: WAF может быть скрыт              │\n";
        std::cout << Color::RESET;
    }

    std::cout << Color::CYAN;
    std::cout << "└─────────────────────────────────────────────┘\n";
    std::cout << Color::RESET;
}