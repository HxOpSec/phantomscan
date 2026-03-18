#include "modules/waf_detect.h"
#include "utils/colors.h"
#include <iostream>
#include <string>
#include <cstdio>
#include <memory>
#include <vector>
#include <algorithm>

// ── Приводим строку к нижнему регистру ───────────────
static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// ── Выполняем команду ─────────────────────────────────
static std::string exec_cmd(const std::string& cmd) {
    std::string result;
    char line[2048];
    auto closer = [](FILE* f) { if (f) pclose(f); };
    std::unique_ptr<FILE, decltype(closer)> fp(
        popen(cmd.c_str(), "r"), closer);
    if (!fp) return "";
    while (fgets(line, sizeof(line), fp.get()))
        result += line;
    return result;
}

WAFResult WAFDetector::detect(const std::string& target) {
    WAFResult result;
    result.detected = false;
    result.name     = "Not Detected";
    result.evidence = "";

    std::cout << Color::INFO << "Определяем WAF: " << Color::CYAN
              << target << Color::RESET << "\n";

    // Пробуем HTTPS, потом HTTP
    std::string headers;
    std::string body;

    for (const auto& proto : {"https", "http"}) {
        std::string cmd = "curl -sI -A 'Mozilla/5.0' -m 8 --insecure "
                        + std::string(proto) + "://" + target
                        + " 2>/dev/null";
        headers = exec_cmd(cmd);
        if (!headers.empty()) break;
    }

    // Также получаем тело страницы (некоторые WAF видны в body)
    std::string cmd_body = "curl -s -A 'Mozilla/5.0' -m 8 --insecure "
                           "https://" + target +
                           " 2>/dev/null | head -c 2000";
    body = exec_cmd(cmd_body);

    if (headers.empty() && body.empty()) {
        std::cout << Color::WARN << "[!] Сервер не отвечает\n"
                  << Color::RESET;
        return result;
    }

    std::string all   = headers + body;
    std::string lower = to_lower(all);

    // ── Функция поиска (case-insensitive) ─────────────
    // NOTE: all strings passed to has() must be lowercase — WAF signatures
    // and additional check literals below are all lowercase by construction.
    auto has = [&](const std::string& s) -> bool {
        return lower.find(s) != std::string::npos;
    };

    // ── База WAF сигнатур ─────────────────────────────
    struct WAFSig {
        const char* name;
        std::vector<std::string> signatures;
        const char* evidence;
    };

    std::vector<WAFSig> waf_db = {
        { "Cloudflare",
          { "cf-ray", "cloudflare", "cf-cache-status",
            "__cfduid", "cf-request-id" },
          "Header: cf-ray / cloudflare" },

        { "AWS WAF / CloudFront",
          { "x-amzn-requestid", "x-amz-cf-id", "awselb",
            "x-amzn-trace-id", "x-cache: hit from cloudfront" },
          "Header: x-amzn / x-amz-cf-id" },

        { "Akamai",
          { "akamai", "x-akamai", "akamaighost",
            "x-check-cacheable", "ak_bmsc" },
          "Header: X-Akamai / AkamaiGHost" },

        { "Imperva Incapsula",
          { "x-cdn: incapsula", "incap_ses", "visid_incap",
            "x-iinfo", "incapsula" },
          "Header: X-CDN=Incapsula / Cookie: incap_ses" },

        { "Sucuri",
          { "x-sucuri", "sucuri", "x-sucuri-id",
            "x-sucuri-cache" },
          "Header: X-Sucuri" },

        { "ModSecurity",
          { "mod_security", "modsecurity", "noyb",
            "x-mod-sec", "501 method not implemented" },
          "Header: mod_security / 501 response" },

        { "F5 BIG-IP ASM",
          { "x-wa-info", "bigip", "f5-TrafficShield",
            "ts=", "x-cnection" },
          "Header: X-WA-Info / BigIP" },

        { "Barracuda WAF",
          { "barracuda", "x-firewall",
            "barra_counter_session" },
          "Header: X-FireWall / Barracuda" },

        { "Fortinet FortiWeb",
          { "fortiwafsid", "x-fw-", "fortiweb",
            "cookiesession1" },
          "Header: FORTIWAFSID / FortiWeb" },

        { "Azure Front Door",
          { "x-azure-ref", "x-fd-healthprobe",
            "x-msedge-ref", "azure" },
          "Header: X-Azure-Ref / X-MSEdge-Ref" },

        { "DDoS-Guard",
          { "ddos-guard", "x-ddos-guard",
            "__ddg1", "__ddg2" },
          "Header/Cookie: DDoS-Guard" },

        { "Nginx / OpenResty WAF",
          { "x-ngx-proxy", "openresty",
            "x-ratelimit-limit" },
          "Header: X-Ngx-Proxy / OpenResty" },

        { "Wallarm",
          { "wallarm", "x-wallarm-node" },
          "Header: X-Wallarm-Node" },

        { "Radware AppWall",
          { "x-sl-compstate", "rdwr", "appwall" },
          "Header: X-SL-CompState / Radware" },

        { "Reblaze",
          { "rbzid", "x-reblaze", "reblaze" },
          "Cookie: rbzid / Reblaze" },
    };

    // Проверяем каждый WAF
    for (const auto& waf : waf_db) {
        for (const auto& sig : waf.signatures) {
            if (has(sig)) {
                result.detected = true;
                result.name     = waf.name;
                result.evidence = waf.evidence;
                return result;
            }
        }
    }

    // Дополнительная проверка — нестандартный статус 403/406/429
    // может означать WAF без явных заголовков
    if (has("x-powered-by:") == false &&
        (has("403 forbidden") || has("406 not acceptable") ||
         has("429 too many"))) {
        result.detected = false; // не уверены — не помечаем
        result.name     = "Possible WAF (403/429)";
        result.evidence = "Suspicious HTTP status code";
    }

    return result;
}

void WAFDetector::print_results(const WAFResult& result) {
    // Рамка: ║ + 48 символов + ║
    // Префикс "  Label    : " = 13 символов => значение = 48-13-1 = 34
    const int W = 34;
    auto fit = [&](std::string s) -> std::string {
        if ((int)s.size() > W) return s.substr(0, W - 3) + "...";
        s.resize(W, ' ');
        return s;
    };

    auto row = [](std::string content) -> std::string {
        content.resize(48, ' ');
        return "║" + content + "║\n";
    };

    std::cout << "\n" << Color::CYAN
              << "╔════════════════════════════════════════════════╗\n"
              << row("      WAF / FIREWALL DETECTOR")
              << "╠════════════════════════════════════════════════╣\n"
              << Color::RESET;

    if (result.detected) {
        std::cout << Color::RED
                  << row("  Status   : WAF DETECTED  [!]")
                  << Color::YELLOW
                  << row("  WAF Name : " + fit(result.name))
                  << row("  Evidence : " + fit(result.evidence))
                  << Color::CYAN
                  << "╠════════════════════════════════════════════════╣\n"
                  << Color::YELLOW
                  << row("  [!] Bypass WAF before scanning!       ")
                  << Color::RESET;
    } else {
        std::cout << Color::GREEN
                  << row("  Status   : Not Detected  [OK]")
                  << Color::CYAN
                  << "╠════════════════════════════════════════════════╣\n"
                  << Color::WHITE
                  << row("  [*] WAF может быть скрыт или не активен")
                  << Color::RESET;
    }

    std::cout << Color::CYAN
              << "╚════════════════════════════════════════════════╝\n"
              << Color::RESET;
}