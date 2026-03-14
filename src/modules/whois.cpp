#include <vector>
#include "modules/whois.h"
#include "utils/colors.h"
#include <iostream>
#include <cstdio>
#include <memory>
#include <string>
#include <array>

// FIX: lambda вместо &pclose
static std::string exec_cmd(const std::string& cmd) {
    std::array<char, 512> buffer;
    std::string result;
    auto closer = [](FILE* f) { if (f) pclose(f); };
    std::unique_ptr<FILE, decltype(closer)> pipe(popen(cmd.c_str(), "r"), closer);
    if (!pipe) return "";
    while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        result += buffer.data();
    return result;
}

// ── Парсим одно поле из JSON ──────────────────────────
static std::string parse_json_field(const std::string& json,
                                     const std::string& key) {
    // Ищем "key":"value"
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

// ── WHOIS через ip-api.com (JSON формат) ─────────────
WhoisResult Whois::lookup(const std::string& target) {
    WhoisResult result;
    result.ip = target;

    // JSON формат — надёжнее чем line (поля всегда на месте)
    std::string cmd = "curl -s --max-time 5 "
                      "'http://ip-api.com/json/" + target +
                      "?fields=country,regionName,city,org,isp,as,timezone'"
                      " 2>/dev/null";
    std::string output = exec_cmd(cmd);

    if (output.empty() || output.find("fail") != std::string::npos) {
        result.country  = "Приватная сеть (RFC1918)";
        result.region   = "-";
        result.city     = "-";
        result.org      = "-";    
        result.isp      = "-";
        result.as       = "-";
        result.timezone = "-";
        return result;
    }

    // Парсим каждое поле по ключу — не зависит от порядка строк
    result.country  = parse_json_field(output, "country");
    result.region   = parse_json_field(output, "regionName");
    result.city     = parse_json_field(output, "city");
    result.org      = parse_json_field(output, "org");
    result.isp      = parse_json_field(output, "isp");
    result.as       = parse_json_field(output, "as");
    result.timezone = parse_json_field(output, "timezone");

    // Заполняем пустые поля
    if (result.country.empty())  result.country  = "Неизвестно";
    if (result.region.empty())   result.region   = "Неизвестно";
    if (result.city.empty())     result.city     = "Неизвестно";
    if (result.org.empty())      result.org      = "Неизвестно";
    if (result.isp.empty())      result.isp      = "Неизвестно";
    if (result.as.empty())       result.as       = "Неизвестно";
    if (result.timezone.empty()) result.timezone = "Неизвестно";

    return result;
}