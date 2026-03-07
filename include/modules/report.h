#pragma once
#include <string>
#include <vector>
#include "core/scanner.h"
#include "modules/whois.h"
#include "modules/cve.h"

struct ScanReport {
    std::string target;
    std::string ip;
    std::string os;
    std::string country;
    std::string city;
    std::string isp;
    bool firewall_detected;
    std::vector<PortResult> ports;
    std::vector<std::string> subdomains;
    int scan_time;
};

class Reporter {
public:
    // Сохранить в TXT
    void save_txt(const ScanReport& report);

    // Сохранить в JSON
    void save_json(const ScanReport& report);

    // Сохранить в HTML
    void save_html(const ScanReport& report);

private:
    std::string get_filename(const std::string& target, const std::string& ext);
};