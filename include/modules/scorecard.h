#pragma once
#include <string>
#include <vector>

struct ScanResult {
    std::vector<int>         open_ports;
    std::vector<std::string> services;
    std::vector<std::string> cve_severities;
    bool has_ssl           = false;
    bool ssl_valid         = false;
    bool ssl_expired       = false;
    bool waf_detected      = false;
    bool firewall_detected = false;
    bool has_telnet        = false;
    bool has_ftp           = false;
    bool has_rdp           = false;
    int  open_port_count   = 0;
};

struct ScoreCard {
    int  total;
    int  cve_penalty;
    int  ports_penalty;
    int  ssl_penalty;
    int  services_penalty;
    std::string grade;
    std::string verdict;
};

class Scorecard {
public:
    ScoreCard calculate(const ScanResult& result);
    void      print(const ScoreCard& sc, const std::string& target);
};
