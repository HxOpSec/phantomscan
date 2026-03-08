#pragma once
#include <string>
#include <vector>

struct VulnResult {
    std::string service;
    std::string version;
    std::string cve_id;
    std::string severity;
    std::string description;
};

class VulnScanner {
public:
    std::vector<VulnResult> scan(const std::string& target,
                                  int port_start, int port_end);
    void print_results(const std::vector<VulnResult>& results);
private:
    std::string grab_version(const std::string& target, int port);
    std::string detect_severity(const std::string& version,
                                 const std::string& service);
};