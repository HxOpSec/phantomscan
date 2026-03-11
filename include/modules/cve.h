#pragma once
#include <string>
#include <vector>

struct CVEEntry {
    std::string id;
    std::string severity;
    double      cvss;
    std::string description;
};

class CVEScanner {
public:
    CVEScanner();
    std::vector<CVEEntry> search(const std::string& service);
    void print_results(const std::string& service,
                       const std::vector<CVEEntry>& entries);
    int  get_risk_score(const std::vector<CVEEntry>& entries);

private:
    const std::string cve_file = "data/cve.json";
    std::vector<CVEEntry> parse(const std::string& json,
                                const std::string& service);
};
