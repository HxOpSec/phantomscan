#pragma once
#include <string>
#include <vector>

struct SYNResult {
    int port;
    std::string service;
    std::string state; // OPEN / CLOSED / FILTERED
};

class SYNScanner {
public:
    std::vector<SYNResult> scan(const std::string& target,
                                 int port_start, int port_end);
    void print_results(const std::vector<SYNResult>& results);
};