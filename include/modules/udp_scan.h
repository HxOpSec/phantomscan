#pragma once
#include <string>
#include <vector>

struct UDPResult {
    int port;
    std::string service;
    std::string state; // OPEN | OPEN|FILTERED | CLOSED
};

class UDPScanner {
public:
    std::vector<UDPResult> scan(const std::string& target,
                                 int port_start, int port_end);
    void print_results(const std::vector<UDPResult>& results);
};