#pragma once
#include <string>
#include <vector>

struct TraceHop {
    int hop;
    std::string ip;
    std::string hostname;
    double rtt_ms;
    bool timeout;
};

class Traceroute {
public:
    std::vector<TraceHop> trace(const std::string& target, 
                                int max_hops = 30);
    void print_results(const std::vector<TraceHop>& hops);
};