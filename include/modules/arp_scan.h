#pragma once
#include <string>
#include <vector>

struct ARPHost {
    std::string ip;
    std::string mac;
    std::string hostname;
};

class ARPScanner {
public:
    std::vector<ARPHost> scan(const std::string& subnet);
    void print_results(const std::vector<ARPHost>& hosts);
};