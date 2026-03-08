#pragma once
#include <string>
#include <vector>

struct WAFResult {
    bool detected;
    std::string name;      // CloudFlare, Akamai, etc
    std::string evidence;  // по какому признаку нашли
};

class WAFDetector {
public:
    WAFResult detect(const std::string& target);
    void print_results(const WAFResult& result);
};