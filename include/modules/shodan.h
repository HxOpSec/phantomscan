#pragma once
#include <string>
#include <vector>

struct ShodanResult {
    std::string ip;
    std::string org;
    std::string country;
    std::string os;
    std::vector<int> ports;
    std::vector<std::string> vulns;
};

class ShodanAPI {
public:
    void set_api_key(const std::string& key);
    ShodanResult lookup(const std::string& ip);
    void print_results(const ShodanResult& result);
private:
    std::string api_key;
    std::string fetch(const std::string& url);
};