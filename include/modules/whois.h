#pragma once
#include <string>

struct WhoisResult {
    std::string ip;
    std::string country;
    std::string org;
    std::string isp;
    std::string city;
};

class Whois {
public:
    WhoisResult lookup(const std::string& target);

private:
    std::string fetch(const std::string& url);
};