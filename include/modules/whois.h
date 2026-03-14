#pragma once
#include <string>

struct WhoisResult {
    std::string ip;
    std::string country;
    std::string region;    // новое поле
    std::string city;
    std::string org;
    std::string isp;
    std::string as;        // новое поле
    std::string timezone;  // новое поле
};

class Whois {
public:
    WhoisResult lookup(const std::string& target);

private:
    std::string fetch(const std::string& url);
};