#pragma once
#include <string>

struct SSLInfo {
    std::string subject;
    std::string issuer;
    std::string valid_from;
    std::string valid_to;
    std::string protocol;
    std::string cipher;
    bool expired;
    bool self_signed;
};

class SSLScanner {
public:
    SSLInfo scan(const std::string& target, int port = 443);
    void print_results(const SSLInfo& info);
};