#pragma once
#include <string>
#include <vector>

struct HTTPPath {
    std::string path;
    int         status_code;
    std::string risk;       // CRITICAL / HIGH / MEDIUM / INFO
    std::string desc;
};

class HTTPScanner {
public:
    std::vector<HTTPPath> scan(const std::string& target, int port = 80);
    void print_results(const std::vector<HTTPPath>& results);

private:
    int  check_path(const std::string& host, int port, const std::string& path);
    bool try_https = false;
};