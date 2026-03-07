#pragma once
#include <string>
#include <map>

class ServiceDetector {
public:
    ServiceDetector();

    // Определяет службу и версию
    std::string detect(const std::string& ip, int port);

    // Только версию
    std::string get_version(const std::string& ip, int port);

private:
    std::map<int, std::string> port_table;
    std::string grab_banner(const std::string& ip, int port);
    std::string parse_version(const std::string& banner, const std::string& service);
    void load_port_table();
};