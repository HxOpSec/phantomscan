#pragma once
#include <string>

class Menu {
public:
    void run();

private:
    std::string target;
    std::string original_target;
    bool get_target();
    
    void full_scan();
    void quick_scan();
    void subdomain_scan();
    void packet_monitor();
    void show_help();
};