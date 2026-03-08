#pragma once
#include <string>

class Menu {
public:
    void run();
    void run_cli(const std::string& t, int p_start, int p_end, 
                 const std::string& output);

private:
    std::string target;
    std::string original_target;
    bool get_target();
    
    void full_scan();
    void quick_scan();
    void subdomain_scan();
    void packet_monitor();
    void show_help();
    void arp_scan();
    void traceroute_scan();
    void syn_scan();        
    void ssl_scan();        
    void waf_detect();
    void vuln_scan();       
    void wordlist_scan();   
    void shodan_lookup();
    void exploit_search();   
    void topology_scan();
    void udp_scan();          // ← новое
        
};