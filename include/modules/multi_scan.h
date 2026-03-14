#pragma once
#include <string>
#include <vector>
#include "modules/threads.h"
#include "modules/cve.h"

struct TargetResult {
    std::string target;
    std::string ip;
    std::string os;
    int         open_ports   = 0;
    int         cve_count    = 0;
    bool        firewall     = false;
    bool        done         = false;
    bool        error        = false;
    std::string error_msg;
};

class MultiScanner {
public:
    // Скан из файла (каждая строка = цель)
    std::vector<TargetResult> scan_from_file(const std::string& filename,
                                              int p_start = 1,
                                              int p_end   = 1024);

    // Скан из вектора строк
    std::vector<TargetResult> scan_targets(const std::vector<std::string>& targets,
                                            int p_start = 1,
                                            int p_end   = 1024);

    void print_results(const std::vector<TargetResult>& results);

private:
    TargetResult scan_one(const std::string& target,
                           int p_start, int p_end);
};