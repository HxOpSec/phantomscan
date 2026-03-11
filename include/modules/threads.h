#pragma once
#include <string>
#include <vector>
#include <mutex>
#include "core/scanner.h"

class ThreadScanner {
public:
    ThreadScanner(const std::string& target_ip, int num_threads = 50);

    // Сканируем с потоками
    std::vector<PortResult> scan(int start_port, int end_port);

private:
    std::string target_ip;
    int num_threads;
    std::mutex results_mutex;  // Защита от конфликтов потоков

    // Функция одного потока
    void scan_range(int start, int end, std::vector<PortResult>& results);
};