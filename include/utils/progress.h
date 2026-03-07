#pragma once
#include <string>
#include <vector>
#include "core/scanner.h"

// Печатает красивую таблицу результатов
void print_table(const std::vector<PortResult>& results);
void print_summary(const std::string& target, const std::string& os, 
                   int open_ports, int total_sec);