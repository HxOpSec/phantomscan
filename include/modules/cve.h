#pragma once
#include <string>
#include <vector>

struct CVEEntry {
    std::string id;
    std::string severity;
    std::string description;
};

class CVEScanner {
public:
    CVEScanner();

    // Ищем CVE для службы
    std::vector<CVEEntry> search(const std::string& service);

    // Красиво выводим результаты
    void print_results(const std::string& service,
                       const std::vector<CVEEntry>& entries);

private:
    std::string cve_file = "data/cve.json";

    // Простой парсер JSON
    std::vector<CVEEntry> parse(const std::string& json,
                                const std::string& service);
};