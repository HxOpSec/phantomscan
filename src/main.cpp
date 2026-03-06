
#include <iostream>
#include "core/scanner.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Использование: ./builds/phantomscan <IP>" << std::endl;
        std::cout << "Пример: ./builds/phantomscan 127.0.0.1" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::cout << "=== PhantomScan v0.1 ===" << std::endl;
    std::cout << "[*] Цель: " << target << std::endl;
    std::cout << "[*] Сканируем порты 1-1024..." << std::endl;

    Scanner scanner(target);
    auto results = scanner.scan(1, 1024);

    std::cout << "\n[*] Найдено открытых портов: " << results.size() << std::endl;

    return 0;
}
