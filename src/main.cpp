#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include "core/scanner.h"
#include "modules/os_detect.h"
#include "modules/packet_capture.h"
#include "modules/firewall.h"
#include "modules/subdomain.h"
#include "utils/colors.h"
#include "utils/banner.h"

int main(int argc, char* argv[]) {

    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string target = argv[1];

    // Резолвинг домена в IP
    struct hostent* host = gethostbyname(target.c_str());
    if (host) {
        target = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
    }

    std::cout << Color::INFO << "Цель     : " << Color::CYAN << argv[1] << Color::RESET << std::endl;
    std::cout << Color::INFO << "IP адрес : " << Color::CYAN << target << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────────────────────\n";

    // OS Detection
    OSDetector os_detector;
    std::string os = os_detector.detect(target);
    std::cout << Color::INFO << "ОС цели  : " << Color::YELLOW << os << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────────────────────\n";

    // Сканер портов
    std::cout << Color::INFO << "Сканируем порты 1-1024..." << Color::RESET << std::endl;
    Scanner scanner(target);
    auto results = scanner.scan(1, 1024);
    std::cout << Color::INFO << "Найдено открытых портов: "
              << Color::GREEN << results.size() << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────────────────────\n";

    // Firewall Detection
    std::cout << Color::INFO << "Проверяем фаервол..." << Color::RESET << std::endl;
    FirewallDetector fw_detector;
    FirewallResult fw_result = fw_detector.detect(target);
    if (fw_result.detected) {
        std::cout << Color::WARN << fw_result.status << Color::RESET << std::endl;
    } else {
        std::cout << Color::OK << fw_result.status << Color::RESET << std::endl;
    }
    std::cout << "──────────────────────────────────────────────────────────\n";

    // Subdomain
    std::cout << Color::INFO << "Ищем поддомены..." << Color::RESET << std::endl;
    SubdomainEnum subdomain;
    auto subdomains = subdomain.enumerate(argv[1]);
    std::cout << Color::INFO << "Найдено поддоменов: "
              << Color::GREEN << subdomains.size() << Color::RESET << std::endl;
    std::cout << "──────────────────────────────────────────────────────────\n";

    // Packet Capture
    std::cout << Color::INFO << "Захват пакетов..." << Color::RESET << std::endl;
    PacketCapture capture("lo");
    capture.start(10);

    return 0;
}