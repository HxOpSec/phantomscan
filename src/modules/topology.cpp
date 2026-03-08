#include "modules/topology.h"
#include "utils/colors.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

void NetworkTopology::build(const std::vector<TopoNode>& nodes,
                             const std::string& target) {
    print_ascii(nodes, target);
    save_to_file(nodes, target);
}

void NetworkTopology::print_ascii(const std::vector<TopoNode>& nodes,
                                   const std::string& target) {
    if (nodes.empty()) {
        std::cout << Color::FAIL << "Нет данных для топологии!"
                  << Color::RESET << std::endl;
        return;
    }

    std::cout << "\n";
    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────────────────────┐\n";
    std::cout << "│                  ТОПОЛОГИЯ СЕТИ                        │\n";
    std::cout << "└─────────────────────────────────────────────────────────┘\n";
    std::cout << Color::RESET << "\n";

    // Источник — наша машина
    std::cout << Color::GREEN;
    std::cout << "  ┌─────────────────────┐\n";
    std::cout << "  │      YOU (src)      │\n";
    std::cout << "  └─────────┬───────────┘\n";
    std::cout << Color::RESET;

    for (size_t i = 0; i < nodes.size(); i++) {
        const auto& n = nodes[i];

        // Соединительная линия
        if (n.timeout) {
            std::cout << Color::WARN;
            std::cout << "            │\n";
            std::cout << "            │ ??? ms\n";
            std::cout << "  ┌─────────┴───────────────────────┐\n";
            std::cout << "  │  HOP " << std::setw(2) << n.hop
                      << "  * * * (timeout)          │\n";
            std::cout << "  └─────────┬───────────────────────┘\n";
            std::cout << Color::RESET;
        } else {
            // Цвет по задержке
            if (n.rtt_ms < 50)
                std::cout << Color::GREEN;
            else if (n.rtt_ms < 150)
                std::cout << Color::WARN;
            else
                std::cout << Color::FAIL;

            std::cout << "            │\n";
            std::cout << "            │ " << std::fixed
                      << std::setprecision(1)
                      << n.rtt_ms << " ms\n";

            // Последний узел — цель
            if (i == nodes.size() - 1) {
                std::cout << Color::CYAN;
                std::cout << "  ┌─────────┴───────────────────────┐\n";
                std::cout << "  │  🎯 TARGET: ";
                std::string ip = n.ip;
                while (ip.size() < 22) ip += " ";
                std::cout << ip << "│\n";

                // Hostname если есть
                if (n.hostname != n.ip && !n.hostname.empty()) {
                    std::string hn = n.hostname;
                    if (hn.size() > 22) hn = hn.substr(0, 19) + "...";
                    while (hn.size() < 22) hn += " ";
                    std::cout << "  │  HOST: " << hn
                              << "     │\n";
                }
                std::cout << "  └─────────────────────────────────┘\n";
            } else {
                std::cout << "  ┌─────────┴───────────────────────┐\n";
                std::cout << "  │  HOP " << std::setw(2) << n.hop
                          << "  ";
                std::string ip = n.ip;
                if (ip.size() > 22) ip = ip.substr(0, 19) + "...";
                while (ip.size() < 22) ip += " ";
                std::cout << ip << "│\n";

                // Hostname если отличается от IP
                if (n.hostname != n.ip && !n.hostname.empty()) {
                    std::string hn = n.hostname;
                    if (hn.size() > 26) hn = hn.substr(0, 23) + "...";
                    while (hn.size() < 26) hn += " ";
                    std::cout << "  │        " << hn << "│\n";
                }
                std::cout << "  └─────────┬───────────────────────┘\n";
            }
            std::cout << Color::RESET;
        }
    }

    // Итог
    std::cout << "\n";
    int timeouts = 0;
    double total_rtt = 0;
    for (const auto& n : nodes) {
        if (n.timeout) timeouts++;
        else total_rtt = n.rtt_ms; // последний RTT
    }

    std::cout << Color::CYAN;
    std::cout << "┌─────────────────────────────────────────────────────────┐\n";
    std::cout << "│ Хопов: " << std::setw(3) << nodes.size()
              << "  │  Таймаутов: " << std::setw(3) << timeouts
              << "  │  Итоговый RTT: "
              << std::fixed << std::setprecision(1)
              << total_rtt << " ms";

    // Дополняем пробелами
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << total_rtt;
    int pad = 8 - (int)oss.str().size();
    for (int i = 0; i < pad; i++) std::cout << " ";
    std::cout << " │\n";
    std::cout << "└─────────────────────────────────────────────────────────┘\n";
    std::cout << Color::RESET << "\n";
}

void NetworkTopology::save_to_file(
        const std::vector<TopoNode>& nodes,
        const std::string& target) {

    std::string filename = "reports/" + target + "_topology.txt";
    std::ofstream f(filename);
    if (!f.is_open()) return;

    f << "PhantomScan — Топология сети\n";
    f << "Цель: " << target << "\n";
    f << "================================\n\n";
    f << "YOU (source)\n";

    for (const auto& n : nodes) {
        f << "  |\n";
        if (n.timeout) {
            f << "  HOP " << n.hop << " — * * * (timeout)\n";
        } else {
            f << "  HOP " << n.hop << " — " << n.ip;
            if (n.hostname != n.ip)
                f << " (" << n.hostname << ")";
            f << " — " << std::fixed << std::setprecision(1)
              << n.rtt_ms << " ms\n";
        }
    }

    f << "\n================================\n";
    f << "Всего хопов: " << nodes.size() << "\n";
    f.close();

    std::cout << Color::OK << "Топология сохранена: "
              << Color::CYAN << filename
              << Color::RESET << std::endl;
}