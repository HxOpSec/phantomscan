#pragma once
#include <string>
#include <vector>

struct TopoNode {
    int hop;
    std::string ip;
    std::string hostname;
    double rtt_ms;
    bool timeout;
};

class NetworkTopology {
public:
    void build(const std::vector<TopoNode>& nodes,
               const std::string& target);
    void print_ascii(const std::vector<TopoNode>& nodes,
                     const std::string& target);
    void save_to_file(const std::vector<TopoNode>& nodes,
                      const std::string& target);
};