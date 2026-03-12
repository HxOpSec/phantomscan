#pragma once
#include <string>
#include <vector>

struct DNSRecord {
    std::string type;    // A, MX, TXT, NS, CNAME, AAAA, SOA
    std::string value;
    int         priority; // для MX
};

struct DNSResult {
    std::string              target;
    std::vector<DNSRecord>   records;
    std::vector<std::string> zone_transfer; // AXFR результаты
    bool                     axfr_success = false;
};

class DNSEnum {
public:
    DNSResult enumerate(const std::string& domain);
    void      print_results(const DNSResult& result);

private:
    std::vector<DNSRecord> query(const std::string& domain,
                                  const std::string& type);
    std::vector<std::string> try_zone_transfer(const std::string& domain,
                                                const std::string& ns);
};