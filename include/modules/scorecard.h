#pragma once
#include <string>
#include <vector>

// ─── Legacy structs (backward compatibility) ──────────────────────────────
struct ScanResult {
    std::vector<int>         open_ports;
    std::vector<std::string> services;
    std::vector<std::string> cve_severities;
    bool has_ssl           = false;
    bool ssl_valid         = false;
    bool ssl_expired       = false;
    bool waf_detected      = false;
    bool firewall_detected = false;
    bool has_telnet        = false;
    bool has_ftp           = false;
    bool has_rdp           = false;
    int  open_port_count   = 0;
};

struct ScoreCard {
    int  total            = 0;
    int  cve_penalty      = 0;
    int  ports_penalty    = 0;
    int  ssl_penalty      = 0;
    int  services_penalty = 0;
    std::string grade;
    std::string verdict;
};

// ─── Professional analyzer structures ────────────────────────────────────
struct CVEFinding {
    std::string id;
    double      cvss    = 0.0;
    std::string desc;
    int         penalty = 0;
};

struct DNSAnalysis {
    bool has_spf      = false;
    bool spf_softfail = false;   // ~all (weak)
    bool spf_plusall  = false;   // +all (dangerous)
    bool has_dmarc    = false;
    bool dmarc_none   = false;   // p=none
    bool has_dnssec   = false;
    bool has_caa      = false;
    bool has_dkim     = false;   // default._domainkey TXT
    bool has_mx       = false;   // MX record
    int  penalty      = 0;
};

// ─── WHOIS analysis ───────────────────────────────────────────────────────
struct WhoisAnalysis {
    int         domain_age_days    = -1;   // -1 = unknown
    int         days_until_expiry  = -1;   // -1 = unknown
    std::string registrar;
    std::string country;
    int         penalty            = 0;
};

struct TLSAnalysis {
    bool tls10        = false;
    bool tls11        = false;
    bool tls12        = false;
    bool tls13        = false;
    int  days_left    = -1;    // -1 = no HTTPS / unknown
    bool self_signed  = false;
    bool weak_ciphers = false;
    bool has_https    = false;  // port 443 is reachable
    int  penalty      = 0;
};

struct HTTPAnalysis {
    bool x_frame_options        = false;
    bool x_content_type_options = false;
    bool csp                    = false;
    bool referrer_policy        = false;
    bool server_version_exposed = false;
    bool has_hsts               = false;
    int  penalty                = 0;   // excl. HSTS (counted in TLS)
};

struct PortsAnalysis {
    bool port_21   = false;   // FTP
    bool port_23   = false;   // Telnet
    bool port_25   = false;   // SMTP
    bool port_139  = false;   // NetBIOS
    bool port_445  = false;   // SMB
    bool port_3389 = false;   // RDP
    int  extra_count = 0;     // additional non-standard open ports
    std::vector<int> open_list;
    int  penalty = 0;
};

// ─── Scorecard class ──────────────────────────────────────────────────────
class Scorecard {
public:
    // Legacy API (backward compatibility)
    ScoreCard calculate(const ScanResult& result);
    void      print(const ScoreCard& sc, const std::string& target);

    // New: full self-contained professional Security Analyzer
    void run(const std::string& target);

private:
    DNSAnalysis             check_dns(const std::string& domain);
    TLSAnalysis             check_tls(const std::string& host);
    HTTPAnalysis            check_http(const std::string& host);
    PortsAnalysis           check_ports(const std::string& host);
    std::vector<CVEFinding> check_cve(const PortsAnalysis& ports);
    bool                    check_firewall(const std::string& host);
    WhoisAnalysis           check_whois(const std::string& domain);
};
