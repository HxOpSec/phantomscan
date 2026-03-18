// ─────────────────────────────────────────────────────────────────────────────
//  scorecard.cpp  —  Professional Security Analyzer
//  Parallel checks via std::async, total ≤ 15s
// ─────────────────────────────────────────────────────────────────────────────

#include "modules/scorecard.h"
#include "modules/cve.h"
#include "utils/colors.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <future>
#include <chrono>
#include <cstring>
#include <ctime>
#include <cctype>
#include <set>
#include <regex>
#include <map>

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

static const int BOX_INNER = 62;
static const std::string BOX_TOP = "╔══════════════════════════════════════════════════════════════╗";
static const std::string BOX_SEP = "╠══════════════════════════════════════════════════════════════╣";
static const std::string BOX_BOT = "╚══════════════════════════════════════════════════════════════╝";

// Count visible chars, stripping ANSI codes, counting UTF-8 codepoints
static int display_len(const std::string& s) {
    int len = 0; bool esc = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\033') { esc = true; continue; }
        if (esc) { if (s[i] == 'm') esc = false; continue; }
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) len++;
    }
    return len;
}

static std::string box_row(const std::string& content) {
    int pad = BOX_INNER - display_len(content);
    if (pad < 0) pad = 0;
    return "║" + content + std::string(static_cast<size_t>(pad), ' ') + "║";
}

static std::string safe_truncate(const std::string& s, int max_vis) {
    if (display_len(s) <= max_vis) return s;
    std::string r; int len = 0;
    for (size_t i = 0; i < s.size(); ) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        int b = (c < 0x80) ? 1 : (c < 0xE0) ? 2 : (c < 0xF0) ? 3 : 4;
        if (len + 1 > max_vis - 3) break;
        r += s.substr(i, static_cast<size_t>(b)); len++; i += static_cast<size_t>(b);
    }
    return r + "...";
}

static void brow(const std::string& text, int clen = -1) {
    std::string txt = text;
    int dlen = (clen >= 0) ? clen : display_len(txt);
    if (dlen > BOX_INNER - 2) {
        while (dlen > BOX_INNER - 5 && !txt.empty()) { txt.pop_back(); dlen = display_len(txt); }
        txt += "..."; dlen = display_len(txt);
    }
    int pad = BOX_INNER - 2 - dlen;
    if (pad < 0) pad = 0;
    std::cout << box_row("  " + txt + std::string(static_cast<size_t>(pad), ' ')) << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string run_cmd(const std::string& cmd) {
    FILE* p = popen(cmd.c_str(), "r"); if (!p) return "";
    char buf[4096]; std::string out;
    while (fgets(buf, static_cast<int>(sizeof(buf)), p)) out += buf;
    pclose(p); return out;
}

static bool tcp_connect(const std::string& host, int port_num, int timeout_sec) {
    struct addrinfo hints{}, *ai = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    std::string svc = std::to_string(port_num);
    if (getaddrinfo(host.c_str(), svc.c_str(), &hints, &ai) != 0 || !ai) return false;
    int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) { freeaddrinfo(ai); return false; }
    int fl = fcntl(sock, F_GETFL, 0);
    if (fl >= 0) fcntl(sock, F_SETFL, fl | O_NONBLOCK);
    connect(sock, ai->ai_addr, ai->ai_addrlen); freeaddrinfo(ai);
    fd_set wset; FD_ZERO(&wset); FD_SET(sock, &wset);
    struct timeval tv; tv.tv_sec = static_cast<long>(timeout_sec); tv.tv_usec = 0;
    bool ok = false;
    if (select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
        int err = 0; socklen_t len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0) ok = (err == 0);
    }
    close(sock); return ok;
}

static std::string port_to_service(int port) {
    switch (port) {
        case 21: return "FTP";   case 22: return "SSH";    case 23: return "Telnet";
        case 25: return "SMTP";  case 53: return "DNS";    case 80: return "HTTP";
        case 110: return "POP3"; case 143: return "IMAP";  case 443: return "HTTPS";
        case 445: return "SMB";  case 3306: return "MySQL"; case 3389: return "RDP";
        case 5432: return "PostgreSQL"; case 5900: return "VNC";
        case 6379: return "Redis"; case 8080: return "Tomcat";
        case 8443: return "HTTPS"; case 27017: return "MongoDB";
        default: return "";
    }
}

static std::string to_lower(const std::string& s) {
    std::string o = s;
    for (char& c : o) c = std::tolower(static_cast<unsigned char>(c));
    return o;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

static std::string safe_filename(const std::string& s) {
    std::string o = s;
    for (char& c : o) if (c=='.'||c=='/'||c=='\\'||c==':') c = '_';
    return o;
}

static std::string format_port_token(const PortsAnalysis::ServiceBanner& sb) {
    if (sb.product.empty()) {
        if (sb.version_known && !sb.version.empty()) return sb.service + "-" + sb.version;
        return sb.service.empty() ? "port" : sb.service;
    }
    std::string sl = to_lower(sb.service);
    std::string ver = (sb.version_known && !sb.version.empty()) ? "/" + sb.version : "";
    if (sl=="http"||sl=="https"||sl=="tomcat") return sb.product + ver;
    if (sl=="ssh" && to_lower(sb.product)=="openssh")
        return "SSH-OpenSSH" + (sb.version_known && !sb.version.empty() ? "_"+sb.version : "");
    return sb.service + "-" + sb.product + ver;
}

static bool should_replace_banner(const PortsAnalysis::ServiceBanner& cur,
                                  const PortsAnalysis::ServiceBanner& cand) {
    if (cur.service.empty()) return true;
    if (cand.version_known && !cur.version_known) return true;
    if (cur.banner.empty() && !cand.banner.empty()) return true;
    return false;
}

static std::string grab_banner_raw(const std::string& host, int port, const std::string& svc) {
    static const std::regex host_re(
        R"(^([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*)$|^(\[?[A-Fa-f0-9:]+\]?)$)");
    if (!std::regex_match(host, host_re)) return "";
    if (host.find_first_of("'\"`$") != std::string::npos) return "";
    std::string r;
    if (port==22||svc=="SSH")
        r = run_cmd("echo '' | timeout 3 nc -w 2 " + host + " 22 2>/dev/null");
    else if (port==21||svc=="FTP")
        r = run_cmd("echo '' | timeout 3 nc -w 2 " + host + " 21 2>/dev/null");
    else if (port==25||svc=="SMTP")
        r = run_cmd("echo '' | timeout 3 nc -w 2 " + host + " 25 2>/dev/null");
    else if (port==80||port==8080||svc=="HTTP"||svc=="Tomcat") {
        r = run_cmd("curl -sI --max-time 4 http://" + host + " 2>/dev/null");
        if (r.empty()) r = run_cmd("curl -sI --max-time 4 http://www." + host + " 2>/dev/null");
    } else if (port==443||port==8443||svc=="HTTPS") {
        r = run_cmd("curl -sI --max-time 4 https://" + host + " 2>/dev/null");
        if (r.find("Server:")==std::string::npos && r.find("server:")==std::string::npos) {
            std::string r2 = run_cmd("curl -sI --max-time 4 https://www." + host + " 2>/dev/null");
            if (!r2.empty()) r = r2;
        }
    }
    return trim(r);
}

static void parse_banner(PortsAnalysis::ServiceBanner& sb) {
    if (sb.banner.empty()) return;
    if (sb.service == "SSH") {
        std::regex re("openssh[_-]?([0-9]+(?:\\.[0-9]+)*)", std::regex::icase);
        std::smatch m;
        if (std::regex_search(sb.banner, m, re) && m.size() >= 2) {
            sb.product="OpenSSH"; sb.version=m.str(1); sb.version_known=true; return;
        }
    }
    if (sb.service=="HTTP"||sb.service=="HTTPS"||sb.service=="Tomcat") {
        std::istringstream ss(sb.banner); std::string line;
        while (std::getline(ss, line)) {
            if (to_lower(line).rfind("server:", 0) == 0) {
                std::regex re("server:\\s*([A-Za-z0-9_.-]+)[/ ]?([0-9]+(?:\\.[0-9A-Za-z_-]+)*)?",
                              std::regex::icase);
                std::smatch m;
                if (std::regex_search(line, m, re) && m.size() >= 2) {
                    sb.product = m.str(1);
                    std::string ver = (m.size() >= 3) ? m.str(2) : "";
                    if (!ver.empty()) { sb.version=ver; sb.version_known=true; }
                    else { sb.version.clear(); sb.version_known=false; }
                    return;
                }
            }
        }
    }
    if (sb.service=="FTP"||sb.service=="SMTP") {
        std::regex re("^\\s*\\d{3}\\s+([A-Za-z0-9_.-]+)[ /]?([A-Za-z0-9_.-]+)?",
                      std::regex::icase);
        std::smatch m;
        if (std::regex_search(sb.banner, m, re) && m.size() >= 2) {
            sb.product = m.str(1);
            std::string ver = (m.size() >= 3) ? m.str(2) : "";
            if (!ver.empty()) { sb.version=ver; sb.version_known=true; }
        }
    }
}

// Known servers that are NOT Apache — show 0 Apache CVEs for these
static bool is_non_apache(const std::string& product) {
    static const std::set<std::string> known = {
        "nginx","gws","cloudflare","openresty","lighttpd","iis",
        "microsoft-iis","litespeed","caddy","gunicorn","envoy","tengine"
    };
    return known.count(to_lower(product)) > 0;
}

static bool cve_recent(const std::string& id) {
    std::regex re("CVE-(\\d{4})-"); std::smatch m;
    if (std::regex_search(id, m, re) && m.size() >= 2) {
        try { return std::stoi(m.str(1)) >= 2015; } catch (...) {}
    }
    return false;
}

static std::pair<int,int> cve_id_order(const std::string& id) {
    std::regex re("CVE-(\\d{4})-(\\d+)"); std::smatch m;
    if (std::regex_search(id, m, re) && m.size() >= 3) {
        try { return {std::stoi(m.str(1)), std::stoi(m.str(2))}; } catch (...) {}
    }
    return {0, 0};
}

static bool cve_matches_version(const CVEEntry& e, const PortsAnalysis::ServiceBanner& sb) {
    if (!sb.version_known || sb.version.empty()) return true;
    std::string dl = to_lower(e.description + " " + e.id);
    std::string pl = to_lower(sb.product.empty() ? sb.service : sb.product);
    if (!pl.empty() && dl.find(pl) == std::string::npos) return false;
    std::string ver = sb.version; size_t dot = ver.find('.');
    std::string major = (dot == std::string::npos) ? ver : ver.substr(0, dot);
    if (!major.empty()) {
        size_t pp = dl.find(pl);
        if (pp != std::string::npos) {
            size_t dp = dl.find_first_of("0123456789", pp);
            if (dp != std::string::npos && dp - pp < 10) {
                std::string found;
                while (dp < dl.size()) {
                    unsigned char u = static_cast<unsigned char>(dl[dp]);
                    if (!(std::isdigit(u)||u==static_cast<unsigned char>('.'))) break;
                    found.push_back(static_cast<char>(u)); dp++;
                }
                if (!found.empty()) {
                    size_t fd = found.find('.');
                    return (fd==std::string::npos?found:found.substr(0,fd)) == major;
                }
            }
        }
    }
    return true;
}

static std::pair<std::string,std::string> score_grade(int s) {
    if (s>=90) return {"A+","Отличная защита"};
    if (s>=80) return {"A", "Хорошая защита"};
    if (s>=70) return {"B", "Удовлетворительно"};
    if (s>=60) return {"C", "Есть проблемы"};
    if (s>=50) return {"D", "Серьёзные проблемы"};
    return            {"F", "Критически опасно"};
}

static std::string score_bar(int score) {
    int f = score * 32 / 100; std::string bar;
    for (int i = 0; i < 32; i++) bar += (i < f ? "█" : "░");
    return bar;
}

static std::string score_color(int score) {
    if (score>=90) return "\033[32m";
    if (score>=70) return "\033[33m";
    if (score>=50) return "\033[38;5;208m";
    return "\033[31m";
}

static void print_progress(int n, const std::string& msg) {
    if (n<0) n=0; if (n>10) n=10;
    std::cout << "\r  \033[36m[";
    for (int i=0;i<10;i++) std::cout << (i<n?"■":"░");
    std::cout << "] \033[0m" << msg << "          " << std::flush;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_dns
// ─────────────────────────────────────────────────────────────────────────────
DNSAnalysis Scorecard::check_dns(const std::string& domain) {
    DNSAnalysis r;
    auto f_spf   = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short TXT " + domain + " 2>/dev/null"); });
    auto f_dmarc = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short TXT _dmarc." + domain + " 2>/dev/null"); });
    auto f_dns   = std::async(std::launch::async, [domain] {
        return run_cmd("dig +dnssec A " + domain + " 2>/dev/null"); });
    auto f_caa   = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short CAA " + domain + " 2>/dev/null"); });
    auto f_mx    = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short MX " + domain + " 2>/dev/null"); });
    // Check 11 DKIM selectors in parallel
    auto f_dkim  = std::async(std::launch::async, [domain] {
        static const std::vector<std::string> sels = {
            "default","google","mail","dkim","k1","s1","s2",
            "selector1","selector2","smtp","email"
        };
        std::vector<std::future<std::string>> futs;
        for (const auto& sel : sels)
            futs.push_back(std::async(std::launch::async, [domain, sel] {
                return run_cmd("dig +short TXT " + sel + "._domainkey." + domain + " 2>/dev/null");
            }));
        for (auto& f : futs) {
            std::string res = f.get();
            if (!res.empty() && res.find("v=DKIM1") != std::string::npos) return std::string("found");
        }
        return std::string("");
    });

    std::string spf=f_spf.get(), dmarc=f_dmarc.get(), dnssec=f_dns.get(),
                caa=f_caa.get(), mx=f_mx.get();

    if (spf.find("v=spf1") != std::string::npos) {
        r.has_spf = true;
        if (spf.find("+all") != std::string::npos) r.spf_plusall = true;
        else if (spf.find("~all") != std::string::npos) r.spf_softfail = true;
    }
    if (dmarc.find("v=DMARC1") != std::string::npos) {
        r.has_dmarc = true;
        if (dmarc.find("p=none") != std::string::npos) r.dmarc_none = true;
    }
    r.has_dnssec = dnssec.find(";; flags:") != std::string::npos &&
                   (dnssec.find(" ad ") != std::string::npos || dnssec.find(" ad;") != std::string::npos);
    r.has_caa  = !caa.empty()  && caa  != "\n" && static_cast<int>(caa.size())  > 1;
    r.has_dkim = (f_dkim.get() == "found");
    r.has_mx   = !mx.empty()   && mx   != "\n" && static_cast<int>(mx.size())   > 1;

    int pen = 0;
    if (!r.has_spf)          pen += 8;
    else if (r.spf_plusall)  pen += 8;
    else if (r.spf_softfail) pen += 4;
    if (!r.has_dmarc)        pen += 7; else if (r.dmarc_none) pen += 4;
    if (!r.has_dnssec) pen += 3; if (!r.has_caa)  pen += 2;
    if (!r.has_dkim)   pen += 3; if (!r.has_mx)   pen += 2;
    r.penalty = std::min(pen, 25);
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_whois
// ─────────────────────────────────────────────────────────────────────────────
static time_t parse_whois_date(const std::string& val) {
    if (val.empty()) return -1;
    struct tm t{};
    if (strptime(val.c_str(), "%Y-%m-%dT%H:%M:%S", &t) || strptime(val.c_str(), "%Y-%m-%d", &t))
        return timegm(&t);
    if (strptime(val.c_str(), "%m/%d/%Y", &t)) return timegm(&t);
    if (strptime(val.c_str(), "%d-%b-%Y", &t)) return timegm(&t);
    if (strptime(val.c_str(), "%a %b %d %H:%M:%S %Z %Y", &t)) return timegm(&t);
    return -1;
}

static std::string whois_field(const std::string& whois, const std::vector<std::string>& keys) {
    std::istringstream ss(whois); std::string line;
    while (std::getline(ss, line)) {
        std::string ll = line;
        for (char& c : ll) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (const auto& key : keys) {
            std::string lk = key;
            for (char& c : lk) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (ll.rfind(lk, 0) == 0) {
                size_t col = line.find(':');
                if (col == std::string::npos) continue;
                std::string val = line.substr(col + 1);
                size_t a = val.find_first_not_of(" \t\r"), b = val.find_last_not_of(" \t\r");
                if (a == std::string::npos) continue;
                return val.substr(a, b - a + 1);
            }
        }
    }
    return "";
}

WhoisAnalysis Scorecard::check_whois(const std::string& domain) {
    WhoisAnalysis r;
    std::string out = run_cmd("whois " + domain + " 2>/dev/null");
    if (out.empty()) return r;

    std::string created = whois_field(out,
        {"creation date:","created on:","created:","registration time:",
         "registered:","domain registered:","commencement date:",
         "registration date:","domain registration date:","reg-date:"});
    std::string expiry = whois_field(out,
        {"registry expiry date:","registrar registration expiration date:",
         "expiration date:","expires:","expire:","paid-till:",
         "expiry date:","validity:","expires on:","expiry:"});
    std::string registrar = whois_field(out,
        {"registrar:","registrar name:","sponsoring registrar:"});
    std::string country = whois_field(out,
        {"registrant country:","country:","registrant: country"});

    time_t now = time(nullptr);
    auto trim_tz = [](const std::string& s) -> std::string {
        if (s.empty()) return s; std::string t = s;
        if (t.back() == 'Z') t.pop_back();
        size_t p = t.rfind('+'); if (p!=std::string::npos && p>10) t=t.substr(0,p);
        return t;
    };
    time_t tc = parse_whois_date(trim_tz(created));
    time_t te = parse_whois_date(trim_tz(expiry));
    if (tc>0 && tc<=now) r.domain_age_days = static_cast<int>((now-tc)/86400);
    if (te>0) r.days_until_expiry = static_cast<int>((te-now)/86400);
    if (!registrar.empty() && registrar.size()>30) registrar = registrar.substr(0,27)+"...";
    r.registrar = registrar;
    if (!country.empty()) {
        size_t sp = country.find(' ');
        r.country = (sp!=std::string::npos) ? country.substr(0,sp) : country;
        if (r.country.size()>20) r.country = r.country.substr(0,20);
    }
    int pen = 0;
    if (r.domain_age_days>=0 && r.domain_age_days<365) pen+=5;
    if (r.days_until_expiry>=0 && r.days_until_expiry<30) pen+=8;
    r.penalty = pen; return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_tls — double-check TLS1.0/1.1 to avoid false positives
// ─────────────────────────────────────────────────────────────────────────────
TLSAnalysis Scorecard::check_tls(const std::string& host) {
    TLSAnalysis r;
    std::string base = "echo | timeout 5 openssl s_client -connect " + host + ":443 ";
    auto f10 = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "-tls1 2>/dev/null");
        return o.find("CONNECTED")!=std::string::npos && o.find("Protocol  : TLSv1")!=std::string::npos;
    });
    auto f11 = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "-tls1_1 2>/dev/null");
        return o.find("CONNECTED")!=std::string::npos && o.find("Protocol  : TLSv1.1")!=std::string::npos;
    });
    auto f12 = std::async(std::launch::async, [base] {
        return run_cmd(base + "-tls1_2 2>/dev/null").find("CONNECTED") != std::string::npos; });
    auto f13 = std::async(std::launch::async, [base] {
        return run_cmd(base + "-tls1_3 2>/dev/null").find("CONNECTED") != std::string::npos; });
    auto f_cert = std::async(std::launch::async, [host] {
        return run_cmd("echo | timeout 5 openssl s_client -connect " + host +
                       ":443 -servername " + host +
                       " 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null"); });
    auto f_ciph = std::async(std::launch::async, [base] {
        return run_cmd(base + "2>/dev/null | grep 'Cipher    '"); });

    r.tls10=f10.get(); r.tls11=f11.get(); r.tls12=f12.get(); r.tls13=f13.get();
    r.has_https = r.tls12 || r.tls13 || r.tls10 || r.tls11;
    if (!r.has_https) r.has_https = tcp_connect(host, 443, 3);

    std::string cert = f_cert.get();
    if (!cert.empty()) {
        auto exf = [&cert](const std::string& key) -> std::string {
            size_t pos = cert.find(key); if (pos==std::string::npos) return "";
            size_t nl = cert.find('\n', pos);
            std::string val = cert.substr(pos+key.size(), nl==std::string::npos?std::string::npos:nl-pos-key.size());
            while (!val.empty()&&(val.back()=='\r'||val.back()==' ')) val.pop_back();
            return val;
        };
        std::string subj=exf("subject="), iss=exf("issuer=");
        r.self_signed = (!subj.empty() && subj==iss);
        std::string na=exf("notAfter=");
        if (!na.empty()) {
            struct tm t{}; if (strptime(na.c_str(),"%b %d %H:%M:%S %Y %Z",&t)!=nullptr)
                r.days_left = static_cast<int>((timegm(&t)-time(nullptr))/86400);
        }
    }
    std::string ciph=f_ciph.get();
    r.weak_ciphers = ciph.find("RC4")!=std::string::npos || ciph.find("DES")!=std::string::npos;
    int pen=0;
    if (r.has_https) {
        if (r.tls10) pen+=10; if (r.tls11) pen+=7; if (!r.tls13) pen+=3;
        if (r.self_signed) pen+=10;
        if (r.days_left>=0&&r.days_left<7) pen+=10;
        else if (r.days_left>=0&&r.days_left<30) pen+=5;
        if (r.weak_ciphers) pen+=8;
    }
    r.penalty=pen; return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_http — no redirect, www fallback for HSTS
// ─────────────────────────────────────────────────────────────────────────────
HTTPAnalysis Scorecard::check_http(const std::string& host) {
    HTTPAnalysis r;
    std::string headers = run_cmd("curl -sI --max-time 5 https://" + host + " 2>/dev/null");
    if (headers.empty())
        headers = run_cmd("curl -sI --max-time 5 http://" + host + " 2>/dev/null");
    auto lh = headers;
    for (char& c : lh) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lh.find("strict-transport-security") == std::string::npos) {
        std::string h2 = run_cmd("curl -sI --max-time 5 https://www." + host + " 2>/dev/null");
        if (!h2.empty()) headers += h2;
    }
    if (headers.empty()) { r.penalty=0; return r; }
    auto has_hdr = [&headers](const std::string& key) {
        std::string lk=key, lh2=headers;
        for (char& c:lk) c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (char& c:lh2) c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return lh2.find(lk)!=std::string::npos;
    };
    r.x_frame_options        = has_hdr("x-frame-options");
    r.x_content_type_options = has_hdr("x-content-type-options");
    r.csp                    = has_hdr("content-security-policy");
    r.referrer_policy        = has_hdr("referrer-policy");
    r.has_hsts               = has_hdr("strict-transport-security");
    size_t sp = headers.find("Server:"); if (sp==std::string::npos) sp=headers.find("server:");
    if (sp!=std::string::npos) {
        size_t nl=headers.find('\n',sp);
        std::string sl=headers.substr(sp,nl==std::string::npos?std::string::npos:nl-sp);
        bool hd=false, as=false;
        for (char c:sl) { if (c=='/'||c==' ') as=true; if (as&&std::isdigit(static_cast<unsigned char>(c))) {hd=true;break;} }
        r.server_version_exposed=hd;
    }
    int pen=0;
    if (!r.x_frame_options)        pen+=2; if (!r.x_content_type_options) pen+=2;
    if (!r.csp)                    pen+=3; if (!r.referrer_policy)        pen+=1;
    if (r.server_version_exposed)  pen+=2;
    r.penalty=std::min(pen,10); return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_ports
// ─────────────────────────────────────────────────────────────────────────────
PortsAnalysis Scorecard::check_ports(const std::string& host) {
    PortsAnalysis r;
    static const std::vector<int> PORTS = {
        21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017};
    static const std::set<int> SAFE={22,80,443,53}, DANGER={21,23,25,445,3389};
    std::vector<std::future<bool>> futs;
    futs.reserve(PORTS.size());
    for (int p:PORTS) futs.push_back(std::async(std::launch::async,[host,p]{return tcp_connect(host,p,3);}));
    for (size_t i=0;i<PORTS.size();i++) {
        if (!futs[i].get()) continue;
        int p=PORTS[i]; r.open_list.push_back(p);
        std::string svc=port_to_service(p);
        if (!svc.empty()) { PortsAnalysis::ServiceBanner sb; sb.port=p; sb.service=svc; r.banners.push_back(sb); }
        if (p==21) r.port_21=true; if (p==23) r.port_23=true; if (p==25) r.port_25=true;
        if (p==139) r.port_139=true; if (p==445) r.port_445=true; if (p==3389) r.port_3389=true;
        if (SAFE.find(p)==SAFE.end()&&DANGER.find(p)==DANGER.end()) r.extra_count++;
    }
    int pen=0;
    if (r.port_23) pen+=15; if (r.port_21) pen+=10; if (r.port_3389) pen+=8;
    if (r.port_445) pen+=8; if (r.port_139) pen+=6; if (r.port_25) pen+=4;
    pen+=r.extra_count*2; r.penalty=std::min(pen,20); return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_cve — strict product filter, HTTPS→HTTP lookup
// ─────────────────────────────────────────────────────────────────────────────
std::vector<CVEFinding> Scorecard::check_cve(const std::string& host, PortsAnalysis& ports) {
    std::vector<CVEFinding> findings;
    CVEScanner cve_db;
    std::map<std::string, PortsAnalysis::ServiceBanner> svc_meta;

    for (size_t i=0;i<ports.banners.size();i++) {
        PortsAnalysis::ServiceBanner filled=ports.banners[i];
        filled.banner=grab_banner_raw(host,filled.port,filled.service);
        parse_banner(filled);
        auto it=svc_meta.find(filled.service);
        if (it==svc_meta.end()||should_replace_banner(it->second,filled)) svc_meta[filled.service]=filled;
        ports.banners[i]=filled;
    }

    std::set<std::string> seen;
    for (int p:ports.open_list) {
        std::string svc=port_to_service(p);
        if (svc.empty()||seen.count(svc)) continue;
        seen.insert(svc);
        std::string lookup=(svc=="HTTPS")?"HTTP":svc;
        auto meta_it=svc_meta.find(svc);
        PortsAnalysis::ServiceBanner meta=(meta_it!=svc_meta.end())?meta_it->second:PortsAnalysis::ServiceBanner{};
        if (meta.service.empty()) { meta.service=svc; meta.port=p; }

        auto entries=cve_db.search(lookup);

        if (!meta.product.empty()) {
            // Known non-Apache server — strict filter by product name
            std::string pl=to_lower(meta.product);
            entries.erase(std::remove_if(entries.begin(),entries.end(),
                [&pl](const CVEEntry& e){return to_lower(e.description).find(pl)==std::string::npos;}),
                entries.end());
        } else if ((svc=="HTTP"||svc=="HTTPS") && meta.banner.empty()) {
            // Banner empty — limit to 3 CVEs to avoid false alarm flood
            std::sort(entries.begin(),entries.end(),[](const CVEEntry& a,const CVEEntry& b){return a.cvss>b.cvss;});
            if (entries.size()>3) entries.resize(3);
        }

        for (auto& e:entries) {
            if (!cve_recent(e.id)) continue;
            if (!cve_matches_version(e,meta)) continue;
            CVEFinding f; f.id=e.id; f.cvss=e.cvss; f.desc=e.description; f.service=svc;
            if (e.cvss>=9.0) f.penalty=15; else if (e.cvss>=7.0) f.penalty=8;
            else if (e.cvss>=4.0) f.penalty=3; else if (e.cvss>0.0) f.penalty=1;
            findings.push_back(std::move(f));
        }
    }
    std::sort(findings.begin(),findings.end(),[](const CVEFinding& a,const CVEFinding& b){
        if (a.cvss==b.cvss) return cve_id_order(a.id)>cve_id_order(b.id);
        return a.cvss>b.cvss;
    });
    if (findings.size()>10) findings.resize(10);
    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_firewall
// ─────────────────────────────────────────────────────────────────────────────
bool Scorecard::check_firewall(const std::string& host) {
    static const int PROBE=31337, TIMEOUT=3;
    struct addrinfo hints{}, *ai=nullptr;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    std::string svc=std::to_string(PROBE);
    if (getaddrinfo(host.c_str(),svc.c_str(),&hints,&ai)!=0||!ai) return false;
    int sock=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
    if (sock<0) { freeaddrinfo(ai); return false; }
    int fl=fcntl(sock,F_GETFL,0); if (fl>=0) fcntl(sock,F_SETFL,fl|O_NONBLOCK);
    auto t0=std::chrono::steady_clock::now();
    connect(sock,ai->ai_addr,ai->ai_addrlen); freeaddrinfo(ai);
    fd_set wset,eset; FD_ZERO(&wset); FD_ZERO(&eset); FD_SET(sock,&wset); FD_SET(sock,&eset);
    struct timeval tv; tv.tv_sec=TIMEOUT; tv.tv_usec=0;
    int sel=select(sock+1,nullptr,&wset,&eset,&tv);
    auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
    close(sock); return (sel==0)||(ms>500);
}

// ─────────────────────────────────────────────────────────────────────────────
//  print_report
// ─────────────────────────────────────────────────────────────────────────────
static void print_report(
    const std::string& target, double elapsed, int score,
    const std::string& grade, const std::string& verdict,
    const std::vector<CVEFinding>& cves, int cve_pen,
    const DNSAnalysis& dns, const TLSAnalysis& tls, int tls_pen,
    const HTTPAnalysis& http, const PortsAnalysis& ports, bool firewall,
    const WhoisAnalysis& whois, bool has_prev, int prev_score)
{
    const std::string R="\033[0m",B="\033[1m",C="\033[36m",G="\033[1;32m",
                      Y="\033[1;33m",RE="\033[1;31m";
    std::string col=score_color(score);
    std::string gc=(grade=="A+"||grade=="A")?G:(grade=="B")?C:(grade=="C")?Y:RE;

    std::cout << "\n" << B << C << BOX_TOP << R << "\n";
    { std::string t="SECURITY SCORECARD — "+target; brow(B+C+t+R,static_cast<int>(t.size())); }
    { std::ostringstream ss; ss<<std::fixed<<std::setprecision(1)<<elapsed;
      brow("Анализ завершён за "+ss.str()+" сек"); }
    std::cout << B<<C<<BOX_SEP<<R<<"\n";

    // Score line
    { std::ostringstream ss; ss<<"SCORE: "<<score<<" / 100    Grade: ";
      std::string pre=ss.str();
      std::string line=col+B+pre+R+gc+B+grade+R+"   "+col+verdict+R;
      brow(line,static_cast<int>(pre.size())+static_cast<int>(grade.size())+3+display_len(verdict)); }
    { brow(col+score_bar(score)+R,32); }

    // History
    { if (has_prev) {
        int diff=score-prev_score; std::ostringstream hs;
        hs<<"История: "<<prev_score<<" pts → "<<score<<" pts  ";
        if (diff>0) hs<<G<<"↑ +"<<diff<<" улучшение"<<R;
        else if (diff<0) hs<<RE<<"↓ "<<diff<<" ухудшение"<<R;
        else hs<<C<<"→ без изменений"<<R;
        int pl=display_len("История: ")+static_cast<int>(std::to_string(prev_score).size())
              +display_len(" pts → ")+static_cast<int>(std::to_string(score).size())+display_len(" pts  ");
        std::string ar=(diff>0)?("↑ +"+std::to_string(diff)+" улучшение"):
                       (diff<0)?("↓ "+std::to_string(diff)+" ухудшение"):"→ без изменений";
        brow(hs.str(),pl+display_len(ar));
      } else brow(C+"Первый скан домена"+R,display_len("Первый скан домена")); }

    // WHOIS
    bool wok=whois.domain_age_days>=0||whois.days_until_expiry>=0||!whois.registrar.empty()||!whois.country.empty();
    if (wok) {
        std::cout<<B<<C<<BOX_SEP<<R<<"\n"; brow(B+"WHOIS"+R,5);
        if (whois.domain_age_days>=0) {
            int yr=whois.domain_age_days/365, mo=(whois.domain_age_days%365)/30;
            std::ostringstream as; as<<"Возраст домена:  ";
            if (yr>0) as<<yr<<" "<<(yr==1?"год":yr<5?"года":"лет")<<" ";
            if (mo>0||yr==0) as<<mo<<" "<<(mo==1?"месяц":mo<5?"месяца":"месяцев");
            std::string at=as.str(); bool aok=whois.domain_age_days>=365;
            std::string st=aok?(G+"OK"+R):(Y+"-5 pts"+R); int sd=aok?2:6;
            int pad=BOX_INNER-2-display_len(at)-sd; if (pad<1) pad=1;
            std::cout<<box_row("  "+at+std::string(static_cast<size_t>(pad),' ')+st)<<"\n";
        }
        if (whois.days_until_expiry>=0) {
            std::ostringstream es; es<<"Истекает через:  "<<whois.days_until_expiry<<" дней";
            std::string et=es.str(); bool eok=whois.days_until_expiry>=30;
            std::string st=eok?(G+"OK"+R):(RE+"-8 pts"+R); int sd=eok?2:6;
            int pad=BOX_INNER-2-display_len(et)-sd; if (pad<1) pad=1;
            std::cout<<box_row("  "+et+std::string(static_cast<size_t>(pad),' ')+st)<<"\n";
        }
        if (!whois.registrar.empty()) brow("Регистратор:     "+whois.registrar);
        if (!whois.country.empty())   brow("Страна:          "+whois.country);
    }

    // CVSS
    std::cout<<B<<C<<BOX_SEP<<R<<"\n"; brow(B+"CVSS ANALYSIS"+R,13);
    if (ports.open_list.empty()) {
        brow("Открытых портов не обнаружено"); brow("CVE штраф: 0 pts");
    } else {
        std::map<int,PortsAnalysis::ServiceBanner> pm;
        for (const auto& b:ports.banners) pm[b.port]=b;
        std::ostringstream pl; pl<<"  Открытые порты: "; bool any_known=false;
        for (size_t i=0;i<ports.open_list.size();i++) {
            int p=ports.open_list[i]; auto it=pm.find(p);
            std::string tok=std::to_string(p)+"(";
            if (it!=pm.end()) { tok+=format_port_token(it->second); if (it->second.version_known&&!it->second.version.empty()) any_known=true; }
            else tok+=(port_to_service(p).empty()?"port":port_to_service(p));
            tok+=")"; pl<<tok; if (i+1<ports.open_list.size()) pl<<", ";
        }
        if (!any_known) pl<<" - версии неизвестны";
        brow(pl.str()); brow("  CVE >= 2015; фильтрация по версиям баннера");
        if (!any_known) { brow("  [?] Захват баннера не дал результата"); brow("  Показаны CVE >= 2015 для найденных сервисов"); }
        if (cves.empty()) {
            brow("  Уязвимостей не найдено",display_len("  Уязвимостей не найдено"));
        } else {
            int crit=0,high=0,med=0; double avg=0.0;
            for (auto& c:cves) { avg+=c.cvss; if (c.cvss>=9.0) crit++; else if (c.cvss>=7.0) high++; else med++; }
            avg/=static_cast<double>(cves.size());
            std::ostringstream ss;
            ss<<"Avg CVSS: "<<std::fixed<<std::setprecision(1)<<avg
              <<"   \u25a0 Critical: "<<crit<<"  \u25a0 High: "<<high<<"  \u25a0 Medium: "<<med;
            brow(ss.str());
            for (auto& c:cves) {
                std::string desc=safe_truncate(c.desc,26);
                std::ostringstream ls;
                ls<<std::left<<std::setw(16)<<c.id<<"CVSS "<<std::fixed<<std::setprecision(1)<<c.cvss
                  <<"  "<<std::setw(26)<<desc<<" -"<<c.penalty<<" pts";
                brow(ls.str());
            }
            std::ostringstream pp; pp<<"Общий штраф CVE: -"<<cve_pen<<" pts";
            brow(RE+B+pp.str()+R,display_len(pp.str()));
        }
    }

    // yn helper
    auto yn=[&](bool ok,const std::string& gt,const std::string& bt,int penalty){
        std::string txt=ok?gt:bt;
        const std::string TK="\u2713",CR="\u2717"; std::string col2=txt; size_t pos;
        if ((pos=col2.find(TK))!=std::string::npos) col2.replace(pos,TK.size(),G+TK+R);
        if ((pos=col2.find(CR))!=std::string::npos) col2.replace(pos,CR.size(),RE+CR+R);
        int tdl=display_len(txt); std::string pts; int pdl=0;
        if (!ok&&penalty>0) { std::ostringstream ps; ps<<"-"<<penalty<<" pts"; pts=Y+ps.str()+R; pdl=static_cast<int>(ps.str().size()); }
        else { pts=G+"OK"+R; pdl=2; }
        int pad=BOX_INNER-2-tdl-pdl; if (pad<1) pad=1;
        std::cout<<box_row("  "+col2+std::string(static_cast<size_t>(pad),' ')+pts)<<"\n";
    };

    // DNS
    std::cout<<B<<C<<BOX_SEP<<R<<"\n"; brow(B+"DNS SECURITY"+R,12);
    { bool spf_ok=dns.has_spf&&!dns.spf_plusall&&!dns.spf_softfail;
      std::string sb=!dns.has_spf?"SPF     \u2717 отсутствует":dns.spf_plusall?"SPF     \u2717 +all ОПАСЕН":"SPF     \u2717 ~all слабый";
      yn(spf_ok,"SPF     \u2713 Настроен",sb,(!dns.has_spf||dns.spf_plusall)?8:4);
      bool dm=dns.has_dmarc&&!dns.dmarc_none;
      std::string db=!dns.has_dmarc?"DMARC   \u2717 отсутствует":"DMARC   \u2717 p=none (слабый)";
      yn(dm,"DMARC   \u2713 Настроен",db,!dns.has_dmarc?7:4);
      yn(dns.has_dnssec,"DNSSEC  \u2713 Включён",  "DNSSEC  \u2717 отключён",    3);
      yn(dns.has_caa,   "CAA     \u2713 Настроен", "CAA     \u2717 отсутствует", 2);
      yn(dns.has_dkim,  "DKIM    \u2713 Настроен", "DKIM    \u2717 отсутствует", 3);
      yn(dns.has_mx,    "MX      \u2713 Настроен", "MX      \u2717 отсутствует", 2); }

    // TLS
    std::cout<<B<<C<<BOX_SEP<<R<<"\n"; brow(B+"SSL/TLS"+R,7);
    if (!tls.has_https) {
        brow(Y+"HTTPS (порт 443) недоступен"+R,display_len("HTTPS (порт 443) недоступен"));
    } else {
        yn(!tls.tls10,"TLS 1.0  \u2713 Отключён",      "TLS 1.0  \u2717 ВКЛЮЧЁН — УСТАРЕЛ",10);
        yn(!tls.tls11,"TLS 1.1  \u2713 Отключён",      "TLS 1.1  \u2717 ВКЛЮЧЁН — УСТАРЕЛ", 7);
        yn(tls.tls12, "TLS 1.2  \u2713 Поддерживается","TLS 1.2  \u2717 Не поддерживается",  0);
        yn(tls.tls13, "TLS 1.3  \u2713 Поддерживается","TLS 1.3  \u2717 Отсутствует",         3);
        if (tls.days_left<0) brow(Y+"Сертификат: не удалось получить"+R,display_len("Сертификат: не удалось получить"));
        else {
            std::ostringstream ss; ss<<"  Сертификат истекает через: "<<tls.days_left<<" дней";
            bool cok=tls.days_left>=30&&!tls.self_signed;
            int cp=tls.self_signed?10:tls.days_left<7?10:tls.days_left<30?5:0;
            yn(cok,ss.str(),ss.str(),cp);
        }
        if (tls.self_signed) brow(RE+"\u2717 Самоподписанный сертификат       -10 pts"+R,display_len("\u2717 Самоподписанный сертификат       -10 pts"));
        if (tls.weak_ciphers) brow(RE+"\u2717 Слабые шифры RC4/DES              -8 pts"+R,display_len("\u2717 Слабые шифры RC4/DES              -8 pts"));
        yn(http.has_hsts,"HSTS     \u2713 Включён","HSTS     \u2717 отсутствует",3);
    }
    { std::ostringstream pp; pp<<"Штраф TLS: -"<<tls_pen<<" pts"; brow(RE+B+pp.str()+R,display_len(pp.str())); }

    // HTTP
    std::cout<<B<<C<<BOX_SEP<<R<<"\n"; brow(B+"HTTP SECURITY HEADERS"+R,21);
    yn(http.x_frame_options,       "X-Frame-Options          \u2713 Настроен","X-Frame-Options          \u2717 отсутствует",2);
    yn(http.x_content_type_options,"X-Content-Type-Options   \u2713 Настроен","X-Content-Type-Options   \u2717 отсутствует",2);
    yn(http.csp,                   "Content-Security-Policy  \u2713 Настроен","Content-Security-Policy  \u2717 отсутствует",3);
    yn(http.referrer_policy,       "Referrer-Policy          \u2713 Настроен","Referrer-Policy          \u2717 отсутствует",1);
    yn(!http.server_version_exposed,"Server версия            \u2713 Скрыта",  "Server версия            \u2717 Раскрыта",   2);

    // Firewall
    std::cout<<B<<C<<BOX_SEP<<R<<"\n"; brow(B+"FIREWALL"+R,8);
    yn(firewall,"Firewall  \u2713 Обнаружен  (+5 pts)","Firewall  \u2717 Не обнаружен  (-5 pts)",5);

    // Recommendations
    std::cout<<B<<C<<BOX_SEP<<R<<"\n";
    brow(B+"РЕКОМЕНДАЦИИ (по приоритету)"+R,display_len("РЕКОМЕНДАЦИИ (по приоритету)"));
    bool any_rec=false;
    auto rec=[&](const std::string& level,const std::string& lc,const std::string& msg){
        std::string br=lc+"["+level+"]\033[0m ";
        brow(br+msg,1+static_cast<int>(level.size())+2+display_len(msg)); any_rec=true;
    };
    for (auto& c:cves) if (c.cvss>=9.0) rec("CRITICAL","\033[1;31m","Устрани "+c.id+" ("+safe_truncate(c.desc,28)+")");
    if (tls.has_https&&tls.tls10) rec("CRITICAL","\033[1;31m","Отключи TLS 1.0: ssl_protocols TLSv1.2 TLSv1.3");
    if (tls.has_https&&tls.tls11) rec("CRITICAL","\033[1;31m","Отключи TLS 1.1: ssl_protocols TLSv1.2 TLSv1.3");
    if (ports.port_23) rec("CRITICAL","\033[1;31m","Отключи Telnet (порт 23) — используй SSH");
    if (!dns.has_spf||dns.spf_plusall) rec("HIGH","\033[1;33m","Добавь SPF: v=spf1 include:_spf.google.com ~all");
    if (!dns.has_dmarc) rec("HIGH","\033[1;33m","Добавь DMARC: v=DMARC1; p=reject; rua=mailto:admin@"+target);
    if (tls.has_https&&tls.self_signed) rec("HIGH","\033[1;33m","Замени самоподписанный сертификат на доверенный CA");
    if (ports.port_21) rec("HIGH","\033[1;33m","Отключи FTP (порт 21) — используй SFTP");
    if (ports.port_3389) rec("HIGH","\033[1;33m","Закрой RDP (3389) от интернета, используй VPN");
    if (whois.days_until_expiry>=0&&whois.days_until_expiry<30)
        rec("HIGH","\033[1;33m","Продли домен — истекает через "+std::to_string(whois.days_until_expiry)+" дней!");
    if (!http.has_hsts) rec("MEDIUM","\033[1;34m","Добавь HSTS: Strict-Transport-Security: max-age=31536000");
    if (!http.csp)      rec("MEDIUM","\033[1;34m","Добавь CSP: Content-Security-Policy header");
    if (!dns.has_dnssec) rec("MEDIUM","\033[1;34m","Включи DNSSEC в настройках DNS-провайдера");
    if (!dns.has_dkim)   rec("MEDIUM","\033[1;34m","Добавь DKIM запись для домена");
    if (whois.domain_age_days>=0&&whois.domain_age_days<365) rec("MEDIUM","\033[1;34m","Молодой домен — риск (менее года)");
    if (!dns.has_caa) rec("LOW","\033[0;37m","Добавь CAA: 0 issue \"letsencrypt.org\"");
    if (!http.x_frame_options) rec("LOW","\033[0;37m","Добавь X-Frame-Options: DENY или SAMEORIGIN");
    if (!http.referrer_policy) rec("LOW","\033[0;37m","Добавь Referrer-Policy: strict-origin-when-cross-origin");
    if (!dns.has_mx) rec("LOW","\033[0;37m","Настрой MX запись для приёма почты");
    if (!any_rec) brow(G+"\u2713 Отличная защита! Продолжай следить за CVE."+R,
                       display_len("\u2713 Отличная защита! Продолжай следить за CVE."));
    std::cout<<B<<C<<BOX_BOT<<R<<"\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  run
// ─────────────────────────────────────────────────────────────────────────────
void Scorecard::run(const std::string& target) {
    auto t0=std::chrono::steady_clock::now();
    std::cout<<"\n"<<Color::INFO<<"Security Scorecard: "<<Color::CYAN<<target<<Color::RESET<<"\n\n";

    PortsAnalysis ports=check_ports(target); print_progress(1,"Проверяем порты...");
    DNSAnalysis   dns  =check_dns(target);   print_progress(3,"Анализируем DNS...");
    TLSAnalysis   tls  =check_tls(target);   print_progress(5,"Проверяем TLS...");
    HTTPAnalysis  http =check_http(target);  print_progress(7,"Анализируем заголовки...");
    auto cves=check_cve(target,ports);       print_progress(9,"Сопоставляем CVE...");
    bool firewall=check_firewall(target);
    WhoisAnalysis whois=check_whois(target);
    print_progress(10,"Готово!"); std::cout<<"\n";

    double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    std::string safe_target=safe_filename(target);

    // Load history — latest file by name
    bool has_prev=false; int prev_score=0;
    { std::filesystem::create_directories("logs");
      try {
        std::string latest; int ls=0;
        std::string prefix="scorecard_"+safe_target+"_";
        for (auto& e:std::filesystem::directory_iterator("logs")) {
            std::string name=e.path().filename().string();
            if (name.rfind(prefix,0)==0&&e.path().extension()==".txt") {
                if (name>latest) { std::ifstream f(e.path()); int s=0; if (f>>s) {latest=name;ls=s;} }
            }
        }
        if (!latest.empty()) { has_prev=true; prev_score=ls; }
      } catch (...) {}
    }

    // Score
    int score=100;
    int cve_pen=0; for (auto& c:cves) cve_pen+=c.penalty; cve_pen=std::min(cve_pen,40);
    int tls_pen=tls.has_https?tls.penalty:0;
    if (tls.has_https&&!http.has_hsts) tls_pen+=3; tls_pen=std::min(tls_pen,15);
    score-=std::min(cve_pen,40); score-=std::min(ports.penalty,20);
    score-=std::min(dns.penalty,20); score-=tls_pen; score-=std::min(http.penalty,10);
    score+=firewall?5:-5; score=std::max(0,std::min(100,score));
    auto [grade,verdict]=score_grade(score);

    // Save
    { time_t now=time(nullptr); struct tm* ti=localtime(&now); char db[16];
      strftime(db,sizeof(db),"%Y-%m-%d",ti);
      std::string lp="logs/scorecard_"+safe_target+"_"+std::string(db)+".txt";
      try { std::ofstream f(lp); if (f) f<<score<<"\n"; } catch (...) {} }

    print_report(target,elapsed,score,grade,verdict,cves,cve_pen,dns,tls,tls_pen,
                 http,ports,firewall,whois,has_prev,prev_score);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Legacy API
// ─────────────────────────────────────────────────────────────────────────────
ScoreCard Scorecard::calculate(const ScanResult& result) {
    ScoreCard sc; int score=100;
    int cp=0;
    for (const auto& s:result.cve_severities) {
        if (s=="CRITICAL") cp+=15; else if (s=="HIGH") cp+=8;
        else if (s=="MEDIUM") cp+=3; else if (s=="LOW") cp+=1;
    }
    sc.cve_penalty=std::min(cp,40); score-=sc.cve_penalty;
    int pp=0,cnt=result.open_port_count;
    if (cnt>20) pp=20; else if (cnt>10) pp=12; else if (cnt>5) pp=6; else if (cnt>2) pp=3;
    sc.ports_penalty=pp; score-=pp;
    int sp=0;
    if (result.has_telnet) sp+=15; if (result.has_ftp) sp+=10; if (result.has_rdp) sp+=8;
    sc.services_penalty=std::min(sp,20); score-=sc.services_penalty;
    int sl=0;
    if (!result.has_ssl) sl+=10; if (result.ssl_expired) sl+=8;
    if (result.has_ssl&&!result.ssl_valid) sl+=5;
    sc.ssl_penalty=sl; score-=sl;
    if (result.firewall_detected) score+=5;
    score=std::max(0,std::min(100,score)); sc.total=score;
    if (score>=90) {sc.grade="A+";sc.verdict="Отличная защита";}
    else if (score>=80) {sc.grade="A";sc.verdict="Хорошая защита";}
    else if (score>=70) {sc.grade="B";sc.verdict="Удовлетворительно";}
    else if (score>=60) {sc.grade="C";sc.verdict="Есть проблемы";}
    else if (score>=50) {sc.grade="D";sc.verdict="Серьёзные проблемы";}
    else {sc.grade="F";sc.verdict="Критически опасно";}
    return sc;
}

static void print_bar_legacy(const std::string& label,int penalty,int max_pen,const std::string& col) {
    int f=(max_pen>0)?std::min(penalty*20/max_pen,20):0;
    std::cout<<"  "<<std::left<<std::setw(18)<<label<<" "<<col;
    for (int i=0;i<f;i++) std::cout<<"█"; std::cout<<"\033[0m";
    for (int i=f;i<20;i++) std::cout<<"░"; std::cout<<"  -"<<penalty<<" pts\n";
}

void Scorecard::print(const ScoreCard& sc,const std::string& target) {
    std::string gc=(sc.grade=="A+"||sc.grade=="A")?"\033[32m":(sc.grade=="B")?"\033[36m":(sc.grade=="C")?"\033[33m":"\033[31m";
    std::cout<<"\n\033[36m\033[1m";
    std::cout<<" ╔══════════════════════════════════════════════════════════════╗\n";
    std::cout<<" ║              SCORECARD БЕЗОПАСНОСТИ                         ║\n";
    std::cout<<" ║  Цель: "<<target;
    int pad=53-static_cast<int>(target.size()); for (int i=0;i<pad;i++) std::cout<<' ';
    std::cout<<"║\n ╠══════════════════════════════════════════════════════════════╣\n\033[0m";
    std::cout<<"\n      Оценка: "<<gc<<"\033[1m"<<sc.grade<<"\033[0m"<<"   —   "<<gc<<sc.verdict<<"\033[0m\n\n";
    std::cout<<"\033[1m  АНАЛИЗ ШТРАФОВ:\n\033[0m";
    print_bar_legacy("CVE уязвимости", sc.cve_penalty,     40,"\033[31m");
    print_bar_legacy("Открытые порты", sc.ports_penalty,    20,"\033[33m");
    print_bar_legacy("Опасные сервисы",sc.services_penalty, 20,"\033[38;5;208m");
    print_bar_legacy("SSL/TLS",        sc.ssl_penalty,      10,"\033[36m");
    std::cout<<"\n\033[1m  РЕКОМЕНДАЦИИ:\n\033[0m";
    if (sc.cve_penalty>20)       std::cout<<"\033[31m  [!] Обновите ПО — обнаружены CRITICAL уязвимости\n\033[0m";
    if (sc.ports_penalty>10)     std::cout<<"\033[33m  [!] Закройте лишние порты через firewall\n\033[0m";
    if (sc.services_penalty>=10) std::cout<<"\033[33m  [!] Замените Telnet/FTP на SSH/SFTP\n\033[0m";
    if (sc.ssl_penalty>=8)       std::cout<<"\033[36m  [i] Обновите или установите SSL-сертификат\n\033[0m";
    if (sc.total>=80)            std::cout<<"\033[32m  [+] Хорошая защита. Продолжайте следить за CVE.\n\033[0m";
    std::cout<<"\n\033[36m\033[1m";
    std::cout<<" ╚══════════════════════════════════════════════════════════════╝\n\033[0m\n";
}