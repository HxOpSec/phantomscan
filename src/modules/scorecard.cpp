// ─────────────────────────────────────────────────────────────────────────────
//  scorecard.cpp  —  Professional Security Analyzer (SecurityScorecard/Qualys)
//  All checks run in parallel via std::async, timeout 5s each, total ≤ 15s
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
#include <thread>
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

// ─────────────────────────────────────────────────────────────────────────────
//  Box helpers — every line passes through box_row() (64 visible chars)
// ─────────────────────────────────────────────────────────────────────────────
static const int BOX_INNER = 62;
static const std::string BOX_TOP = "╔══════════════════════════════════════════════════════════════╗";
static const std::string BOX_SEP = "╠══════════════════════════════════════════════════════════════╣";
static const std::string BOX_BOT = "╚══════════════════════════════════════════════════════════════╝";

// Считает реальную ширину строки БЕЗ ANSI кодов
static int display_len(const std::string& s) {
    int len = 0;
    bool in_escape = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\033') { in_escape = true; continue; }
        if (in_escape) {
            if (s[i] == 'm') in_escape = false;
            continue;
        }
        // UTF-8: считаем только первый байт символа
        unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c & 0xC0) != 0x80) len++;
    }
    return len;
}

// Строит одну строку рамки РОВНО 64 символа
static std::string box_row(const std::string& content) {
    int visible = display_len(content);
    int pad = BOX_INNER - visible; // 64 - 2 (для ║ слева и справа)
    if (pad < 0) pad = 0;
    return "║" + content + std::string(static_cast<size_t>(pad), ' ') + "║";
}

// Print helper that optionally left-pads with two spaces like старый формат
static void brow(const std::string& text, int custom_display_len = -1) {
    std::string txt = text;
    int dlen = (custom_display_len >= 0) ? custom_display_len : display_len(txt);
    if (dlen > BOX_INNER - 2) {
        // leave room for two leading spaces and "..." (BOX_INNER - 5 visible chars)
        const int max_visible = BOX_INNER - 5;
        while (dlen > max_visible && !txt.empty()) {
            txt.pop_back();
            dlen = display_len(txt);
        }
        txt += "...";
        dlen = display_len(txt);
    }
    int pad = BOX_INNER - 2 - dlen;
    if (pad < 0) pad = 0;
    std::string row = "  " + txt + std::string(static_cast<size_t>(pad), ' ');
    std::cout << box_row(row) << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  Static helpers
// ─────────────────────────────────────────────────────────────────────────────

// Run a shell command and return its stdout
static std::string run_cmd(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[4096];
    std::string out;
    while (fgets(buf, static_cast<int>(sizeof(buf)), pipe))
        out += buf;
    pclose(pipe);
    return out;
}

// Non-blocking TCP connect with timeout
static bool tcp_connect(const std::string& host, int port_num, int timeout_sec) {
    struct addrinfo hints{};
    struct addrinfo* ai = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string svc = std::to_string(port_num);
    if (getaddrinfo(host.c_str(), svc.c_str(), &hints, &ai) != 0 || ai == nullptr)
        return false;

    int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) { freeaddrinfo(ai); return false; }

    int fl = fcntl(sock, F_GETFL, 0);
    if (fl >= 0) fcntl(sock, F_SETFL, fl | O_NONBLOCK);

    connect(sock, ai->ai_addr, ai->ai_addrlen);   // EINPROGRESS expected
    freeaddrinfo(ai);

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv;
    tv.tv_sec  = static_cast<long>(timeout_sec);
    tv.tv_usec = 0;

    bool ok = false;
    if (select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0)
            ok = (err == 0);
    }
    close(sock);
    return ok;
}

// Map port to service name for CVE lookup
static std::string port_to_service(int port) {
    switch (port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 8080: return "Tomcat";
        case 8443: return "HTTPS";
        case 27017: return "MongoDB";
        default:   return "";
    }
}

// Lowercase helper
static std::string to_lower(const std::string& s) {
    std::string out = s;
    for (char& ch : out) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return out;
}

// Trim leading/trailing whitespace
static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos || end == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

static std::string format_port_token(const PortsAnalysis::ServiceBanner& sb) {
    std::string service = sb.service.empty() ? "port" : sb.service;
    std::string product = sb.product;
    std::string version = sb.version;

    if (!product.empty()) {
        std::string product_l = to_lower(product);
        std::string service_l = to_lower(service);
        // Prefer product for HTTP-like services
        if (service_l == "http" || service_l == "https" || service_l == "tomcat") {
            std::string token = product;
            if (sb.version_known && !version.empty())
                token += "/" + version;
            return token;
        }
        // SSH -> keep service prefix
        if (service_l == "ssh" && product_l == "openssh") {
            std::string token = "SSH-OpenSSH";
            if (sb.version_known && !version.empty())
                token += "_" + version;
            return token;
        }
        std::string token = service + "-" + product;
        if (sb.version_known && !version.empty())
            token += "/" + version;
        return token;
    }
    if (sb.version_known && !version.empty())
        return service + "-" + version;
    return service;
}

// Extract banner for given port/service using lightweight commands (3-5s timeout)
static std::string grab_banner_raw(const std::string& host, int port, const std::string& svc) {
    // Basic sanitization to avoid shell injection in helper commands
    for (char ch : host) {
        if (!(std::isalnum(static_cast<unsigned char>(ch)) ||
              ch == '.' || ch == '-' || ch == ':' || ch == '[' || ch == ']'))
            return "";
    }
    std::string cmd;
    if (port == 22 || svc == "SSH") {
        cmd = "echo '' | timeout 3 nc -w 2 " + host + " 22 2>/dev/null";
    } else if (port == 21 || svc == "FTP") {
        cmd = "echo '' | timeout 3 nc -w 2 " + host + " 21 2>/dev/null";
    } else if (port == 25 || svc == "SMTP") {
        cmd = "echo '' | timeout 3 nc -w 2 " + host + " 25 2>/dev/null";
    } else if (port == 80 || port == 8080 || svc == "HTTP" || svc == "Tomcat") {
        cmd = "curl -sI --max-time 5 http://" + host + " 2>/dev/null";
    } else if (port == 443 || port == 8443 || svc == "HTTPS") {
        cmd = "curl -sI --max-time 5 https://" + host + " 2>/dev/null";
    } else {
        return "";
    }
    return trim(run_cmd(cmd));
}

// Parse banner into product + version token
static void parse_banner(PortsAnalysis::ServiceBanner& sb) {
    if (sb.banner.empty()) return;
    std::string lower = to_lower(sb.banner);

    if (sb.service == "SSH") {
        std::regex re("openssh[_-]?([0-9]+(?:\\.[0-9]+)*)", std::regex::icase);
        std::smatch m;
        if (std::regex_search(sb.banner, m, re) && m.size() >= 2) {
            sb.product = "OpenSSH";
            sb.version = m.str(1);
            sb.version_known = true;
            return;
        }
    }

    if (sb.service == "HTTP" || sb.service == "HTTPS" || sb.service == "Tomcat") {
        std::istringstream ss(sb.banner);
        std::string line;
        while (std::getline(ss, line)) {
            std::string l = to_lower(line);
            if (l.rfind("server:", 0) == 0) {
                std::regex re("server:\\s*([A-Za-z0-9._-]+)[/ ]?([A-Za-z0-9._-]+)?", std::regex::icase);
                std::smatch m;
                if (std::regex_search(line, m, re) && m.size() >= 2) {
                    sb.product = m.str(1);
                    if (m.size() >= 3) sb.version = m.str(2);
                    sb.version_known = !sb.version.empty();
                    return;
                }
            }
        }
    }

    if (sb.service == "FTP" || sb.service == "SMTP") {
        std::regex re("^\\s*\\d{3}\\s+([A-Za-z0-9._-]+)[ /]?([A-Za-z0-9._-]+)?", std::regex::icase);
        std::smatch m;
        if (std::regex_search(sb.banner, m, re) && m.size() >= 2) {
            sb.product = m.str(1);
            if (m.size() >= 3) sb.version = m.str(2);
            sb.version_known = !sb.version.empty();
        }
    }
}

// Determine if CVE entry year is recent enough
static bool cve_recent(const std::string& id) {
    std::regex re("CVE-(\\d{4})-");
    std::smatch m;
    if (std::regex_search(id, m, re) && m.size() >= 2) {
        int year = std::stoi(m.str(1));
        return year >= 2015;
    }
    return false;
}

// Check if CVE description matches detected version (heuristic)
static bool cve_matches_version(const CVEEntry& e,
                                const PortsAnalysis::ServiceBanner& sb) {
    if (!sb.version_known || sb.version.empty())
        return true; // unknown version -> keep

    std::string desc_l = to_lower(e.description + " " + e.id);
    std::string prod_l = to_lower(sb.product.empty() ? sb.service : sb.product);

    // require product mention to avoid cross-product noise
    if (!prod_l.empty() && desc_l.find(prod_l) == std::string::npos)
        return false;

    // match major version
    std::string ver = sb.version;
    size_t dot = ver.find('.');
    std::string major = (dot == std::string::npos) ? ver : ver.substr(0, dot);

    if (!major.empty()) {
        // If description mentions another version number, ensure major matches
        std::regex version_re(prod_l + "[^0-9]{0,5}(\\d+(?:\\.\\d+)*)");
        std::smatch m;
        if (std::regex_search(desc_l, m, version_re) && m.size() >= 2) {
            std::string found = m.str(1);
            size_t fdot = found.find('.');
            std::string found_major = (fdot == std::string::npos) ? found : found.substr(0, fdot);
            return found_major == major;
        }
        // No explicit version in description -> allow if product matched
        return true;
    }
    return true;
}

// Grade + verdict from final score
static std::pair<std::string, std::string> score_grade(int s) {
    if (s >= 90) return {"A+", "Отличная защита"};
    if (s >= 80) return {"A",  "Хорошая защита"};
    if (s >= 70) return {"B",  "Удовлетворительно"};
    if (s >= 60) return {"C",  "Есть проблемы"};
    if (s >= 50) return {"D",  "Серьёзные проблемы"};
    return            {"F",  "Критически опасно"};
}

// Score bar: ████░░░░ style (32 blocks)
static std::string score_bar(int score) {
    int filled = score * 32 / 100;
    std::string bar;
    for (int i = 0; i < 32; i++)
        bar += (i < filled ? "█" : "░");
    return bar;
}

// ANSI color for score
static std::string score_color(int score) {
    if (score >= 90) return "\033[32m";          // green
    if (score >= 70) return "\033[33m";          // yellow
    if (score >= 50) return "\033[38;5;208m";    // orange
    return "\033[31m";                           // red
}

// Print real-time progress bar for fixed 6 steps (fills 1,3,5,7,9,10 blocks)
static void print_progress(int filled_blocks, const std::string& msg) {
    if (filled_blocks < 0) filled_blocks = 0;
    if (filled_blocks > 10) filled_blocks = 10;
    std::cout << "\r  \033[36m[";
    for (int i = 0; i < 10; i++)
        std::cout << (i < filled_blocks ? "■" : "░");
    std::cout << "] \033[0m" << msg << "          " << std::flush;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_dns — SPF, DMARC, DNSSEC, CAA (all parallel via dig)
// ─────────────────────────────────────────────────────────────────────────────
DNSAnalysis Scorecard::check_dns(const std::string& domain) {
    DNSAnalysis r;

    auto f_spf    = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short TXT " + domain + " 2>/dev/null");
    });
    auto f_dmarc  = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short TXT _dmarc." + domain + " 2>/dev/null");
    });
    auto f_dnssec = std::async(std::launch::async, [domain] {
        return run_cmd("dig +dnssec A " + domain + " 2>/dev/null");
    });
    auto f_caa    = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short CAA " + domain + " 2>/dev/null");
    });
    auto f_dkim   = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short TXT default._domainkey." + domain + " 2>/dev/null");
    });
    auto f_mx     = std::async(std::launch::async, [domain] {
        return run_cmd("dig +short MX " + domain + " 2>/dev/null");
    });

    std::string spf    = f_spf.get();
    std::string dmarc  = f_dmarc.get();
    std::string dnssec = f_dnssec.get();
    std::string caa    = f_caa.get();
    std::string dkim   = f_dkim.get();
    std::string mx     = f_mx.get();

    // SPF
    if (spf.find("v=spf1") != std::string::npos) {
        r.has_spf = true;
        if (spf.find("+all") != std::string::npos)
            r.spf_plusall = true;
        else if (spf.find("~all") != std::string::npos)
            r.spf_softfail = true;
    }

    // DMARC
    if (dmarc.find("v=DMARC1") != std::string::npos) {
        r.has_dmarc = true;
        if (dmarc.find("p=none") != std::string::npos)
            r.dmarc_none = true;
    }

    // DNSSEC: look for "ad" flag in the flags section
    r.has_dnssec = (dnssec.find(";; flags:") != std::string::npos &&
                    (dnssec.find(" ad ") != std::string::npos ||
                     dnssec.find(" ad;") != std::string::npos));

    // CAA: non-empty response means records exist
    r.has_caa = (!caa.empty() && caa != "\n" &&
                 static_cast<int>(caa.size()) > 1);

    // DKIM (default._domainkey selector): non-empty = present
    r.has_dkim = (!dkim.empty() && dkim != "\n" && dkim.find("v=DKIM1") != std::string::npos);

    // MX: non-empty = at least one MX record
    r.has_mx = (!mx.empty() && mx != "\n" && static_cast<int>(mx.size()) > 1);

    // Penalty
    int pen = 0;
    if (!r.has_spf)          pen += 8;
    else if (r.spf_plusall)  pen += 8;
    else if (r.spf_softfail) pen += 4;

    if (!r.has_dmarc)       pen += 7;
    else if (r.dmarc_none)  pen += 4;

    if (!r.has_dnssec) pen += 3;
    if (!r.has_caa)    pen += 2;
    if (!r.has_dkim)   pen += 3;
    if (!r.has_mx)     pen += 2;

    r.penalty = std::min(pen, 25);
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_whois — parse whois output for age, expiry, registrar, country
// ─────────────────────────────────────────────────────────────────────────────

// Try to parse a date string (multiple formats) into a time_t. Returns -1 on failure.
static time_t parse_whois_date(const std::string& val) {
    if (val.empty()) return -1;
    struct tm t{};
    // ISO 8601: 2020-01-15T... or 2020-01-15
    if (strptime(val.c_str(), "%Y-%m-%dT%H:%M:%S", &t) ||
        strptime(val.c_str(), "%Y-%m-%d", &t))
        return timegm(&t);
    // MM/DD/YYYY
    if (strptime(val.c_str(), "%m/%d/%Y", &t))
        return timegm(&t);
    // dd-Mon-YYYY
    if (strptime(val.c_str(), "%d-%b-%Y", &t))
        return timegm(&t);
    // Mon Jan 15 ...
    if (strptime(val.c_str(), "%a %b %d %H:%M:%S %Z %Y", &t))
        return timegm(&t);
    return -1;
}

// Extract first field value matching one of the given keys (case-insensitive)
static std::string whois_field(const std::string& whois,
                               const std::vector<std::string>& keys) {
    std::istringstream ss(whois);
    std::string line;
    while (std::getline(ss, line)) {
        std::string lline = line;
        for (char& ch : lline)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        for (const auto& key : keys) {
            std::string lkey = key;
            for (char& ch : lkey)
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (lline.rfind(lkey, 0) == 0) {
                // find colon in original line
                size_t colon = line.find(':');
                if (colon == std::string::npos) continue;
                std::string val = line.substr(colon + 1);
                // trim leading/trailing whitespace
                size_t s = val.find_first_not_of(" \t\r");
                size_t e = val.find_last_not_of(" \t\r");
                if (s == std::string::npos) continue;
                return val.substr(s, e - s + 1);
            }
        }
    }
    return "";
}

WhoisAnalysis Scorecard::check_whois(const std::string& domain) {
    WhoisAnalysis r;
    std::string out = run_cmd("whois " + domain + " 2>/dev/null");
    if (out.empty()) return r;

    // Creation date
    std::string created = whois_field(out,
        {"creation date:", "created on:", "created:", "registration time:",
         "registered:", "domain registered:", "commencement date:",
         "registration date:", "domain registration date:"});
    // Expiry date
    std::string expiry = whois_field(out,
        {"registry expiry date:", "registrar registration expiration date:",
         "expiration date:", "expires:", "expire:", "paid-till:",
         "expiry date:", "validity:"});
    // Registrar
    std::string registrar = whois_field(out,
        {"registrar:", "registrar name:", "sponsoring registrar:"});
    // Country
    std::string country = whois_field(out,
        {"registrant country:", "country:", "registrant: country"});

    time_t now = time(nullptr);

    // Trim ISO timezone suffix (Z or +00:00) before parsing
    auto trim_tz = [](const std::string& s) -> std::string {
        if (s.empty()) return s;
        std::string t = s;
        if (t.back() == 'Z') t.pop_back();
        size_t plus = t.rfind('+');
        if (plus != std::string::npos && plus > 10) t = t.substr(0, plus);
        return t;
    };

    time_t t_created = parse_whois_date(trim_tz(created));
    time_t t_expiry  = parse_whois_date(trim_tz(expiry));

    if (t_created > 0 && t_created <= now)
        r.domain_age_days = static_cast<int>((now - t_created) / 86400);
    if (t_expiry  > 0)
        r.days_until_expiry = static_cast<int>((t_expiry - now) / 86400);

    // Trim registrar to fit in box
    if (!registrar.empty() && registrar.size() > 30)
        registrar = registrar.substr(0, 27) + "...";
    r.registrar = registrar;

    // Country: take only first token
    if (!country.empty()) {
        size_t sp = country.find(' ');
        r.country = (sp != std::string::npos) ? country.substr(0, sp) : country;
        if (r.country.size() > 20) r.country = r.country.substr(0, 20);
    }

    // Penalties
    int pen = 0;
    if (r.domain_age_days >= 0 && r.domain_age_days < 365) pen += 5;  // young domain
    if (r.days_until_expiry >= 0 && r.days_until_expiry < 30) pen += 8; // expiring soon
    r.penalty = pen;
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_tls — TLS 1.0/1.1/1.2/1.3, certificate, weak ciphers (all parallel)
// ─────────────────────────────────────────────────────────────────────────────
TLSAnalysis Scorecard::check_tls(const std::string& host) {
    TLSAnalysis r;

    std::string base = "echo | timeout 5 openssl s_client -connect " +
                       host + ":443 ";

    auto f10 = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "-tls1 2>/dev/null");
        return o.find("CONNECTED") != std::string::npos;
    });
    auto f11 = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "-tls1_1 2>/dev/null");
        return o.find("CONNECTED") != std::string::npos;
    });
    auto f12 = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "-tls1_2 2>/dev/null");
        return o.find("CONNECTED") != std::string::npos;
    });
    auto f13 = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "-tls1_3 2>/dev/null");
        return o.find("CONNECTED") != std::string::npos;
    });
    auto f_cert = std::async(std::launch::async, [host] {
        return run_cmd(
            "echo | timeout 5 openssl s_client -connect " + host +
            ":443 -servername " + host +
            " 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null");
    });
    auto f_ciph = std::async(std::launch::async, [base] {
        std::string o = run_cmd(base + "2>/dev/null | grep 'Cipher    '");
        return o;
    });

    r.tls10 = f10.get();
    r.tls11 = f11.get();
    r.tls12 = f12.get();
    r.tls13 = f13.get();
    r.has_https = r.tls10 || r.tls11 || r.tls12 || r.tls13;

    // Certificate
    std::string cert = f_cert.get();
    if (!cert.empty()) {
        std::string subject, issuer;

        auto extract_field = [&cert](const std::string& key) -> std::string {
            size_t pos = cert.find(key);
            if (pos == std::string::npos) return "";
            size_t nl = cert.find('\n', pos);
            std::string val = cert.substr(pos + key.size(),
                                          nl == std::string::npos
                                          ? std::string::npos
                                          : nl - pos - key.size());
            while (!val.empty() && (val.back() == '\r' || val.back() == ' '))
                val.pop_back();
            return val;
        };

        subject = extract_field("subject=");
        issuer  = extract_field("issuer=");
        r.self_signed = (!subject.empty() && subject == issuer);

        std::string not_after = extract_field("notAfter=");
        if (!not_after.empty()) {
            struct tm t{};
            if (strptime(not_after.c_str(), "%b %d %H:%M:%S %Y %Z", &t)
                    != nullptr) {
                time_t cert_t = timegm(&t);
                time_t now_t  = time(nullptr);
                r.days_left   = static_cast<int>((cert_t - now_t) / 86400);
            }
        }
    }

    // Weak ciphers (RC4 / DES)
    std::string ciph = f_ciph.get();
    r.weak_ciphers = (ciph.find("RC4") != std::string::npos ||
                      ciph.find("DES")  != std::string::npos);

    // Penalty (max 15 here; HSTS -3 added separately in run())
    int pen = 0;
    if (r.has_https) {
        if (r.tls10)        pen += 10;
        if (r.tls11)        pen += 7;
        if (!r.tls13)       pen += 3;
        if (r.self_signed)  pen += 10;
        if (r.days_left >= 0 && r.days_left < 7)   pen += 10;
        else if (r.days_left >= 0 && r.days_left < 30) pen += 5;
        if (r.weak_ciphers) pen += 8;
    }
    r.penalty = pen;   // capped in run() together with HSTS
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_http — Security headers via curl
// ─────────────────────────────────────────────────────────────────────────────
HTTPAnalysis Scorecard::check_http(const std::string& host) {
    HTTPAnalysis r;

    // Try HTTPS first, fall back to HTTP
    std::string headers = run_cmd(
        "curl -sIL --max-time 5 https://" + host + " 2>/dev/null");
    if (headers.empty())
        headers = run_cmd(
            "curl -sIL --max-time 5 http://" + host + " 2>/dev/null");

    if (headers.empty()) return r;

    auto has_hdr = [&headers](const std::string& key) {
        std::string lkey = key;
        for (char& ch : lkey)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        std::string lh = headers;
        for (char& ch : lh)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        return lh.find(lkey) != std::string::npos;
    };

    r.x_frame_options        = has_hdr("x-frame-options");
    r.x_content_type_options = has_hdr("x-content-type-options");
    r.csp                    = has_hdr("content-security-policy");
    r.referrer_policy        = has_hdr("referrer-policy");
    r.has_hsts               = has_hdr("strict-transport-security");

    // Server version exposed: check if "Server:" header has version numbers
    size_t srv_pos = headers.find("Server:");
    if (srv_pos == std::string::npos)
        srv_pos = headers.find("server:");
    if (srv_pos != std::string::npos) {
        size_t nl = headers.find('\n', srv_pos);
        std::string srv_line = headers.substr(srv_pos,
            nl == std::string::npos ? std::string::npos : nl - srv_pos);
        // Has version if there's a digit after a slash or space
        bool has_digit = false;
        bool after_sep = false;
        for (char ch : srv_line) {
            if (ch == '/' || ch == ' ') { after_sep = true; }
            if (after_sep && std::isdigit(static_cast<unsigned char>(ch))) { has_digit = true; break; }
        }
        r.server_version_exposed = has_digit;
    }

    // Penalty (excl. HSTS — counted in TLS section)
    int pen = 0;
    if (!r.x_frame_options)        pen += 2;
    if (!r.x_content_type_options) pen += 2;
    if (!r.csp)                    pen += 3;
    if (!r.referrer_policy)        pen += 1;
    if (r.server_version_exposed)  pen += 2;

    r.penalty = std::min(pen, 10);
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_ports — TCP connect scan of dangerous ports (parallel)
// ─────────────────────────────────────────────────────────────────────────────
PortsAnalysis Scorecard::check_ports(const std::string& host) {
    PortsAnalysis r;

    static const std::vector<int> SCAN_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    };

    // Safe ports (don't count as "extra")
    static const std::set<int> SAFE_PORTS = {22, 80, 443, 53};
    // Dangerous ports that have specific penalties
    static const std::set<int> DANGER_PORTS = {21, 23, 25, 445, 3389};

    // Launch all TCP checks in parallel
    std::vector<std::future<bool>> futs;
    futs.reserve(SCAN_PORTS.size());
    for (int p : SCAN_PORTS) {
        futs.push_back(std::async(std::launch::async,
            [host, p] { return tcp_connect(host, p, 3); }));
    }

    for (size_t i = 0; i < SCAN_PORTS.size(); i++) {
        if (!futs[i].get()) continue;
        int p = SCAN_PORTS[i];
        r.open_list.push_back(p);
        std::string svc_name = port_to_service(p);
        if (!svc_name.empty()) {
            PortsAnalysis::ServiceBanner sb;
            sb.port = p;
            sb.service = svc_name;
            r.banners.push_back(sb);
        }
        if (p == 21)   r.port_21   = true;
        if (p == 23)   r.port_23   = true;
        if (p == 25)   r.port_25   = true;
        if (p == 139)  r.port_139  = true;
        if (p == 445)  r.port_445  = true;
        if (p == 3389) r.port_3389 = true;

        if (SAFE_PORTS.find(p) == SAFE_PORTS.end() &&
            DANGER_PORTS.find(p) == DANGER_PORTS.end())
            r.extra_count++;
    }

    int pen = 0;
    if (r.port_23)   pen += 15;
    if (r.port_21)   pen += 10;
    if (r.port_3389) pen += 8;
    if (r.port_445)  pen += 8;
    if (r.port_139)  pen += 6;
    if (r.port_25)   pen += 4;
    pen += r.extra_count * 2;

    r.penalty = std::min(pen, 20);
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_cve — lookup CVEs for open services in data/cve.json
// ─────────────────────────────────────────────────────────────────────────────
std::vector<CVEFinding> Scorecard::check_cve(const std::string& host,
                                             PortsAnalysis& ports) {
    std::vector<CVEFinding> findings;
    CVEScanner cve_db;
    std::map<std::string, PortsAnalysis::ServiceBanner> svc_meta;

    for (auto& sb : ports.banners) {
        PortsAnalysis::ServiceBanner filled = sb;
        filled.banner = grab_banner_raw(host, sb.port, sb.service);
        parse_banner(filled);

        auto it = svc_meta.find(sb.service);
        if (it == svc_meta.end()) {
            svc_meta[sb.service] = filled;
        } else {
            // Prefer entry with known version/banner
            bool replace = false;
            if (filled.version_known && !it->second.version_known) replace = true;
            else if (!it->second.version_known && !it->second.banner.empty() && filled.banner.empty()) replace = false;
            else if (it->second.banner.empty() && !filled.banner.empty()) replace = true;
            if (replace) svc_meta[sb.service] = filled;
        }
        sb = filled;
    }

    std::set<std::string> seen_services;
    for (int p : ports.open_list) {
        std::string svc = port_to_service(p);
        if (svc.empty() || seen_services.count(svc)) continue;
        seen_services.insert(svc);

        auto meta_it = svc_meta.find(svc);
        PortsAnalysis::ServiceBanner meta = (meta_it != svc_meta.end())
                                            ? meta_it->second
                                            : PortsAnalysis::ServiceBanner{};
        if (meta.service.empty()) {
            meta.service = svc;
            meta.port    = p;
        }

        auto entries = cve_db.search(svc);
        for (auto& e : entries) {
            if (!cve_recent(e.id)) continue;
            if (!cve_matches_version(e, meta)) continue;

            CVEFinding f;
            f.id      = e.id;
            f.cvss    = e.cvss;
            f.desc    = e.description;
            f.service = svc;

            if (e.cvss >= 9.0)      f.penalty = 15;
            else if (e.cvss >= 7.0) f.penalty = 8;
            else if (e.cvss >= 4.0) f.penalty = 3;
            else if (e.cvss > 0.0)  f.penalty = 1;

            findings.push_back(std::move(f));
        }
    }

    // Sort by CVSS descending and limit to top 10
    std::sort(findings.begin(), findings.end(),
        [](const CVEFinding& a, const CVEFinding& b) {
            if (a.cvss == b.cvss) return a.id < b.id;
            return a.cvss > b.cvss;
        });
    if (findings.size() > 10)
        findings.resize(10);

    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
//  check_firewall — filtered port = firewall likely present
// ─────────────────────────────────────────────────────────────────────────────
bool Scorecard::check_firewall(const std::string& host) {
    // Probe a port that is almost never legitimately open.
    // If it times out (filtered), a firewall is present.
    // If RST arrives quickly, it's just closed — no filtering.
    static const int PROBE = 31337;
    static const int TIMEOUT = 3;

    struct addrinfo hints{};
    struct addrinfo* ai = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string svc = std::to_string(PROBE);
    if (getaddrinfo(host.c_str(), svc.c_str(), &hints, &ai) != 0 || ai == nullptr)
        return false;

    int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) { freeaddrinfo(ai); return false; }

    int fl = fcntl(sock, F_GETFL, 0);
    if (fl >= 0) fcntl(sock, F_SETFL, fl | O_NONBLOCK);

    auto t_start = std::chrono::steady_clock::now();
    connect(sock, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);

    fd_set wset, eset;
    FD_ZERO(&wset); FD_ZERO(&eset);
    FD_SET(sock, &wset);
    FD_SET(sock, &eset);
    struct timeval tv;
    tv.tv_sec  = static_cast<long>(TIMEOUT);
    tv.tv_usec = 0;

    int sel = select(sock + 1, nullptr, &wset, &eset, &tv);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t_start).count();
    close(sock);

    // Timeout (sel == 0) or very slow response ⟹ port is filtered ⟹ firewall
    if (sel == 0) return true;
    // Fast RST (< 500 ms) ⟹ probably just closed
    return (elapsed > 500);
}

// ─────────────────────────────────────────────────────────────────────────────
//  print_report — format and display the full security report
// ─────────────────────────────────────────────────────────────────────────────
static void print_report(
    const std::string&          target,
    double                      elapsed,
    int                         score,
    const std::string&          grade,
    const std::string&          verdict,
    const std::vector<CVEFinding>& cves,
    int                         cve_pen,
    const DNSAnalysis&          dns,
    const TLSAnalysis&          tls,
    int                         tls_pen,
    const HTTPAnalysis&         http,
    const PortsAnalysis&        ports,
    bool                        firewall,
    const WhoisAnalysis&        whois,
    bool                        has_prev,
    int                         prev_score)
{
    std::string col = score_color(score);
    const std::string R  = "\033[0m";
    const std::string B  = "\033[1m";
    const std::string C  = "\033[36m";
    const std::string G  = "\033[1;32m";    // bold green  (✓)
    const std::string Y  = "\033[1;33m";    // bold yellow ([HIGH])
    const std::string RE = "\033[1;31m";    // bold red    ([CRITICAL] / ✗)
    const std::string BL = "\033[1;34m";    // bold blue   ([MEDIUM])
    const std::string GR = "\033[0;37m";    // grey        ([LOW])

    // Grade colour
    std::string gc = (grade == "A+" || grade == "A") ? G :
                     (grade == "B")                  ? C :
                     (grade == "C")                  ? Y : RE;

    std::cout << "\n" << B << C << BOX_TOP << R << "\n";

    // Title
    {
        std::string title = "SECURITY SCORECARD — " + target;
        brow(B + C + title + R, static_cast<int>(title.size()));
    }
    {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << elapsed;
        std::string sub = "Анализ завершён за " + ss.str() + " сек";
        brow(sub);
    }

    std::cout << B << C << BOX_SEP << R << "\n";

    // Score line
    {
        std::ostringstream ss;
        ss << "SCORE: " << score << " / 100    Grade: ";
        std::string pre  = ss.str();
        std::string line = col + B + pre + R + gc + B + grade + R
                         + "   " + col + verdict + R;
        brow(line, static_cast<int>(pre.size()) + static_cast<int>(grade.size())
                   + 3 + static_cast<int>(verdict.size()));
    }
    // Score bar
    {
        std::string bar   = score_bar(score);
        std::string line  = col + bar + R;
        brow(line, 32);  // bar is 32 display cols (█/░ are 3-byte, 1 col each)
    }
    // History row
    {
        if (has_prev) {
            int diff = score - prev_score;
            std::ostringstream hs;
            hs << "История: " << prev_score << " pts → " << score << " pts  ";
            if (diff > 0)       hs << G  << "↑ +" << diff << " улучшение" << R;
            else if (diff < 0)  hs << RE << "↓ "  << diff << " ухудшение" << R;
            else                hs << C  << "→ без изменений"              << R;
            int plain_len = static_cast<int>(
                ("История: " + std::to_string(prev_score) + " pts → " +
                 std::to_string(score) + " pts  ").size());
            std::string arrow_txt = (diff > 0) ? ("↑ +" + std::to_string(diff) + " улучшение") :
                                    (diff < 0) ? ("↓ "  + std::to_string(diff) + " ухудшение") :
                                                 "→ без изменений";
            brow(hs.str(), plain_len + display_len(arrow_txt));
        } else {
            brow(C + "Первый скан домена" + R, 18);
        }
    }

    // ── WHOIS ───────────────────────────────────────────────────────────────
    bool whois_available = (whois.domain_age_days >= 0 || whois.days_until_expiry >= 0 ||
                            !whois.registrar.empty() || !whois.country.empty());
    if (whois_available) {
        std::cout << B << C << BOX_SEP << R << "\n";
        brow(B + "WHOIS" + R, 5);
        // Domain age
        if (whois.domain_age_days >= 0) {
            int years  = whois.domain_age_days / 365;
            int months = (whois.domain_age_days % 365) / 30;
            std::ostringstream as;
            as << "Возраст домена:  ";
            if (years > 0)  as << years  << " " << (years  == 1 ? "год" :
                                                     years  < 5  ? "года" : "лет") << " ";
            if (months > 0 || years == 0)
                as << months << " " << (months == 1 ? "месяц" :
                                        months  < 5  ? "месяца" : "месяцев");
            std::string age_txt = as.str();
            bool age_ok = (whois.domain_age_days >= 365);
            std::string status_str = age_ok ? (G + "OK" + R) : (Y + "-5 pts" + R);
            int status_dlen = age_ok ? 2 : 6;
            int pad = BOX_INNER - 2 - display_len(age_txt) - status_dlen;
            if (pad < 1) pad = 1;
            std::cout << box_row("  " + age_txt + std::string(static_cast<size_t>(pad), ' ') + status_str) << "\n";
        }

        // Days until expiry
        if (whois.days_until_expiry >= 0) {
            std::ostringstream es;
            es << "Истекает через:  " << whois.days_until_expiry << " дней";
            std::string exp_txt = es.str();
            bool exp_ok = (whois.days_until_expiry >= 30);
            std::string status_str = exp_ok ? (G + "OK" + R) : (RE + "-8 pts" + R);
            int status_dlen = exp_ok ? 2 : 6;
            int pad = BOX_INNER - 2 - display_len(exp_txt) - status_dlen;
            if (pad < 1) pad = 1;
            std::cout << box_row("  " + exp_txt + std::string(static_cast<size_t>(pad), ' ') + status_str) << "\n";
        }

        // Registrar
        if (!whois.registrar.empty()) {
            std::string reg_txt = "Регистратор:     " + whois.registrar;
            brow(reg_txt);
        }
        // Country
        if (!whois.country.empty()) {
            std::string ctr_txt = "Страна:          " + whois.country;
            brow(ctr_txt);
        }
    }

    // ── CVSS ANALYSIS ──────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R << "\n";
    brow(B + "CVSS ANALYSIS" + R, 13);

    if (ports.open_list.empty()) {
        brow("  Открытых портов не обнаружено              " + G + "OK" + R,
             display_len("  Открытых портов не обнаружено              OK"));
        brow("  CVE штраф: 0 pts",
             display_len("  CVE штраф: 0 pts"));
    } else {
        // Build port description with banners/versions
        std::map<int, PortsAnalysis::ServiceBanner> port_map;
        for (const auto& b : ports.banners) port_map[b.port] = b;

        std::ostringstream port_line;
        port_line << "  Открытые порты: ";
        bool any_known = false;
        for (size_t i = 0; i < ports.open_list.size(); i++) {
            int p = ports.open_list[i];
            auto it = port_map.find(p);
            std::string svc = port_to_service(p);
            std::string token = std::to_string(p) + "(";
            if (it != port_map.end()) {
                const auto& sb = it->second;
                token += format_port_token(sb);
                if (sb.version_known && !sb.version.empty())
                    any_known = true;
            } else {
                token += (svc.empty() ? "port" : svc);
            }
            token += ")";
            port_line << token;
            if (i + 1 < ports.open_list.size()) port_line << ", ";
        }

        if (!any_known) {
            port_line << " — версии неизвестны";
        }
        brow(port_line.str());
        if (!any_known) {
            brow("  [?] Banner grabbing не дал результата");
            brow("  Показаны CVE >= 2015 для найденных сервисов");
        }

        int crit = 0, high = 0, med = 0, low = 0;
        double avg = 0.0;
        for (auto& c : cves) {
            avg += c.cvss;
            if (c.cvss >= 9.0)      crit++;
            else if (c.cvss >= 7.0) high++;
            else if (c.cvss >= 4.0) med++;
            else                    low++;
        }
        if (!cves.empty())
            avg /= static_cast<double>(cves.size());

        if (cves.empty()) {
            brow("  Уязвимостей не найдено в data/cve.json", 42);
        } else {
            std::ostringstream ss;
            ss << "Avg CVSS: " << std::fixed << std::setprecision(1) << avg
               << "   \u25a0 Critical: " << crit
               << "  \u25a0 High: "     << high
               << "  \u25a0 Medium: "   << med;
            brow(ss.str());

            // Show top CVEs (up to 10 already limited)
            for (size_t i = 0; i < cves.size(); i++) {
                if (i >= 10) break;
                auto& c = cves[i];
                std::string desc = c.desc;
                if (static_cast<int>(desc.size()) > 26) desc = desc.substr(0, 23) + "...";
                std::ostringstream ls;
                ls << std::left << std::setw(16) << c.id
                   << "CVSS " << std::fixed << std::setprecision(1) << c.cvss
                   << "  " << std::setw(26) << desc
                   << " -" << c.penalty << " pts";
                brow(ls.str());
            }
            std::ostringstream pp;
            pp << "Общий штраф CVE: -" << cve_pen << " pts";
            brow(RE + B + pp.str() + R, display_len(pp.str()));
        }
    }

    // ── DNS SECURITY ────────────────────────────────────────────────────────
    // yn: prints a status row without a leading extra mark.
    // txt must already contain ✓ or ✗ as part of the label.
    auto yn = [&](bool ok, const std::string& good_txt, const std::string& bad_txt,
                  int penalty) {
        std::string txt = ok ? good_txt : bad_txt;
        // Add ANSI color to the ✓/✗ already embedded in txt
        const std::string TICK  = "\u2713";
        const std::string CROSS = "\u2717";
        std::string colored = txt;
        size_t pos;
        if ((pos = colored.find(TICK))  != std::string::npos)
            colored.replace(pos, TICK.size(),  G  + TICK  + R);
        if ((pos = colored.find(CROSS)) != std::string::npos)
            colored.replace(pos, CROSS.size(), RE + CROSS + R);

        int txt_dlen = display_len(txt);

        std::string pts_str;
        int pts_dlen = 0;
        if (!ok && penalty > 0) {
            std::ostringstream ps; ps << "-" << penalty << " pts";
            pts_str  = Y + ps.str() + R;
            pts_dlen = static_cast<int>(ps.str().size());
        } else {
            pts_str  = G + "OK" + R;
            pts_dlen = 2;
        }

        int pad = BOX_INNER - 2 - txt_dlen - pts_dlen;
        if (pad < 1) pad = 1;
        std::cout << box_row("  " + colored
                  + std::string(static_cast<size_t>(pad), ' ')
                  + pts_str) << "\n";
    };

    std::cout << B << C << BOX_SEP << R << "\n";
    brow(B + "DNS SECURITY" + R, 12);
    {
        std::string spf_good = "SPF     \u2713 Настроен";
        std::string spf_bad  = !dns.has_spf   ? "SPF     \u2717 отсутствует" :
                               dns.spf_plusall ? "SPF     \u2717 +all ОПАСЕН" :
                               dns.spf_softfail ? "SPF     \u2717 ~all слабый" :
                               "SPF     \u2713 Настроен (strict)";
        int spf_pen = !dns.has_spf ? 8 : dns.spf_plusall ? 8 : 4;
        bool spf_ok = dns.has_spf && !dns.spf_plusall && !dns.spf_softfail;
        yn(spf_ok, spf_good, spf_bad, spf_pen);

        bool dmarc_ok = dns.has_dmarc && !dns.dmarc_none;
        std::string dm_bad = !dns.has_dmarc ? "DMARC   \u2717 отсутствует" :
                             "DMARC   \u2717 p=none (слабый)";
        int dm_pen = !dns.has_dmarc ? 7 : 4;
        yn(dmarc_ok, "DMARC   \u2713 Настроен", dm_bad, dm_pen);

        yn(dns.has_dnssec, "DNSSEC  \u2713 Включён",
           "DNSSEC  \u2717 отключён", 3);
        yn(dns.has_caa,    "CAA     \u2713 Настроен",
           "CAA     \u2717 отсутствует", 2);
        yn(dns.has_dkim,   "DKIM    \u2713 Настроен",
           "DKIM    \u2717 отсутствует", 3);
        yn(dns.has_mx,     "MX      \u2713 Настроен",
           "MX      \u2717 отсутствует", 2);
    }

    // ── SSL/TLS ─────────────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R << "\n";
    brow(B + "SSL/TLS" + R, 7);

    if (!tls.has_https) {
        brow(Y + "HTTPS (порт 443) недоступен" + R, 27);
    } else {
        yn(!tls.tls10, "TLS 1.0  \u2713 Отключён",
           "TLS 1.0  \u2717 ВКЛЮЧЁН — УСТАРЕЛ", 10);
        yn(!tls.tls11, "TLS 1.1  \u2713 Отключён",
           "TLS 1.1  \u2717 ВКЛЮЧЁН — УСТАРЕЛ", 7);
        yn(tls.tls12,  "TLS 1.2  \u2713 Поддерживается",
           "TLS 1.2  \u2717 Не поддерживается", 0);
        yn(tls.tls13,  "TLS 1.3  \u2713 Поддерживается",
           "TLS 1.3  \u2717 Отсутствует", 3);

        if (tls.days_left < 0) {
            brow(Y + "Сертификат: не удалось получить" + R, 31);
        } else {
            std::ostringstream ss;
            ss << "  Сертификат истекает через: " << tls.days_left << " дней";
            bool cert_ok = tls.days_left >= 30 && !tls.self_signed;
            int  cert_pen = tls.self_signed ? 10 :
                            tls.days_left < 7 ? 10 :
                            tls.days_left < 30 ? 5 : 0;
            yn(cert_ok, ss.str(), ss.str(), cert_pen);
        }
        if (tls.self_signed)
            brow(RE + "\u2717 Самоподписанный сертификат       -10 pts" + R, 44);
        if (tls.weak_ciphers)
            brow(RE + "\u2717 Слабые шифры RC4/DES              -8 pts" + R, 42);
        yn(http.has_hsts, "HSTS     \u2713 Включён",
           "HSTS     \u2717 отсутствует", 3);
    }
    {
        std::ostringstream pp;
        pp << "Штраф TLS: -" << tls_pen << " pts";
        brow(RE + B + pp.str() + R, display_len(pp.str()));
    }

    // ── HTTP SECURITY HEADERS ───────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R << "\n";
    brow(B + "HTTP SECURITY HEADERS" + R, 21);
    yn(http.x_frame_options,
       "X-Frame-Options          \u2713 Настроен",
       "X-Frame-Options          \u2717 отсутствует", 2);
    yn(http.x_content_type_options,
       "X-Content-Type-Options   \u2713 Настроен",
       "X-Content-Type-Options   \u2717 отсутствует", 2);
    yn(http.csp,
       "Content-Security-Policy  \u2713 Настроен",
       "Content-Security-Policy  \u2717 отсутствует", 3);
    yn(http.referrer_policy,
       "Referrer-Policy          \u2713 Настроен",
       "Referrer-Policy          \u2717 отсутствует", 1);
    yn(!http.server_version_exposed,
       "Server версия            \u2713 Скрыта",
       "Server версия            \u2717 Раскрыта", 2);

    // ── FIREWALL ────────────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R << "\n";
    brow(B + "FIREWALL" + R, 8);
    yn(firewall,
       "Firewall  \u2713 Обнаружен  (+5 pts)",
       "Firewall  \u2717 Не обнаружен  (-5 pts)", 5);

    // ── RECOMMENDATIONS ─────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R;
    brow(B + "РЕКОМЕНДАЦИИ (по приоритету)" + R, 28);

    bool any_rec = false;
    auto rec = [&](const std::string& level, const std::string& level_col,
                   const std::string& msg) {
        std::string bracket = level_col + "[" + level + "]\033[0m ";
        int dlen = 1 + static_cast<int>(level.size()) + 2  // "[LEVEL] "
                   + display_len(msg);
        brow(bracket + msg, dlen);
        any_rec = true;
    };

    // Critical CVEs
    for (auto& c : cves) {
        if (c.cvss >= 9.0) {
            std::string short_desc = c.desc.size() > 28
                ? c.desc.substr(0, 25) + "..." : c.desc;
            rec("CRITICAL", "\033[1;31m", "Устрани " + c.id + " (" + short_desc + ")");
        }
    }
    if (tls.has_https && tls.tls10)
        rec("CRITICAL", "\033[1;31m", "Отключи TLS 1.0: ssl_protocols TLSv1.2 TLSv1.3");
    if (tls.has_https && tls.tls11)
        rec("CRITICAL", "\033[1;31m", "Отключи TLS 1.1: ssl_protocols TLSv1.2 TLSv1.3");
    if (ports.port_23)
        rec("CRITICAL", "\033[1;31m", "Отключи Telnet (порт 23) — используй SSH");
    if (!dns.has_spf || dns.spf_plusall)
        rec("HIGH", "\033[1;33m", "Добавь SPF: v=spf1 include:_spf.google.com ~all");
    if (!dns.has_dmarc)
        rec("HIGH", "\033[1;33m", "Добавь DMARC: v=DMARC1; p=reject; rua=mailto:admin@" + target);
    if (tls.has_https && tls.self_signed)
        rec("HIGH", "\033[1;33m", "Замени самоподписанный сертификат на доверенный CA");
    if (ports.port_21)
        rec("HIGH", "\033[1;33m", "Отключи FTP (порт 21) — используй SFTP");
    if (ports.port_3389)
        rec("HIGH", "\033[1;33m", "Закрой RDP (3389) от интернета, используй VPN");
    if (whois.days_until_expiry >= 0 && whois.days_until_expiry < 30)
        rec("HIGH", "\033[1;33m", "Продли домен — истекает через " +
            std::to_string(whois.days_until_expiry) + " дней!");
    if (!http.has_hsts)
        rec("MEDIUM", "\033[1;34m", "Добавь HSTS: Strict-Transport-Security: max-age=31536000");
    if (!http.csp)
        rec("MEDIUM", "\033[1;34m", "Добавь CSP: Content-Security-Policy header");
    if (!dns.has_dnssec)
        rec("MEDIUM", "\033[1;34m", "Включи DNSSEC в настройках DNS-провайдера");
    if (!dns.has_dkim)
        rec("MEDIUM", "\033[1;34m", "Добавь DKIM запись для домена");
    if (whois.domain_age_days >= 0 && whois.domain_age_days < 365)
        rec("MEDIUM", "\033[1;34m", "Молодой домен — риск (менее года)");
    if (!dns.has_caa)
        rec("LOW", "\033[0;37m", "Добавь CAA: 0 issue \"letsencrypt.org\"");
    if (!http.x_frame_options)
        rec("LOW", "\033[0;37m", "Добавь X-Frame-Options: DENY или SAMEORIGIN");
    if (!http.referrer_policy)
        rec("LOW", "\033[0;37m", "Добавь Referrer-Policy: strict-origin-when-cross-origin");
    if (!dns.has_mx)
        rec("LOW", "\033[0;37m", "Настрой MX запись для приёма почты");
    if (!any_rec)
        brow(G + "\u2713 Отличная защита! Продолжай следить за CVE." + R, 44);

    std::cout << B << C << BOX_BOT << R << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  run — main entry point: parallel checks + progress bar + report
// ─────────────────────────────────────────────────────────────────────────────
void Scorecard::run(const std::string& target) {
    auto t_start = std::chrono::steady_clock::now();

    std::cout << "\n" << Color::INFO
              << "Security Scorecard: " << Color::CYAN << target
              << Color::RESET << "\n\n";

    // ── Sequential steps with accurate progress ────────────────────────────
    PortsAnalysis ports = check_ports(target);
    print_progress(1, "Проверяем порты...");
    DNSAnalysis dns = check_dns(target);
    print_progress(3, "Анализируем DNS...");
    TLSAnalysis tls = check_tls(target);
    print_progress(5, "Проверяем TLS...");
    HTTPAnalysis http = check_http(target);
    print_progress(7, "Анализируем заголовки...");
    std::vector<CVEFinding> cves = check_cve(target, ports);
    print_progress(9, "Сопоставляем CVE...");
    print_progress(10, "Готово!");
    std::cout << "\n";

    bool firewall = check_firewall(target);
    WhoisAnalysis whois = check_whois(target);

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    // ── Load scan history ──────────────────────────────────────────────────
    bool has_prev   = false;
    int  prev_score = 0;
    {
        std::filesystem::create_directories("logs");
        try {
            for (auto& entry : std::filesystem::directory_iterator("logs")) {
                std::string name = entry.path().filename().string();
                if (name.rfind("scorecard_" + target + "_", 0) == 0 &&
                    entry.path().extension() == ".txt") {
                    std::ifstream f(entry.path());
                    int s = 0;
                    if (f >> s) {
                        has_prev   = true;
                        prev_score = s;
                    }
                    break;  // use first file found (one per date per domain)
                }
            }
        } catch (...) {}
    }

    // ── Calculate final score ──────────────────────────────────────────────
    int score = 100;

    // CVE penalty (max -40)
    int cve_pen = 0;
    for (auto& c : cves) cve_pen += c.penalty;
    cve_pen = std::min(cve_pen, 40);

    // TLS penalty (max -15) — includes HSTS
    int tls_pen = tls.penalty;
    if (!tls.has_https) {
        tls_pen = 0;
    } else if (!http.has_hsts) {
        tls_pen += 3;
    }
    tls_pen = std::min(tls_pen, 15);

    int firewall_bonus = firewall ? 5 : -5;

    score -= std::min(cve_pen, 40);
    score -= std::min(ports.penalty, 20);
    score -= std::min(dns.penalty, 20);
    score -= tls_pen;
    score -= std::min(http.penalty, 10);
    // WHOIS penalties are shown in the report for context only (not included in score)
    score += firewall_bonus;
    score = std::max(0, std::min(100, score));

    auto [grade, verdict] = score_grade(score);

    // ── Save scan result ───────────────────────────────────────────────────
    {
        // Build date string YYYY-MM-DD
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char date_buf[16];
        strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", tm_info);
        std::string log_path = "logs/scorecard_" + target + "_" +
                               std::string(date_buf) + ".txt";
        try {
            std::ofstream f(log_path);
            if (f) f << score << "\n";
        } catch (...) {}
    }

    // ── Print report ───────────────────────────────────────────────────────
    print_report(target, elapsed, score, grade, verdict,
                 cves, cve_pen, dns, tls, tls_pen, http, ports, firewall,
                 whois, has_prev, prev_score);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Legacy API  —  kept for backward compatibility
// ─────────────────────────────────────────────────────────────────────────────
ScoreCard Scorecard::calculate(const ScanResult& result) {
    ScoreCard sc;
    int score = 100;

    int cve_pen = 0;
    for (const auto& sev : result.cve_severities) {
        if      (sev == "CRITICAL") cve_pen += 15;
        else if (sev == "HIGH")     cve_pen += 8;
        else if (sev == "MEDIUM")   cve_pen += 3;
        else if (sev == "LOW")      cve_pen += 1;
    }
    cve_pen = std::min(cve_pen, 40);
    sc.cve_penalty = cve_pen;
    score -= cve_pen;

    int ports_pen = 0;
    int count = result.open_port_count;
    if      (count > 20) ports_pen = 20;
    else if (count > 10) ports_pen = 12;
    else if (count > 5)  ports_pen = 6;
    else if (count > 2)  ports_pen = 3;
    sc.ports_penalty = ports_pen;
    score -= ports_pen;

    int svc_pen = 0;
    if (result.has_telnet) svc_pen += 15;
    if (result.has_ftp)    svc_pen += 10;
    if (result.has_rdp)    svc_pen += 8;
    svc_pen = std::min(svc_pen, 20);
    sc.services_penalty = svc_pen;
    score -= svc_pen;

    int ssl_pen = 0;
    if (!result.has_ssl)    ssl_pen += 10;
    if (result.ssl_expired) ssl_pen += 8;
    if (result.has_ssl && !result.ssl_valid) ssl_pen += 5;
    sc.ssl_penalty = ssl_pen;
    score -= ssl_pen;

    if (result.firewall_detected) score += 5;

    score = std::max(0, std::min(100, score));
    sc.total = score;

    if      (score >= 90) { sc.grade = "A+"; sc.verdict = "Отличная защита"; }
    else if (score >= 80) { sc.grade = "A";  sc.verdict = "Хорошая защита"; }
    else if (score >= 70) { sc.grade = "B";  sc.verdict = "Удовлетворительно"; }
    else if (score >= 60) { sc.grade = "C";  sc.verdict = "Есть проблемы"; }
    else if (score >= 50) { sc.grade = "D";  sc.verdict = "Серьёзные проблемы"; }
    else                  { sc.grade = "F";  sc.verdict = "Критически опасно"; }

    return sc;
}

static void print_bar_legacy(const std::string& label, int penalty,
                              int max_pen, const std::string& col) {
    int filled = (max_pen > 0) ? (penalty * 20 / max_pen) : 0;
    filled = std::min(filled, 20);
    std::cout << "  " << std::left << std::setw(18) << label << " ";
    std::cout << col;
    for (int i = 0; i < filled; i++)  std::cout << "█";
    std::cout << "\033[0m";
    for (int i = filled; i < 20; i++) std::cout << "░";
    std::cout << "  -" << penalty << " pts\n";
}

void Scorecard::print(const ScoreCard& sc, const std::string& target) {
    std::string grade_col;
    if      (sc.grade == "A+" || sc.grade == "A") grade_col = "\033[32m";
    else if (sc.grade == "B")                      grade_col = "\033[36m";
    else if (sc.grade == "C")                      grade_col = "\033[33m";
    else                                           grade_col = "\033[31m";

    std::cout << "\n\033[36m\033[1m";
    std::cout << " ╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << " ║              SCORECARD БЕЗОПАСНОСТИ                         ║\n";
    std::cout << " ║  Цель: " << target;
    int pad = 53 - static_cast<int>(target.size());
    for (int i = 0; i < pad; i++) std::cout << ' ';
    std::cout << "║\n";
    std::cout << " ╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "\033[0m";

    std::cout << "\n      Оценка: " << grade_col << "\033[1m"
              << sc.grade << "\033[0m" << "   —   "
              << grade_col << sc.verdict << "\033[0m" << "\n\n";

    std::cout << "\033[1m  АНАЛИЗ ШТРАФОВ:\n\033[0m";
    print_bar_legacy("CVE уязвимости",  sc.cve_penalty,      40, "\033[31m");
    print_bar_legacy("Открытые порты",  sc.ports_penalty,     20, "\033[33m");
    print_bar_legacy("Опасные сервисы", sc.services_penalty,  20, "\033[38;5;208m");
    print_bar_legacy("SSL/TLS",         sc.ssl_penalty,       10, "\033[36m");

    std::cout << "\n\033[1m  РЕКОМЕНДАЦИИ:\n\033[0m";
    if (sc.cve_penalty > 20)
        std::cout << "\033[31m  [!] Обновите ПО — обнаружены CRITICAL уязвимости\n\033[0m";
    if (sc.ports_penalty > 10)
        std::cout << "\033[33m  [!] Закройте лишние порты через firewall\n\033[0m";
    if (sc.services_penalty >= 10)
        std::cout << "\033[33m  [!] Замените Telnet/FTP на SSH/SFTP\n\033[0m";
    if (sc.ssl_penalty >= 8)
        std::cout << "\033[36m  [i] Обновите или установите SSL-сертификат\n\033[0m";
    if (sc.total >= 80)
        std::cout << "\033[32m  [+] Хорошая защита. Продолжайте следить за CVE.\n\033[0m";

    std::cout << "\n\033[36m\033[1m";
    std::cout << " ╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}
