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
#include <algorithm>
#include <future>
#include <thread>
#include <chrono>
#include <cstring>
#include <ctime>
#include <cctype>
#include <set>

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Box-drawing constants (64 chars wide: ║ + 62 inner + ║)
// ─────────────────────────────────────────────────────────────────────────────
static const char BOX_TOP[] =
    "╔══════════════════════════════════════════════════════════════╗\n";
static const char BOX_SEP[] =
    "╠══════════════════════════════════════════════════════════════╣\n";
static const char BOX_BOT[] =
    "╚══════════════════════════════════════════════════════════════╝\n";
// inner width between the ║ characters
static const int BOX_I = 62;

// Print a box row: ║  <text><padding>║
// display_len = visible char count in text (pass when text has ANSI codes)
static void brow(const std::string& text, int display_len = -1) {
    int dlen = (display_len >= 0) ? display_len : static_cast<int>(text.size());
    int pad  = BOX_I - 2 - dlen;
    if (pad < 0) pad = 0;
    std::cout << "║  " << text << std::string(static_cast<size_t>(pad), ' ') << "║\n";
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

    bool ok = (select(sock + 1, nullptr, &wset, nullptr, &tv) > 0);
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
        case 8080: return "HTTP";
        case 8443: return "HTTPS";
        default:   return "";
    }
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
    if (score >= 80) return "\033[32m";
    if (score >= 60) return "\033[33m";
    if (score >= 40) return "\033[38;5;208m";
    return "\033[31m";
}

// Print real-time progress bar (overwrites current line)
static void print_progress(int done, int total, const std::string& msg) {
    int bars = (total > 0) ? (done * 10 / total) : 0;
    std::cout << "\r  \033[36m[";
    for (int i = 0; i < 10; i++)
        std::cout << (i < bars ? "■" : "░");
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

    std::string spf    = f_spf.get();
    std::string dmarc  = f_dmarc.get();
    std::string dnssec = f_dnssec.get();
    std::string caa    = f_caa.get();

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

    // Penalty
    int pen = 0;
    if (!r.has_spf)         pen += 8;
    else if (r.spf_plusall) pen += 8;
    else if (r.spf_softfail) pen += 4;

    if (!r.has_dmarc)       pen += 7;
    else if (r.dmarc_none)  pen += 4;

    if (!r.has_dnssec) pen += 3;
    if (!r.has_caa)    pen += 2;

    r.penalty = std::min(pen, 20);
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
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
        445, 465, 587, 993, 995, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 8888, 27017
    };

    // Safe ports (don't count as "extra")
    static const std::set<int> SAFE_PORTS = {22, 80, 443, 53};
    // Dangerous ports that have specific penalties
    static const std::set<int> DANGER_PORTS = {21, 23, 25, 139, 445, 3389};

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
std::vector<CVEFinding> Scorecard::check_cve(const PortsAnalysis& ports) {
    std::vector<CVEFinding> findings;
    CVEScanner cve_db;
    std::set<std::string> seen_services;

    for (int p : ports.open_list) {
        std::string svc = port_to_service(p);
        if (svc.empty() || seen_services.count(svc)) continue;
        seen_services.insert(svc);

        auto entries = cve_db.search(svc);
        for (auto& e : entries) {
            CVEFinding f;
            f.id   = e.id;
            f.cvss = e.cvss;
            f.desc = e.description;

            if (e.cvss >= 9.0)      f.penalty = 15;
            else if (e.cvss >= 7.0) f.penalty = 8;
            else if (e.cvss >= 4.0) f.penalty = 3;
            else if (e.cvss > 0.0)  f.penalty = 1;

            findings.push_back(std::move(f));
        }
    }

    // Sort by CVSS descending
    std::sort(findings.begin(), findings.end(),
        [](const CVEFinding& a, const CVEFinding& b) {
            return a.cvss > b.cvss;
        });

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
    bool                        firewall)
{
    std::string col = score_color(score);
    const std::string R = "\033[0m";
    const std::string B = "\033[1m";
    const std::string C = "\033[36m";
    const std::string G = "\033[32m";
    const std::string Y = "\033[33m";
    const std::string RE = "\033[31m";

    // Grade colour
    std::string gc = (grade == "A+" || grade == "A") ? G :
                     (grade == "B")                  ? C :
                     (grade == "C")                  ? Y : RE;

    std::cout << "\n" << B << C << BOX_TOP << R;

    // Title
    {
        std::string title = "  SECURITY SCORECARD — " + target;
        brow(B + C + title + R, static_cast<int>(title.size()));
    }
    {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << elapsed;
        std::string sub = "  Анализ завершён за " + ss.str() + " сек";
        brow(sub, static_cast<int>(sub.size()));
    }

    std::cout << B << C << BOX_SEP << R;

    // Score line
    {
        std::ostringstream ss;
        ss << "SCORE: " << score << " / 100          Grade: " << grade;
        std::string txt = ss.str();
        brow(col + B + txt + R + "  " + gc + B + grade + R,
             static_cast<int>(txt.size()) + 2 + static_cast<int>(grade.size()));
    }
    // Score bar — use verdict as the risk label
    {
        std::string bar  = score_bar(score);
        // bar = 32 "█"/"░" chars (each is 3 bytes but 1 col => display=32)
        std::string line = col + bar + R + "  " + col + B + verdict + R;
        brow(line, 32 + 2 + static_cast<int>(verdict.size()));
    }

    // ── CVSS ANALYSIS ──────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R;
    brow(B + "CVSS ANALYSIS" + R, 13);

    if (cves.empty()) {
        brow("  Уязвимостей не найдено в data/cve.json",
             42);
    } else {
        int crit = 0, high = 0, med = 0, low = 0;
        double avg = 0.0;
        for (auto& c : cves) {
            avg += c.cvss;
            if (c.cvss >= 9.0)      crit++;
            else if (c.cvss >= 7.0) high++;
            else if (c.cvss >= 4.0) med++;
            else                    low++;
        }
        avg /= static_cast<double>(cves.size());

        std::ostringstream ss;
        ss << "Avg CVSS: " << std::fixed << std::setprecision(1) << avg
           << "   \u25a0 Critical: " << crit
           << "  \u25a0 High: "     << high
           << "  \u25a0 Medium: "   << med;
        brow(ss.str(), static_cast<int>(ss.str().size()));

        // Show top CVEs (up to 5)
        int shown = 0;
        for (auto& c : cves) {
            if (shown++ >= 5) break;
            std::ostringstream ls;
            std::string desc = c.desc;
            if (static_cast<int>(desc.size()) > 26) desc = desc.substr(0, 23) + "...";
            ls << std::left << std::setw(16) << c.id
               << "  CVSS " << std::fixed << std::setprecision(1) << c.cvss
               << "  " << std::setw(28) << desc
               << "  -" << c.penalty << " pts";
            brow(ls.str(), static_cast<int>(ls.str().size()));
        }
        std::ostringstream pp;
        pp << "Общий штраф CVE: -" << cve_pen << " pts";
        brow(RE + B + pp.str() + R, static_cast<int>(pp.str().size()));
    }

    // ── DNS SECURITY ────────────────────────────────────────────────────────
    auto yn = [&](bool ok, const std::string& good_txt, const std::string& bad_txt,
                  int penalty) {
        std::string mark = ok ? (G + "\u2713" + R) : (RE + "\u2717" + R);
        std::string txt  = ok ? good_txt : bad_txt;
        int pts_len = 0;
        std::string pts_str;
        if (!ok && penalty > 0) {
            std::ostringstream ps; ps << "-" << penalty << " pts";
            pts_str = Y + ps.str() + R;
            pts_len = static_cast<int>(ps.str().size());
        } else {
            pts_str = G + "OK" + R;
            pts_len = 2;
        }
        // Layout: mark(1) + " " + label(text, max 44) + spacing + pts
        int content_display = 1 + 1 + static_cast<int>(txt.size()) + 4 + pts_len;
        int pad = 58 - content_display;
        if (pad < 1) pad = 1;
        std::cout << "║  " << mark << " " << txt
                  << std::string(static_cast<size_t>(pad), ' ')
                  << pts_str << "║\n";
    };

    std::cout << B << C << BOX_SEP << R;
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
    }

    // ── SSL/TLS ─────────────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R;
    brow(B + "SSL/TLS" + R, 7);

    if (!tls.has_https) {
        brow(Y + "  HTTPS (порт 443) недоступен" + R, 29);
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
            brow(Y + "  Сертификат: не удалось получить" + R, 33);
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
            brow(RE + "  \u2717 Самоподписанный сертификат       -10 pts" + R, 44);
        if (tls.weak_ciphers)
            brow(RE + "  \u2717 Слабые шифры RC4/DES              -8 pts" + R, 43);
        yn(http.has_hsts, "HSTS     \u2713 Включён",
           "HSTS     \u2717 отсутствует", 3);
    }
    {
        std::ostringstream pp;
        pp << "Штраф TLS: -" << tls_pen << " pts";
        brow(RE + B + pp.str() + R, static_cast<int>(pp.str().size()));
    }

    // ── HTTP SECURITY HEADERS ───────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R;
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
    std::cout << B << C << BOX_SEP << R;
    brow(B + "FIREWALL" + R, 8);
    yn(firewall,
       "Firewall  \u2713 Обнаружен  (+5 pts)",
       "Firewall  \u2717 Не обнаружен  (-5 pts)", 5);

    // ── RECOMMENDATIONS ─────────────────────────────────────────────────────
    std::cout << B << C << BOX_SEP << R;
    brow(B + "РЕКОМЕНДАЦИИ (по приоритету)" + R, 28);

    bool any_rec = false;
    auto rec = [&](const std::string& level, const std::string& col_s,
                   const std::string& msg) {
        std::string line = col_s + B + "[" + level + "]" + R + " " + msg;
        int dlen = 1 + static_cast<int>(level.size()) + 1 + 1 +
                   static_cast<int>(msg.size());
        brow(line, dlen);
        any_rec = true;
    };

    // Critical CVEs
    for (auto& c : cves) {
        if (c.cvss >= 9.0) {
            std::string short_desc = c.desc.size() > 28
                ? c.desc.substr(0, 25) + "..." : c.desc;
            rec("CRITICAL", RE, "Устрани " + c.id + " (" + short_desc + ")");
        }
    }
    if (tls.has_https && tls.tls10)
        rec("CRITICAL", RE, "Отключи TLS 1.0: ssl_protocols TLSv1.2 TLSv1.3");
    if (tls.has_https && tls.tls11)
        rec("CRITICAL", RE, "Отключи TLS 1.1: ssl_protocols TLSv1.2 TLSv1.3");
    if (ports.port_23)
        rec("CRITICAL", RE, "Отключи Telnet (порт 23) — используй SSH");
    if (!dns.has_spf || dns.spf_plusall)
        rec("HIGH", Y, "Добавь SPF: v=spf1 include:_spf.google.com ~all");
    if (!dns.has_dmarc)
        rec("HIGH", Y, "Добавь DMARC: v=DMARC1; p=reject; rua=mailto:admin@" + target);
    if (tls.has_https && tls.self_signed)
        rec("HIGH", Y, "Замени самоподписанный сертификат на доверенный CA");
    if (ports.port_21)
        rec("HIGH", Y, "Отключи FTP (порт 21) — используй SFTP");
    if (ports.port_3389)
        rec("HIGH", Y, "Закрой RDP (3389) от интернета, используй VPN");
    if (!http.has_hsts)
        rec("MEDIUM", C, "Добавь HSTS: Strict-Transport-Security: max-age=31536000");
    if (!http.csp)
        rec("MEDIUM", C, "Добавь CSP: Content-Security-Policy header");
    if (!dns.has_dnssec)
        rec("MEDIUM", C, "Включи DNSSEC в настройках DNS-провайдера");
    if (!dns.has_caa)
        rec("LOW", G, "Добавь CAA: 0 issue \"letsencrypt.org\"");
    if (!http.x_frame_options)
        rec("LOW", G, "Добавь X-Frame-Options: DENY или SAMEORIGIN");
    if (!http.referrer_policy)
        rec("LOW", G, "Добавь Referrer-Policy: strict-origin-when-cross-origin");
    if (!any_rec)
        brow(G + "  Отличная защита! Продолжай следить за CVE." + R, 44);

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

    // ── Launch all checks in parallel ──────────────────────────────────────
    auto f_dns   = std::async(std::launch::async,
        [this, &target] { return check_dns(target); });

    auto f_tls   = std::async(std::launch::async,
        [this, &target] { return check_tls(target); });

    auto f_http  = std::async(std::launch::async,
        [this, &target] { return check_http(target); });

    // Ports + CVE: CVE lookup runs after port scan, same async task
    auto f_ports_cve = std::async(std::launch::async,
        [this, &target] {
            PortsAnalysis pa = check_ports(target);
            std::vector<CVEFinding> cv = check_cve(pa);
            return std::make_pair(pa, cv);
        });

    auto f_fw    = std::async(std::launch::async,
        [this, &target] { return check_firewall(target); });

    // ── Progress bar while tasks run ───────────────────────────────────────
    using ms = std::chrono::milliseconds;
    for (;;) {
        bool dns_done   = f_dns.wait_for(ms(0))       == std::future_status::ready;
        bool tls_done   = f_tls.wait_for(ms(0))       == std::future_status::ready;
        bool http_done  = f_http.wait_for(ms(0))      == std::future_status::ready;
        bool pcve_done  = f_ports_cve.wait_for(ms(0)) == std::future_status::ready;
        bool fw_done    = f_fw.wait_for(ms(0))        == std::future_status::ready;

        int done = static_cast<int>(dns_done) + static_cast<int>(tls_done) +
                   static_cast<int>(http_done) + static_cast<int>(pcve_done) +
                   static_cast<int>(fw_done);

        std::string msg = dns_done  ? (tls_done ? (http_done ? (pcve_done ?
                          (fw_done ? "Готово!           " :
                           "Проверяем firewall...") :
                           "Ищем CVE...        ") :
                           "Проверяем заголовки...") :
                           "Анализируем TLS...    ") :
                           "Проверяем DNS...      ";

        print_progress(done, 5, msg);
        if (done == 5) break;
        std::this_thread::sleep_for(ms(300));
    }
    std::cout << "\n";

    // ── Collect results ────────────────────────────────────────────────────
    DNSAnalysis             dns  = f_dns.get();
    TLSAnalysis             tls  = f_tls.get();
    HTTPAnalysis            http = f_http.get();
    auto                    pc   = f_ports_cve.get();
    PortsAnalysis           ports = pc.first;
    std::vector<CVEFinding> cves  = pc.second;
    bool                    firewall = f_fw.get();

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    // ── Calculate final score ──────────────────────────────────────────────
    int score = 100;

    // CVE penalty (max -40)
    int cve_pen = 0;
    for (auto& c : cves) cve_pen += c.penalty;
    cve_pen = std::min(cve_pen, 40);
    score -= cve_pen;

    // Ports penalty (max -20)
    score -= std::min(ports.penalty, 20);

    // DNS penalty (max -20)
    score -= std::min(dns.penalty, 20);

    // TLS penalty (max -15) — includes HSTS
    int tls_pen = tls.penalty;
    if (tls.has_https && !http.has_hsts) tls_pen += 3;
    tls_pen = std::min(tls_pen, 15);
    score -= tls_pen;

    // HTTP headers penalty (max -10, HSTS already in TLS)
    score -= std::min(http.penalty, 10);

    // Firewall
    if (firewall)  score += 5;
    else           score -= 5;

    score = std::max(0, std::min(100, score));

    auto [grade, verdict] = score_grade(score);

    // ── Print report ───────────────────────────────────────────────────────
    print_report(target, elapsed, score, grade, verdict,
                 cves, cve_pen, dns, tls, tls_pen, http, ports, firewall);
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

