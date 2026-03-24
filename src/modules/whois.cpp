#include "modules/whois.h"
#include "utils/colors.h"
#include <iostream>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

static constexpr size_t MAX_IP_TARGET_LENGTH = 64;

static int hex_char_value(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
}

static bool parse_u16_hex(const std::string& s, size_t pos, uint16_t& out) {
    if (pos + 3 >= s.size()) return false;
    int h1 = hex_char_value(s[pos]);
    int h2 = hex_char_value(s[pos + 1]);
    int h3 = hex_char_value(s[pos + 2]);
    int h4 = hex_char_value(s[pos + 3]);
    if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) return false;
    out = static_cast<uint16_t>((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
    return true;
}

static void append_utf8_from_codepoint(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back('?');
    }
}

static bool is_private_or_loopback_ipv4(const std::string& ip) {
    uint32_t a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    return (a == 10) ||
           (a == 172 && b >= 16 && b <= 31) ||
           (a == 192 && b == 168) ||
           (a == 127);
}

static std::string parse_json_field(const std::string& json,
                                     const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(search, pos);
        if (pos == std::string::npos) return "";

        size_t before = pos;
        while (before > 0 && (json[before - 1] == ' ' || json[before - 1] == '\t' ||
                              json[before - 1] == '\n' || json[before - 1] == '\r')) {
            --before;
        }
        if (before > 0 && json[before - 1] != '{' && json[before - 1] != ',') {
            pos += search.size();
            continue;
        }

        size_t after = pos + search.size();
        while (after < json.size() && (json[after] == ' ' || json[after] == '\t' ||
                                       json[after] == '\n' || json[after] == '\r')) {
            ++after;
        }
        if (after >= json.size() || json[after] != ':') {
            pos += search.size();
            continue;
        }
        ++after;
        while (after < json.size() && (json[after] == ' ' || json[after] == '\t' ||
                                       json[after] == '\n' || json[after] == '\r')) {
            ++after;
        }
        if (after >= json.size()) return "";
        if (json.compare(after, 4, "null") == 0) return "";
        if (json[after] != '"') return "";
        pos = after + 1;
        break;
    }

    std::string value;
    bool escaped = false;
    for (; pos < json.size(); ++pos) {
        char ch = json[pos];
        if (escaped) {
            switch (ch) {
                case '"':  value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/':  value.push_back('/'); break;
                case 'b':  value.push_back('\b'); break;
                case 'f':  value.push_back('\f'); break;
                case 'n':  value.push_back('\n'); break;
                case 'r':  value.push_back('\r'); break;
                case 't':  value.push_back('\t'); break;
                case 'u': {
                    uint16_t cp16 = 0;
                    if (parse_u16_hex(json, pos + 1, cp16)) {
                        pos += 4;
                        uint32_t cp = cp16;
                        if (cp16 >= 0xD800 && cp16 <= 0xDBFF) {
                            if (pos + 6 < json.size() && json[pos + 1] == '\\' && json[pos + 2] == 'u') {
                                uint16_t low = 0;
                                if (parse_u16_hex(json, pos + 3, low) && low >= 0xDC00 && low <= 0xDFFF) {
                                    cp = 0x10000u + (((static_cast<uint32_t>(cp16) - 0xD800u) << 10)
                                                     | (static_cast<uint32_t>(low) - 0xDC00u));
                                    pos += 6;
                                }
                            }
                        }
                        append_utf8_from_codepoint(value, cp);
                        break;
                    }
                    value.push_back('?');
                    break;
                }
                default:   value.push_back(ch); break;
            }
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') return value;
        value.push_back(ch);
    }
    return "";
}

static bool connect_with_timeout(int sock, const struct sockaddr* addr,
                                 socklen_t addr_len, int timeout_sec) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) return false;

    int rc = connect(sock, addr, addr_len);
    if (rc == 0) {
        (void)fcntl(sock, F_SETFL, flags);
        return true;
    }
    if (errno != EINPROGRESS) {
        (void)fcntl(sock, F_SETFL, flags);
        return false;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    rc = select(sock + 1, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) {
        (void)fcntl(sock, F_SETFL, flags);
        return false;
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
        (void)fcntl(sock, F_SETFL, flags);
        return false;
    }

    (void)fcntl(sock, F_SETFL, flags);
    return true;
}

static std::string extract_http_body(const std::string& response) {
    size_t header_end = response.find("\r\n\r\n");
    if (header_end != std::string::npos) return response.substr(header_end + 4);
    header_end = response.find("\n\n");
    if (header_end != std::string::npos) return response.substr(header_end + 2);
    return "";
}

static std::string fetch_ip_api_json(const std::string& ip) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo* results = nullptr;
    if (getaddrinfo("ip-api.com", "80", &hints, &results) != 0) {
        std::cerr << Color::WARN << "WHOIS: failed to resolve ip-api.com" << std::endl;
        return "";
    }

    std::string request = "GET /json/" + ip + " HTTP/1.0\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n";
    std::string response;
    bool connected = false;
    bool transferred = false;

    for (struct addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
        int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (!connect_with_timeout(sock, ai->ai_addr, ai->ai_addrlen, 5)) {
            close(sock);
            continue;
        }
        connected = true;

        size_t sent = 0;
        while (sent < request.size()) {
            ssize_t n = send(sock, request.data() + sent, request.size() - sent, 0);
            if (n <= 0) break;
            sent += static_cast<size_t>(n);
        }
        if (sent == request.size()) {
            char buffer[1024];
            while (true) {
                ssize_t n = recv(sock, buffer, sizeof(buffer), 0);
                if (n <= 0) break;
                response.append(buffer, static_cast<size_t>(n));
            }
            transferred = !response.empty();
        }
        close(sock);
        if (transferred) break;
    }

    freeaddrinfo(results);
    if (!connected) {
        std::cerr << Color::WARN << "WHOIS: failed to connect to ip-api.com" << std::endl;
        return "";
    }
    if (!transferred) {
        std::cerr << Color::WARN << "WHOIS: empty response from ip-api.com" << std::endl;
        return "";
    }
    return extract_http_body(response);
}

static bool is_safe_ip_target(const std::string& ip) {
    if (ip.empty() || ip.size() > MAX_IP_TARGET_LENGTH) return false;
    for (char ch : ip) {
        const bool is_digit = (ch >= '0' && ch <= '9');
        const bool is_lower_hex = (ch >= 'a' && ch <= 'f');
        const bool is_upper_hex = (ch >= 'A' && ch <= 'F');
        if (!(is_digit || is_lower_hex || is_upper_hex || ch == '.' || ch == ':')) {
            return false;
        }
    }
    return true;
}

static void set_private_fallback(WhoisResult& result) {
    result.country = "Private network (RFC1918)";
    result.region = "-";
    result.city = "-";
    result.org = "-";
    result.isp = "-";
    result.as = "-";
    result.timezone = "-";
}

static void set_public_fallback(WhoisResult& result) {
    result.country = "Unknown";
    result.region = "-";
    result.city = "-";
    result.org = "-";
    result.isp = "-";
    result.as = "-";
    result.timezone = "-";
}

static bool fill_from_ip_api_json(const std::string& json, WhoisResult& result) {
    if (json.empty()) return false;
    if (json.find('{') == std::string::npos || json.find('}') == std::string::npos) return false;
    if (parse_json_field(json, "status") != "success") return false;

    result.country = parse_json_field(json, "country");
    result.region = parse_json_field(json, "regionName");
    result.city = parse_json_field(json, "city");
    result.org = parse_json_field(json, "org");
    result.isp = parse_json_field(json, "isp");
    result.as = parse_json_field(json, "as");
    result.timezone = parse_json_field(json, "timezone");

    if (result.country.empty()) result.country = "Unknown";
    if (result.region.empty()) result.region = "-";
    if (result.city.empty()) result.city = "-";
    if (result.org.empty()) result.org = "-";
    if (result.isp.empty()) result.isp = "-";
    if (result.as.empty()) result.as = "-";
    if (result.timezone.empty()) result.timezone = "-";
    return true;
}

WhoisResult Whois::lookup(const std::string& target) {
    WhoisResult result;
    result.ip = target;

    if (is_private_or_loopback_ipv4(target)) {
        set_private_fallback(result);
        return result;
    }
    if (!is_safe_ip_target(target)) {
        set_public_fallback(result);
        return result;
    }

    std::string json = fetch_ip_api_json(target);
    if (json.empty()) {
        json = fetch_ip_api_json(target);
    }
    if (!fill_from_ip_api_json(json, result)) {
        set_public_fallback(result);
    }

    return result;
}
