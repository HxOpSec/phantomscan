#include "modules/subdomain.h"
#include "utils/colors.h"
#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>

// ── Wordlist 100+ популярных поддоменов ───────────────
std::vector<std::string> SubdomainEnum::get_wordlist() {
    return {
        // Основные
        "www", "mail", "ftp", "admin", "dev",
        "test", "api", "blog", "shop", "secure",
        "vpn", "remote", "portal", "mx", "smtp",
        "pop", "imap", "ns1", "ns2", "cdn",
        "staging", "beta", "app", "mobile", "m",
        // Расширенные
        "dashboard", "panel", "cpanel", "webmail",
        "email", "login", "auth", "oauth", "sso",
        "accounts", "account", "user", "users",
        "support", "help", "docs", "wiki", "kb",
        "status", "monitor", "stats", "analytics",
        "git", "gitlab", "github", "bitbucket",
        "jenkins", "ci", "cd", "build", "deploy",
        "db", "database", "mysql", "postgres", "mongo",
        "redis", "cache", "queue", "broker",
        "api2", "api3", "apiv1", "apiv2", "rest",
        "graphql", "grpc", "webhook", "webhooks",
        "static", "assets", "media", "img", "images",
        "uploads", "files", "storage", "s3", "backup",
        "dev2", "test2", "staging2", "preprod", "prod",
        "internal", "intranet", "corp", "office", "vpn2",
        "proxy", "gateway", "lb", "load", "haproxy",
        "k8s", "kubernetes", "docker", "registry",
        "grafana", "kibana", "elastic", "logstash",
        "old", "new", "legacy", "archive", "demo",
        "sandbox", "uat", "qa", "sentry", "error",
        "mx1", "mx2", "smtp2", "mail2", "relay",
        "ns3", "ns4", "dns", "dns1", "dns2",
        "ww2", "www2", "web", "web2", "site",
    };
}

// FIX: getaddrinfo вместо gethostbyname (устарела, не thread-safe)
bool SubdomainEnum::check_subdomain(const std::string& subdomain,
                                     std::string& ip) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(subdomain.c_str(), nullptr, &hints, &res) != 0)
        return false;

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,
              &((struct sockaddr_in*)res->ai_addr)->sin_addr,
              buf, sizeof(buf));
    freeaddrinfo(res);
    ip = std::string(buf);
    return true;
}

// ── Перебор поддоменов ────────────────────────────────
std::vector<SubdomainResult> SubdomainEnum::enumerate(
    const std::string& domain) {

    std::vector<SubdomainResult> results;
    auto wordlist = get_wordlist();

    std::cout << Color::INFO << "Ищем поддомены для: "
              << Color::CYAN << domain << Color::RESET << "\n";
    std::cout << Color::INFO << "Проверяем "
              << wordlist.size() << " вариантов...\n"
              << Color::RESET;

    for (const auto& word : wordlist) {
        std::string full = word + "." + domain;
        std::string ip;

        if (check_subdomain(full, ip)) {
            SubdomainResult result;
            result.subdomain = full;
            result.ip        = ip;
            results.push_back(result);

            std::cout << Color::OK << "Найден: "
                      << Color::CYAN << full
                      << Color::RESET << " → "
                      << Color::YELLOW << ip
                      << Color::RESET << "\n";
        }
    }

    std::cout << Color::INFO << "Найдено: " << Color::GREEN
              << results.size() << Color::RESET << "\n";

    return results;
}