#pragma once
#include <string>
#include <vector>

class WordlistGenerator {
public:
    std::vector<std::string> generate(const std::string& domain);
    void save_to_file(const std::vector<std::string>& words,
                      const std::string& filename);
    void print_results(const std::vector<std::string>& found);
private:
    std::vector<std::string> base_words = {
        "www", "mail", "admin", "api", "blog",
        "shop", "vpn", "smtp", "ns1", "ns2",
        "ftp", "ssh", "dev", "test", "staging",
        "portal", "cdn", "static", "media", "img",
        "remote", "secure", "login", "auth", "app",
        "beta", "old", "new", "backup", "db",
        "mysql", "redis", "mongo", "elastic", "git",
        "jenkins", "ci", "docker", "k8s", "proxy"
    };
};